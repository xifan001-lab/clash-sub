# -*- coding: utf-8 -*-
"""CI pipeline: fetch sources -> normalize -> drop vmess -> mihomo latency-test -> build clash.yaml.

Runs on GitHub Actions (ubuntu). Node count capped to [100, 200].
"""
import os, re, json, time, base64, hashlib, urllib.parse, urllib.request
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "raw")
os.makedirs(RAW, exist_ok=True)

SOURCES = {
    "anaer":        "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "ermaozi":      "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "snakem982":    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "bestclash":    "https://raw.githubusercontent.com/PuddinCat/BestClash/main/proxies.yaml",
    "free-airport": "https://sunmiao4458.github.io/free-proxy-airport/clash.yaml",
    "zhuhaiuk":     "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml",
    "ts-sf":        "https://raw.githubusercontent.com/ts-sf/fly/main/clash",
    "peasoft":      "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "mahdibland":   "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
    "ripaojiedian": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "Pawdroid":     "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "freefq":       "https://raw.githubusercontent.com/freefq/free/master/v2",
    "ermaozi2":     "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/clash.yml",
}


def mirrors(u):
    yield u
    if "raw.githubusercontent.com" in u:
        rest = u.split("raw.githubusercontent.com/", 1)[1]
        yield "https://cdn.jsdelivr.net/gh/" + rest
        yield "https://gh-proxy.com/" + u


def fetch(name, url, timeout=35):
    for u in mirrors(url):
        for _ in range(2):
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "clash-verge/2.x"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = r.read()
                if len(data) > 800:
                    return data
            except Exception:
                pass
            time.sleep(0.5)
    return None


# ---------- link parsers ----------

def b64pad(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def try_b64(text):
    t = re.sub(r"\s+", "", text)
    if len(t) < 40:
        return None
    try:
        s = base64.b64decode(b64pad(t), validate=False).decode("utf-8", "replace")
        return s if "://" in s else None
    except Exception:
        return None


def qs(u):
    return {k: v[0] for k, v in urllib.parse.parse_qs(u).items()}


def parse_ss(link):
    body = link[5:]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1)
        name = urllib.parse.unquote(name)
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            userinfo = base64.b64decode(b64pad(userinfo)).decode("utf-8", "replace")
        except Exception:
            pass
        method, _, pwd = userinfo.partition(":")
        host, _, port = hostport.partition(":")
        port = re.sub(r"[^0-9].*$", "", port)
        if not host or not port:
            return None
        return {"name": name or host, "type": "ss", "server": host, "port": int(port),
                "cipher": method or "aes-256-gcm", "password": pwd, "udp": True}


def parse_vless(link):
    pr = urllib.parse.urlparse(link)
    if not pr.hostname or not pr.port:
        return None
    q = qs(pr.query)
    p = {"name": urllib.parse.unquote(pr.fragment) or pr.hostname, "type": "vless",
         "server": pr.hostname, "port": int(pr.port),
         "uuid": urllib.parse.unquote(pr.username or ""), "udp": True}
    if q.get("security") in ("tls", "reality", "xtls"):
        p["tls"] = True
    if q.get("sni"):
        p["servername"] = q["sni"]
    if q.get("flow"):
        p["flow"] = q["flow"]
    if q.get("fp"):
        p["client-fingerprint"] = q["fp"]
    net = q.get("type", "tcp")
    if net == "ws":
        p["network"] = "ws"
        p["ws-opts"] = {"path": urllib.parse.unquote(q.get("path", "/"))}
        if q.get("host"):
            p["ws-opts"]["headers"] = {"Host": q["host"]}
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    if q.get("security") == "reality":
        p["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
    return p


def parse_trojan(link):
    pr = urllib.parse.urlparse(link)
    if not pr.hostname or not pr.port:
        return None
    q = qs(pr.query)
    p = {"name": urllib.parse.unquote(pr.fragment) or pr.hostname, "type": "trojan",
         "server": pr.hostname, "port": int(pr.port),
         "password": urllib.parse.unquote(pr.username or ""), "udp": True}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("type") == "ws":
        p["network"] = "ws"
        p["ws-opts"] = {"path": urllib.parse.unquote(q.get("path", "/"))}
        if q.get("host"):
            p["ws-opts"]["headers"] = {"Host": q["host"]}
    return p


def parse_hy2(link):
    pr = urllib.parse.urlparse(link)
    if not pr.hostname or not pr.port:
        return None
    q = qs(pr.query)
    user = urllib.parse.unquote(pr.username or "")
    pwd = urllib.parse.unquote(pr.password or "") or user
    p = {"name": urllib.parse.unquote(pr.fragment) or pr.hostname, "type": "hysteria2",
         "server": pr.hostname, "port": int(pr.port), "password": pwd, "udp": True}
    if q.get("sni"):
        p["sni"] = q["sni"]
    if q.get("obfs") and q.get("obfs-password"):
        p["obfs"] = q["obfs"]
        p["obfs-password"] = q["obfs-password"]
    if q.get("insecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    return p


LINK_PARSERS = [
    ("vless://", parse_vless),
    ("trojan://", parse_trojan),
    ("hysteria2://", parse_hy2),
    ("hy2://", parse_hy2),
    ("ss://", parse_ss),
]


def parse_links(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for pref, fn in LINK_PARSERS:
            if line.lower().startswith(pref):
                try:
                    p = fn(line)
                except Exception:
                    p = None
                if p and p.get("server") and p.get("port"):
                    out.append(p)
                break
    return out


def load_source(path):
    raw = open(path, "rb").read()
    txt = raw.decode("utf-8", "replace")
    nodes = []
    if re.search(r"^\s*proxies\s*:", txt, re.M):
        try:
            doc = yaml.safe_load(txt)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                for p in doc["proxies"]:
                    if isinstance(p, dict) and p.get("server") and p.get("port"):
                        nodes.append(p)
        except Exception:
            pass
    if not nodes:
        dec = try_b64(txt)
        body = dec if dec else txt
        nodes = parse_links(body)
    return nodes


def sig(p):
    key = "|".join(str(p.get(k, "")) for k in
                   ("type", "server", "port", "uuid", "password", "cipher",
                    "auth_str", "auth-str", "username", "sni"))
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]


# ---------- mihomo testing ----------

def start_mihomo(cfg_dir, cfg_path):
    proc = subprocess.Popen(
        [os.environ.get("MIHOMO_BIN", "mihomo"), "-d", cfg_dir, "-f", cfg_path],
        stdout=open(os.path.join(cfg_dir, "mihomo.log"), "w"),
        stderr=subprocess.STDOUT)
    for _ in range(30):
        time.sleep(1)
        try:
            with urllib.request.urlopen("http://127.0.0.1:9099/version", timeout=2) as r:
                json.load(r)
            return proc
        except Exception:
            if proc.poll() is not None:
                break
    raise RuntimeError("mihomo failed to start")


def delay(pid, to=6000):
    q = urllib.parse.urlencode({"url": "https://www.gstatic.com/generate_204", "timeout": to})
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:9099/proxies/{urllib.parse.quote(pid)}/delay?{q}",
                timeout=to / 1000 + 4) as f:
            return json.load(f).get("delay")
    except Exception:
        return None


def run_test(ids, workers=64):
    out = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fs = {ex.submit(delay, i): i for i in ids}
        for f in as_completed(fs):
            out[fs[f]] = f.result()
    return out


# ---------- main ----------

if __name__ == "__main__":
    pool = {}
    for name, url in SOURCES.items():
        data = fetch(name, url)
        if not data:
            print(f"  FAIL {name}")
            continue
        p = os.path.join(RAW, name + ".txt")
        open(p, "wb").write(data)
        nodes = load_source(p)
        new = 0
        for nd in nodes:
            s = sig(nd)
            if s not in pool:
                nd["_sig"] = s
                nd["_src"] = name
                pool[s] = nd
                new += 1
        print(f"  {name:14s} new={new}")

    print(f"unique pool: {len(pool)}")
    nonvmess = [p for p in pool.values() if str(p.get("type", "")).lower() != "vmess"]
    print(f"non-vmess: {len(nonvmess)}")

    PROBE = os.path.join(ROOT, "probe")
    os.makedirs(PROBE, exist_ok=True)
    proxies, index = [], []
    for n in nonvmess:
        q = {k: v for k, v in n.items() if k not in ("_sig", "_src")}
        pid = f"n{len(index):05d}"
        index.append({"id": pid, "proxy": q})
        q["name"] = pid
        proxies.append(q)

    cfg = {"mixed-port": 7899, "allow-lan": False, "mode": "rule", "log-level": "warning",
           "external-controller": "127.0.0.1:9099", "secret": "",
           "proxies": proxies, "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
    cfg_path = os.path.join(PROBE, "config.yaml")
    yaml.safe_dump(cfg, open(cfg_path, "w", encoding="utf-8"),
                   allow_unicode=True, sort_keys=False, width=4096)

    proc = start_mihomo(PROBE, cfg_path)
    try:
        pending = [r["id"] for r in index]
        allbest = {}
        for rnd in range(3):
            res = run_test(pending)
            ok = {k: v for k, v in res.items() if v}
            for k, v in ok.items():
                allbest[k] = min(allbest.get(k, 1 << 30), v)
            pending = [i for i in pending if not res.get(i)]
            print(f"  round{rnd+1}: alive_total={len(allbest)} pending={len(pending)}")
            if not pending or len(allbest) >= 220:
                break
    finally:
        proc.terminate()

    print(f"alive: {len(allbest)}")
    if len(allbest) < 100:
        raise SystemExit(f"only {len(allbest)} alive (<100)")

    rows = sorted(allbest.items(), key=lambda kv: kv[1])[:200]
    by_id = {r["id"]: r["proxy"] for r in index}
    out_proxies, out_names = [], []
    for i, (pid, d) in enumerate(rows, 1):
        p = dict(by_id[pid])
        core = str(p.get("name") or p.get("server")).strip()[:64]
        core = core.replace("|", "/")
        nm = f"{i:03d} | {d}ms | {core}"
        p["name"] = nm
        p["udp"] = True
        out_proxies.append(p)
        out_names.append(nm)

    out = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
        "proxies": out_proxies,
        "proxy-groups": [
            {"name": "AUTO-FASTEST", "type": "url-test", "proxies": out_names,
             "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "tolerance": 50, "lazy": False},
            {"name": "PROXY", "type": "select",
             "proxies": ["AUTO-FASTEST", "DIRECT"] + out_names},
        ],
        "rules": ["MATCH,PROXY"],
    }
    with open(os.path.join(ROOT, "clash.yaml"), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# auto-generated {time.strftime('%F %T UTC')}\n")
        f.write(f"# nodes: {len(out_proxies)} (non-vmess, mihomo latency-tested)\n")
        yaml.safe_dump(out, f, allow_unicode=True, sort_keys=False, width=4096)
    print("wrote clash.yaml")
