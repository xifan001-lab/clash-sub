
# -*- coding: utf-8 -*-
"""CI refresh: fetch sources, TCP prescan, 3-round mihomo test, keep top 100 alive (non-vmess)."""
import os, sys, json, re, time, base64, socket, hashlib, urllib.parse, urllib.request, collections, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "ci_raw")
os.makedirs(RAW, exist_ok=True)
TEST_URL = "https://www.gstatic.com/generate_204"
CTRL = "http://127.0.0.1:9099"
TARGET = 100

SOURCES = {
    "anaer":        "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "ermaozi":      "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "snakem982":    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "snakem982-1":  "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
    "bestclash":    "https://raw.githubusercontent.com/PuddinCat/BestClash/main/proxies.yaml",
    "free-airport": "https://sunmiao4458.github.io/free-proxy-airport/clash.yaml",
    "zhuhaiuk":     "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml",
    "ts-sf":        "https://raw.githubusercontent.com/ts-sf/fly/main/clash",
    "peasoft":      "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "mahdibland":   "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
    "sub-merge":    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge_base64.txt",
    "ripaojiedian": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "Pawdroid":     "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "freefq":       "https://raw.githubusercontent.com/freefq/free/master/v2",
    "ermaozi2":     "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/clash.yml",
    "Barabama":     "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.yaml",
    "epodonios":    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "aliilapro":    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "openproxylist":"https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "c22":          "https://raw.githubusercontent.com/free-nodes/clashfree/main/clash20261019.yml",
    "freenodes":    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashnode.txt",
}

def fetch(url, timeout=25):
    for u in (url, "https://gh-proxy.com/" + url if "raw.githubusercontent.com" in url else url):
        for _ in range(2):
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "clash-verge/2.x"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = r.read()
                if len(data) > 500:
                    return data
            except Exception:
                time.sleep(0.4)
    return None

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
    if "@" not in body:
        return None
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
    pwd = urllib.parse.unquote(pr.password or "") or urllib.parse.unquote(pr.username or "")
    p = {"name": urllib.parse.unquote(pr.fragment) or pr.hostname, "type": "hysteria2",
         "server": pr.hostname, "port": int(pr.port), "password": pwd, "udp": True}
    if q.get("sni"):
        p["sni"] = q["sni"]
    return p

PARSERS = [("vless://", parse_vless), ("trojan://", parse_trojan),
           ("hysteria2://", parse_hy2), ("hy2://", parse_hy2), ("ss://", parse_ss)]

def parse_links(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("vmess://"):
            continue
        for pref, fn in PARSERS:
            if line.lower().startswith(pref):
                try:
                    p = fn(line)
                except Exception:
                    p = None
                if p and p.get("server") and p.get("port"):
                    out.append(p)
                break
    return out

def sig(p):
    key = "|".join(str(p.get(k, "")) for k in ("type", "server", "port", "uuid", "password", "cipher"))
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]

def load_source(path):
    txt = open(path, "rb").read().decode("utf-8", "replace")
    if re.search(r"^\s*proxies\s*:", txt, re.M):
        try:
            doc = yaml.safe_load(txt)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                return [p for p in doc["proxies"] if isinstance(p, dict) and p.get("server") and p.get("port")]
        except Exception:
            pass
    dec = try_b64(txt)
    return parse_links(dec if dec else txt)

# ---- fetch ----
pool = {}
for name, url in SOURCES.items():
    data = fetch(url)
    if not data:
        print(f"  FAIL {name}", flush=True)
        continue
    path = os.path.join(RAW, name + ".txt")
    open(path, "wb").write(data)
    n = 0
    for p in load_source(path):
        if str(p.get("type")).lower() == "vmess":
            continue
        s = sig(p)
        if s not in pool:
            p["_sig"] = s
            pool[s] = p
            n += 1
    print(f"  OK {name:14s} new={n}", flush=True)
print("pool:", len(pool), flush=True)

# ---- TCP prescan ----
def tcp(server, port, timeout=2.0):
    try:
        t0 = time.perf_counter()
        infos = socket.getaddrinfo(server, port, proto=socket.IPPROTO_TCP)
        fam, st, proto, _, sa = infos[0]
        s = socket.socket(fam, st, proto)
        s.settimeout(timeout)
        try:
            s.connect(sa)
            return round((time.perf_counter() - t0) * 1000)
        finally:
            s.close()
    except Exception:
        return None


seeds = []
old_path = os.path.join(ROOT, 'clash.yaml')
if os.path.exists(old_path):
    try:
        old = yaml.safe_load(open(old_path, encoding='utf-8')) or {}
        for p in (old.get('proxies') or []):
            if not p.get('server'):
                continue
            q = dict(p)
            parts = str(q.get('name', '')).split(' | ')
            q['name'] = 'seed' + str(len(seeds))
            q.pop('udp', None)
            seeds.append(q)
    except Exception as e:
        print('seed load failed:', e)
print('seeds:', len(seeds), flush=True)
seed_keys = {(str(s.get('type')), str(s.get('server')), str(s.get('port'))) for s in seeds}
cands = seeds + [p for p in list(pool.values()) if (str(p.get('type')), str(p.get('server')), str(p.get('port'))) not in seed_keys]
cands = list(cands)
tcp_ok = []
with ThreadPoolExecutor(max_workers=200) as ex:
    futs = {ex.submit(tcp, p["server"], int(p["port"])): p for p in cands}
    for fu in as_completed(futs):
        p = futs[fu]
        r = fu.result()
        if r is not None:
            p["_tcp"] = r
            tcp_ok.append(p)
tcp_ok.sort(key=lambda p: p["_tcp"])
print("tcp alive:", len(tcp_ok), flush=True)
test = tcp_ok[:1100]
for i, p in enumerate(test):
    p["name"] = f"c{i:04d}"

# ---- mihomo 3-round ----
probe = os.path.join(ROOT, "ci_probe")
os.makedirs(probe, exist_ok=True)
cfg = {"mixed-port": 7898, "allow-lan": False, "mode": "rule", "log-level": "warning",
       "ipv6": False, "external-controller": "127.0.0.1:9099", "secret": "",
       "proxies": [{k: v for k, v in p.items() if k != "_tcp"} for p in test],
       "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
cp = os.path.join(probe, "config.yaml")
yaml.safe_dump(cfg, open(cp, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False, width=4096)

def start_mihomo(cfg_path, probe_dir):
    proc = subprocess.Popen(["mihomo", "-d", probe_dir, "-f", cfg_path],
                            stdout=open(os.path.join(probe_dir, "mihomo.log"), "w"),
                            stderr=subprocess.STDOUT)
    for _ in range(40):
        time.sleep(1)
        try:
            urllib.request.urlopen(f"{CTRL}/version", timeout=2).read()
            return proc
        except Exception:
            if proc.poll() is not None:
                return None
    proc.terminate()
    return None

def delay(name, to=6000):
    q = urllib.parse.urlencode({"url": TEST_URL, "timeout": to})
    try:
        with urllib.request.urlopen(f"{CTRL}/proxies/{urllib.parse.quote(name)}/delay?{q}",
                                    timeout=to / 1000 + 5) as f:
            return json.load(f).get("delay")
    except Exception:
        return None

def run_test(names, workers=50):
    out = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fs = {ex.submit(delay, n): n for n in names}
        for f in as_completed(fs):
            out[fs[f]] = f.result()
    return out

passes, lat = collections.Counter(), {}
chunk = 300
good = []
for start in range(0, len(test), chunk):
    batch = test[start:start+chunk]
    cfg = {"mixed-port": 7898, "allow-lan": False, "mode": "rule", "log-level": "warning",
           "ipv6": False, "external-controller": "127.0.0.1:9099", "secret": "",
           "proxies": [{k: v for k, v in p.items() if k != "_tcp"} for p in batch],
           "proxy-groups": [], "rules": ["MATCH,DIRECT"]}
    cp = os.path.join(probe, f"config{start}.yaml")
    yaml.safe_dump(cfg, open(cp, "w", encoding="utf-8"), allow_unicode=True, sort_keys=False, width=4096)
    proc = start_mihomo(cp, probe)
    if not proc:
        print(f"  batch {start}: load failed, skipping", flush=True)
        continue
    good.extend(batch)
    names = [p["name"] for p in batch]
    try:
        for rnd in range(3):
            res = run_test(names)
            for n, v in res.items():
                if v:
                    passes[n] += 1
                    lat[n] = min(lat.get(n, 1 << 30), v)
            print(f"  batch {start} round{rnd+1}: passed={sum(1 for n in names if passes.get(n))}", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

test = good
print(f"tested total: {len(test)}, alive: {len(passes)}", flush=True)
rows = [p for p in test if passes.get(p["name"])]
rows.sort(key=lambda p: (-passes[p["name"]], lat[p["name"]]))
print("alive:", len(rows), flush=True)
picked = rows[:TARGET]
if len(picked) < TARGET:
    print(f"WARN: only {len(picked)} verified (<{TARGET}), keep existing clash.yaml", flush=True)
    raise SystemExit(0)

proxies = []
for i, p in enumerate(picked, 1):
    q = {k: v for k, v in p.items() if k not in ("_sig", "_tcp", "name")}
    core = str(p.get("name") or p.get("server"))
    core = str(q.get("server"))
    q["name"] = f"{i:03d} | {lat[p['name']]}ms | {core}"
    q["udp"] = True
    proxies.append(q)
nm = [p["name"] for p in proxies]
out = {"mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
       "ipv6": True, "unified-delay": True, "external-controller": "127.0.0.1:9090",
       "proxies": proxies,
       "proxy-groups": [
           {"name": "AUTO-FASTEST", "type": "url-test", "proxies": nm,
            "url": TEST_URL, "interval": 300, "tolerance": 50, "lazy": False},
           {"name": "PROXY", "type": "select", "proxies": ["AUTO-FASTEST", "DIRECT"] + nm},
           {"name": "GLOBAL", "type": "select", "proxies": ["AUTO-FASTEST", "PROXY", "DIRECT"] + nm},
       ],
       "rules": ["MATCH,PROXY"]}
header = (
    "# ============================================================\n"
    f"#  免费节点订阅  •  {len(proxies)} 个节点\n"
    f"#  生成时间: {time.strftime('%Y-%m-%d %H:%M')} (UTC)\n"
    "#  说明: 已用 mihomo 多轮实测延迟，全部非 VMess；按通过轮次优先排序\n"
    "#  安全提醒: 公开免费节点不可信，请勿用于网银/支付/公司系统等敏感场景。\n"
    "# ============================================================\n"
)
with open(os.path.join(ROOT, "clash.yaml"), "w", encoding="utf-8", newline="\n") as f:
    f.write(header)
    yaml.safe_dump(out, f, allow_unicode=True, sort_keys=False, width=4096)
print("wrote clash.yaml", len(proxies), flush=True)
