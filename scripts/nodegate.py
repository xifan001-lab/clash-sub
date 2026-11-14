
# -*- coding: utf-8 -*-
"""Classify node IPs (residential vs datacenter) and gate nodes on Google AI Studio.

Used by pipeline_ci.py. Both steps degrade gracefully: if ip-api or mihomo is
unavailable the caller still gets a usable (if less precise) node set.
"""
import json, os, time, collections, subprocess, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

def _find_mihomo():
    """Locate the mihomo binary: env override, PATH, then common CI locations."""
    env = os.environ.get("MIHOMO_BIN")
    if env and os.path.exists(env):
        return env
    for cand in ("mihomo", "verge-mihomo",
                 "/usr/local/bin/mihomo", "/usr/bin/mihomo",
                 r"C:\Program Files\Clash Verge\verge-mihomo.exe"):
        if os.path.sep in cand:
            if os.path.exists(cand):
                return cand
        else:
            from shutil import which
            found = which(cand)
            if found:
                return found
    return "mihomo"


MIHOMO = _find_mihomo()
CTRL = "http://127.0.0.1:9099"
AI_URL = "https://aistudio.google.com/app/apikey"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
OP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
IP_FIELDS = "status,query,countryCode,isp,hosting"


def classify(proxies, cache_path, workers=1):
    """Annotate each proxy with _hosting True/False/None using ip-api batch."""
    cache = {}
    if os.path.exists(cache_path):
        try:
            cache = json.load(open(cache_path, encoding="utf-8"))
            cache = {k: v for k, v in cache.items() if v.get("status") == "success"}
        except Exception:
            cache = {}

    servers = sorted({str(p.get("server")) for p in proxies})
    todo = [s for s in servers if s not in cache]
    print(f"  classify: {len(servers)} servers, {len(todo)} to query", flush=True)

    def batch(ips):
        body = json.dumps([{"query": ip} for ip in ips]).encode()
        req = urllib.request.Request(
            f"http://ip-api.com/batch?fields={IP_FIELDS}",
            data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    i = 0
    while i < len(todo):
        chunk = todo[i:i + 95]
        for attempt in range(3):
            try:
                for ip, info in zip(chunk, batch(chunk)):
                    cache[ip] = info
                break
            except Exception:
                if attempt == 2:
                    for ip in chunk:
                        cache.setdefault(ip, {"status": "fail"})
                time.sleep(3)
        i += 95
        time.sleep(4.5)

    try:
        json.dump(cache, open(cache_path, "w", encoding="utf-8"), ensure_ascii=False)
    except Exception:
        pass

    for p in proxies:
        info = cache.get(str(p.get("server"))) or {}
        p["_hosting"] = info.get("hosting")
        p["_cc"] = info.get("countryCode")
    c = collections.Counter(
        "RES" if p["_hosting"] is False else ("DC" if p["_hosting"] else "UNK")
        for p in proxies)
    print(f"  classify done: {dict(c)}", flush=True)
    return proxies


def _ai_probe(port, timeout=18):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}))
    req = urllib.request.Request(AI_URL, headers={"User-Agent": UA})
    try:
        with op.open(req, timeout=timeout) as r:
            r.read(2000)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _start(cfg_path, work_dir):
    proc = subprocess.Popen(
        [MIHOMO, "-d", work_dir, "-f", cfg_path],
        stdout=open(os.path.join(work_dir, "ai_mihomo.log"), "w"),
        stderr=subprocess.STDOUT)
    for _ in range(40):
        time.sleep(0.6)
        try:
            OP.open(f"{CTRL}/version", timeout=2).read()
            return proc
        except Exception:
            if proc.poll() is not None:
                return None
    try:
        proc.terminate()
    except Exception:
        pass
    return None


def ai_gate(proxies, work_dir, batch_size=110, base_port=21000):
    """Probe each proxy against Google AI Studio through its own listener port."""
    import yaml
    os.makedirs(work_dir, exist_ok=True)
    for p in proxies:
        p["_ai"] = None

    for start in range(0, len(proxies), batch_size):
        part = proxies[start:start + batch_size]
        px, listeners, ports = [], [], {}
        for i, n in enumerate(part):
            pn = f"n{i:04d}"
            q = {k: v for k, v in n.items() if not k.startswith("_")}
            q["name"] = pn
            px.append(q)
            port = base_port + i
            listeners.append({"name": f"L{i:04d}", "type": "mixed", "port": port, "proxy": pn})
            ports[pn] = port
        cfg = {"mixed-port": 0, "allow-lan": False, "mode": "rule",
               "log-level": "warning", "ipv6": True,
               "external-controller": "127.0.0.1:9099", "secret": "",
               "proxies": px, "proxy-groups": [], "listeners": listeners,
               "rules": ["MATCH,DIRECT"]}
        cp = os.path.join(work_dir, "ai_config.yaml")
        yaml.safe_dump(cfg, open(cp, "w", encoding="utf-8"),
                       allow_unicode=True, sort_keys=False, width=4096)
        proc = _start(cp, work_dir)
        if not proc:
            print(f"  ai batch {start}: LOAD FAILED", flush=True)
            continue
        time.sleep(1)
        try:
            with ThreadPoolExecutor(max_workers=40) as ex:
                fut_map = {ex.submit(_ai_probe, port): idx
                           for idx, port in enumerate(ports.values())}
                results = {}
                for fu in as_completed(fut_map):
                    results[fut_map[fu]] = fu.result()
            for i, n in enumerate(part):
                n["_ai"] = results.get(i)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except Exception:
                proc.kill()
        ok = sum(1 for n in part if n["_ai"] == 200)
        print(f"  ai batch {start}: {ok}/{len(part)} HTTP200", flush=True)

    total = sum(1 for p in proxies if p["_ai"] == 200)
    print(f"  ai gate done: {total}/{len(proxies)} can open AI Studio", flush=True)
    return proxies
