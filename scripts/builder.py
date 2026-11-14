
# -*- coding: utf-8 -*-
"""Compose the published subscription: 个人(AI) / 机房(AI) / 备用 groups."""
import collections
import yaml

TEST_URL = "https://www.gstatic.com/generate_204"
AI_URL = "https://aistudio.google.com/"
TARGET = 100
PERSONAL_TARGET = 40
DC_TARGET = 50


def _cls(p):
    if p.get("_hosting") is False:
        return "RES"
    if p.get("_hosting"):
        return "DC"
    return "UNK"


def compose(proxies, target=TARGET):
    """proxies: dicts with latency info (_delay), _passes, _hosting, _ai, name/orig name."""
    personal = [p for p in proxies if _cls(p) == "RES" and p.get("_ai") == 200]
    dc_ai = [p for p in proxies if _cls(p) == "DC" and p.get("_ai") == 200]
    for lst in (personal, dc_ai):
        lst.sort(key=lambda p: p["_delay"])

    picked_p = personal[:PERSONAL_TARGET]
    picked_d = dc_ai[:DC_TARGET]

    used = {(p.get("type"), str(p.get("server")), str(p.get("port"))) for p in picked_p + picked_d}
    rest = [p for p in proxies
            if (p.get("type"), str(p.get("server")), str(p.get("port"))) not in used]
    # prefer AI-capable and stable ones when filling
    rest.sort(key=lambda p: (0 if p.get("_ai") == 200 else 1,
                             -p.get("_passes", 0), p["_delay"]))

    chosen = picked_p + picked_d
    for p in rest:
        if len(chosen) >= target:
            break
        chosen.append(p)

    tags = {}
    for p in picked_p:
        tags[id(p)] = "个人"
    for p in picked_d:
        tags.setdefault(id(p), "机房")
    for p in chosen:
        tags.setdefault(id(p), "备用")

    order = {"个人": 0, "机房": 1, "备用": 2}
    chosen.sort(key=lambda p: (order[tags[id(p)]], p["_delay"]))

    out_proxies, groups, seen = [], {"个人": [], "机房": [], "备用": []}, set()
    for p in chosen:
        q = {k: v for k, v in p.items() if not k.startswith("_")}
        core = str(p.get("_orig") or q.get("name") or q.get("server"))
        core = core.replace("|", "/").strip()[:54]
        tag = tags[id(p)]
        nm = f"{len(out_proxies)+1:03d} | {p['_delay']}ms | {tag} {core}"
        while nm in seen:
            nm += " *"
        seen.add(nm)
        q["name"] = nm
        q["udp"] = True
        out_proxies.append(q)
        groups[tag].append(nm)

    names = [p["name"] for p in out_proxies]
    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "warning", "ipv6": True, "unified-delay": True,
        "external-controller": "127.0.0.1:9090",
        "proxies": out_proxies,
        "proxy-groups": [
            {"name": "AI-STUDIO", "type": "url-test",
             "proxies": groups["个人"] + groups["机房"],
             "url": AI_URL, "interval": 600, "tolerance": 80, "lazy": False},
            {"name": "个人节点", "type": "select",
             "proxies": ["AI-STUDIO"] + groups["个人"]},
            {"name": "机房节点", "type": "select",
             "proxies": ["AI-STUDIO"] + groups["机房"]},
            {"name": "AUTO-FASTEST", "type": "url-test", "proxies": names,
             "url": TEST_URL, "interval": 300, "tolerance": 50, "lazy": False},
            {"name": "PROXY", "type": "select",
             "proxies": ["AI-STUDIO", "个人节点", "机房节点", "AUTO-FASTEST", "DIRECT"] + names},
            {"name": "GLOBAL", "type": "select",
             "proxies": ["AI-STUDIO", "个人节点", "机房节点", "AUTO-FASTEST",
                         "PROXY", "DIRECT"] + names},
        ],
        "rules": ["MATCH,PROXY"],
    }
    return cfg, groups


def render(cfg, groups, when):
    import collections as _c
    from datetime import datetime
    pc = _c.Counter(p["type"] for p in cfg["proxies"])
    ds = sorted(int(p["name"].split(" | ")[1].replace("ms", "")) for p in cfg["proxies"])
    header = (
        "# ============================================================\n"
        f"#  免费节点订阅  •  {len(cfg['proxies'])} 个节点\n"
        f"#  生成时间: {when}\n"
        f"#  个人节点（住宅 IP + Google AI Studio 实测可访问）: {len(groups['个人'])} 个\n"
        f"#  机房节点（AI Studio 实测可访问）: {len(groups['机房'])} 个\n"
        f"#  备用节点: {len(groups['备用'])} 个\n"
        "#  AI 组节点逐个以独立端口验证 aistudio.google.com 返回 200\n"
        "#  全部节点经 mihomo 多轮延迟实测\n"
        "#  协议: " + ", ".join(f"{k}×{v}" for k, v in sorted(pc.items())) + "\n"
        f"#  延迟: {ds[0]}~{ds[-1]} ms（实测）\n"
        "#  安全提醒: 公开免费节点不可信，请勿用于网银/支付/公司系统等敏感场景。\n"
        "# ============================================================\n"
    )
    return header + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, width=4096)
