# clash-sub

自动生成并实测可用的 Clash/Mihomo 免费节点订阅。

## 订阅链接

```
https://raw.githubusercontent.com/xifan001-lab/clash-sub/main/clash.yaml
```

镜像（国内直连不稳时使用）：

```
https://gh-proxy.com/https://raw.githubusercontent.com/xifan001-lab/clash-sub/main/clash.yaml
```

## 节点构成

| 分组 | 数量 | 说明 |
| --- | --- | --- |
| 个人节点 | 26 | 住宅 IP，已逐节点验证可打开 Google AI Studio |
| 机房节点 | 60 | 数据中心 IP，已验证可打开 Google AI Studio |
| 备用节点 | 14 | 多轮实测稳定，延迟优先 |

- 节点总数：100
- 协议：http×61, hysteria×3, hysteria2×1, socks5×5, ss×12, trojan×1, vless×17
- 延迟：165 ~ 2750 ms（实测）

## 内置策略组

- `AI-STUDIO`：所有验证过 AI Studio 的节点自动选最快，专供 Google AI Studio / Gemini
- `个人节点`：仅住宅 IP 节点，最不容易触发风控
- `机房节点`：仅数据中心节点
- `AUTO-FASTEST` / `PROXY` / `GLOBAL`：通用自动选择

## 判定方式

- 延迟：本机 mihomo 内核多轮延迟实测，按通过率择优
- AI Studio：每个节点开独立本地端口，实测 aistudio.google.com/app/apikey 返回 200
- IP 类型：ip-api 查询 hosting 字段区分住宅 / 机房

> 公开免费节点不可信，请勿用于网银/支付/公司系统等敏感场景。
