# 遥测网关 UDP 探测与迁网路由追踪

值班员的两组工具，FastAPI + asyncio 实现，全部操作在 `/docs` 内完成：

1. **UDP 最大负载探测（MTUP）**：确认遥测网关可用的最大 UDP 负载，默认 576～1400 字节，
   二分搜索收敛，DF=1 禁止分片；
2. **迁网路由追踪（MTTR/MTRE）**：固定 UDP 源地址/端口、递增 TTL 发诊断包，
   按跳返回 ICMP TTL 超时的路由器地址，并确认最后是哪台回显实例应答。

## 快速开始

### Docker Compose（推荐，含真实路由器演示拓扑）

```bash
docker compose up --build
# 打开 http://localhost:8000/docs
```

### 本地运行

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

---

## 一、迁网路由追踪 `POST /trace`

### 请求（/docs 里填写）

```json
{
  "target_ipv4": "10.1.0.11",
  "target_port": 9999,
  "expected_instance": "echo-instance-a",
  "max_hops": 8
}
```

| 字段 | 约束 | 说明 |
|---|---|---|
| `target_ipv4` | 合法 IPv4 | 目标回显端地址（不接受主机名/IPv6） |
| `target_port` | 1～65535 | 目标 UDP 端口 |
| `expected_instance` | 1～64 字符 | 预期回显实例名 |
| `max_hops` | **1～16** | 最大跳数 |

### 判定规则（与需求逐条对应）

- **固定源**：整个运行只 `bind/connect` 一次，源地址与源端口全程不变；
  从 TTL=1 起逐跳 +1，每跳发一个带**本次运行编号（UUID）+ 序号**的 MTTR 诊断包（40 字节）。
- **按跳归跳**：收到可归属的 ICMP TTL 超时 → 记录该跳路由器地址（`status=router`），进入下一 TTL。
- **500ms 无应答**：等满 500ms 仍无可归属反馈 → 该跳标 `no_response` 并继续，
  超时时间固定 `hop_timeout_ms=500`，不可由请求覆盖。
- **完整 MTUP 头才可归跳**：ICMP 只在引述内层 IP/UDP 且包含**完整 28 字节 MTUP 头**、
  magic/编号/序号全部对应时才归跳；只引述经典 8 字节（IP 头+UDP 头）的差错无法归属，直接丢弃。
- **迟到/无法对应不改判**：编号或序号不符、引述不完整、残包等一律计入 `stray_feedback`，
  既不改变已有跳的判定，也**不算作新一跳的发送失败**；只有真正的 `sendto` 异常才记 `send_error`。
- **实例名应答即停**：回显端收到 MTTR 后用 MTRE 回包带回自己的实例名，
  收到即停止，返回实际实例名与 `matched`：
  - 名称一致 → `status=reached, matched=true`；
  - 名称不一致（错投）→ `status=mismatch, matched=false`。
- **旧端原样回包**：对端不认识 MTTR、把诊断包原样弹回 → `status=instance_unconfirmed`，
  `instance_name=null`，报告实例无法确认并停止。
- **端口不可达单独报告**：目标返回可归属的 ICMP 端口不可达（type 3/code 3）→
  `status=port_unreachable` 并停止；其他目的不可达记 `dest_unreachable`。
- **用尽跳数**：达到 `max_hops` 仍无终态 → `max_hops_exceeded`。

### 返回示例（经过一台路由器）

```json
{
  "trace_id": "…",
  "status": "reached",
  "target_ipv4": "10.1.0.11",
  "target_port": 9999,
  "source_ipv4": "172.30.0.10",
  "source_port": 54321,
  "expected_instance": "echo-instance-a",
  "instance_name": "echo-instance-a",
  "matched": true,
  "max_hops": 8,
  "hops": [
    {"hop": 1, "ttl": 1, "status": "router", "router": "172.30.0.1", "rtt_ms": 0.42},
    {"hop": 2, "ttl": 2, "status": "echo", "router": "10.1.0.11",
     "instance_name": "echo-instance-a", "rtt_ms": 0.88}
  ],
  "reason": null,
  "stray_feedback": 0,
  "icmp_available": true,
  "hop_timeout_ms": 500
}
```

历史结论：`GET /traces`、`GET /trace/{trace_id}`（内存保留最近 200 条）。

### ICMP 接收的两种后端

| 后端 | 特权要求 | 机制 |
|---|---|---|
| `IP_RECVERR` 错误队列（默认） | 无需特权 | 内核把异步 ICMP 差错放入 UDP socket 错误队列，`recvmsg(MSG_ERRQUEUE)` 取出 |
| raw ICMP socket（回退） | `CAP_NET_RAW` | 收整机 ICMP，按引述的 UDP 端口对过滤本运行报文 |

`icmp_available` 字段如实上报本次是否成功启用 ICMP 接收。

---

## 二、Docker Compose 演示：真实 IPv4 路由器 + 双回显实例

拓扑（两个独立 bridge 子网，中间是一台**真实 Linux 路由器**容器，不是模拟）：

```
probe (172.30.0.10) ── net-probe ── router (172.30.0.1 / 10.1.0.1)
                                        │ net-echo (10.1.0.0/24)
                          ┌─────────────┴─────────────┐
                   echo-a (10.1.0.11)         echo-b (10.1.0.12)
                   实例名 echo-instance-a      实例名 echo-instance-b
```

探针启动时自动安装 `10.1.0.0/24 via 172.30.0.1` 路由；路由器开启 `ip_forward`
并放行跨网转发，TTL 耗尽时由内核真实回 ICMP TTL 超时。

### 演示 1：核对中间跳 + 目标实例匹配

`POST /trace`，body：

```json
{"target_ipv4": "10.1.0.11", "target_port": 9999,
 "expected_instance": "echo-instance-a", "max_hops": 8}
```

预期：第 1 跳 `router=172.30.0.1`（真实路由器的 TTL 超时），
第 2 跳 `echo` 且 `instance_name=echo-instance-a`、`matched=true`。

### 演示 2：错投（实际应答实例与预期不符）

把预期名称故意填错，或直接探另一台实例：

```json
{"target_ipv4": "10.1.0.12", "target_port": 9999,
 "expected_instance": "echo-instance-a", "max_hops": 8}
```

预期：正常到达 `10.1.0.12`，但 `instance_name=echo-instance-b`，
`status=mismatch, matched=false` —— 遥测包被错投到了另一台实例。

### 演示 3：端口不可达

```json
{"target_ipv4": "10.1.0.11", "target_port": 12345,
 "expected_instance": "echo-instance-a", "max_hops": 8}
```

预期：路由器归跳后，目标回 ICMP 端口不可达，`status=port_unreachable` 并停止。

### 演示 4：本机 loopback（无中间跳）

```json
{"target_ipv4": "127.0.0.1", "target_port": 9999,
 "expected_instance": "echo-local", "max_hops": 3}
```

预期：TTL=1 直达，第 1 跳即 `echo`，实例名 `echo-local`。

---

## 三、UDP 最大负载探测 `POST /probe`（原 MTUP 能力，保持不变）

Body 可全部缺省：

```json
{"min_size": 576, "max_size": 1400, "timeout_ms": 500, "small_size": 64}
```

| `status` | 含义 |
|---|---|
| `ok` | 已确认最大可用负载（等于 `max_size` 时 `reached_range_max=true`） |
| `below_range` | 链路正常，但范围下限都确认不了 |
| `undetermined` | 大包失败后小包复核也失败，链路不确定，绝不把故障当尺寸上限 |
| `invalidated` | 探测期间回显端配置被修改，本次结论作废 |

- **禁止 IP 分片**：探测/回显 socket 均 `IP_PMTUDISC_DO`（DF=1），`df_enabled` 如实上报；
- **报文带探测编号**：UUID + 序号写入 28 字节 MTUP 头，四项全对应才算成功；
- **大包失败小包复核**：小包通 = 尺寸受限继续二分；小包也不通 = `undetermined`；
- **配置改变结论作废**：回显端配置带单调 `epoch`，不一致即 `invalidated`；
- **原 MTUP 探测仍原样回显**：回显端只对 MTTR 诊断包改回 MTRE，普通 MTUP 报文行为不变。

### 回显端配置 `PUT /echo/config`

```json
{"mode": "normal", "drop_threshold": 1000, "instance_name": "edge-paris-01"}
```

- `drop_threshold`：UDP 负载超过该字节数即丢弃；`null` 不丢弃；
- `mode=disconnect`：丢弃一切报文；
- `instance_name`：本实例名，MTTR 诊断包的 MTRE 应答携带它（默认取环境变量 `ECHO_INSTANCE_NAME`）；
- 校验失败返回 422，**原配置保持不变**；每次成功变更 `epoch+1`。

## 报文格式

三类报文共享 28 字节 MTUP 头（`magic="MTUP" | UUID(16) | seq | size`）：

| 报文 | magic/kind | 长度 | 用途 |
|---|---|---|---|
| MTUP 探测 | `MTUP` | 可变 | 最大负载探测，回显端**原样回显** |
| MTTR 诊断 | 头 `MTUP` + kind `MTTR` | 40B | 路由追踪请求 |
| MTRE 应答 | 头 `MTUP` + kind `MTRE` | 36B+名称 | 回显端携带实例名的应答 |

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `ECHO_HOST` | `0.0.0.0` | 回显端监听地址 |
| `ECHO_PORT` | `9999` | 回显端 UDP 端口 |
| `ECHO_INSTANCE_NAME` | `echo-local` | 本回显实例名（MTRE 应答内容） |
| `PROBE_TARGET_HOST` | `127.0.0.1` | `/probe` 默认目标 |
| `ROUTER_IP` / `ECHO_SUBNET` | `172.30.0.1` / `10.1.0.0/24` | compose 演示静态路由 |
| `SKIP_ROUTE_SETUP` | `0` | 回显实例设为 `1` 跳过路由安装 |

## 项目结构

```
app/
  main.py          # FastAPI 路由与生命周期（/probe、/trace、/echo/config）
  echo_server.py   # 回显端：MTUP 原样回显、MTTR→MTRE 实例名应答、epoch
  prober.py        # 最大负载二分探测引擎
  tracer.py        # 路由追踪引擎（固定源、递增 TTL、500ms 归跳、终态判定）
  packets.py       # MTUP/MTTR/MTRE 报文编解码
  icmp.py          # ICMP 差错解析（完整 MTUP 头归属、校验和、测试造包）
  icmp_receiver.py # IP_RECVERR 错误队列 / raw ICMP 两种接收后端
  netutil.py       # DF 位设置
router/            # 真实 Linux 路由器容器（ip_forward + iptables）
entrypoint.sh      # 探针容器入口（安装经路由器的静态路由）
tests/
```
