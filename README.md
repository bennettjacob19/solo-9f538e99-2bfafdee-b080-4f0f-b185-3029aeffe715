# 遥测网关 UDP 最大负载探测 + 逐跳诊断

迁网验收分两段：**先看清遥测包经过哪些路由器，再确认最后是哪台回显实例应答**。

- `POST /trace`：逐跳诊断。填目标 IPv4、UDP 端口、预期回显实例名与最大跳数（1～16），
  固定 UDP 源地址和端口，递增 TTL 发出带编号和序号的诊断包；按跳返回当次 ICMP TTL
  超时的路由器地址，最后报告实际回显实例名与是否匹配。
- `POST /probe`：原有的最大 UDP 负载探测（二分搜索、DF、小包复核、配置变更作废），
  行为保持不变。

## 快速开始

```bash
docker compose up --build
# 打开 http://localhost:8000/docs
```

Compose 默认启动 `lab` 服务：容器内用网络命名空间搭出一条**真实的 IPv4 转发路径**
（全部是 RFC 2544 / RFC 5737 保留地址，不碰真实网络）：

```
probe(172.30.0.2) ── r1(172.30.0.1 / 10.1.0.1) ── r2(10.1.0.2 / 192.0.2.1)
                                                       └─ 192.0.2.0/24
                                                          echo-a   .10  实例名 echo-a
                                                          echo-b   .11  实例名 echo-b
                                                          legacy   .12  旧端，原样回显
                                                          (void)   .99  无监听 → 端口不可达
```

中间跳是真正的内核路由器（`ip_forward=1`），ICMP TTL 超时由它们自己回送。若运行
环境不允许建命名空间，脚本会打印警告并降级：只有本地回显（`127.0.0.1:9999`）可用，
`/trace` 仍可指向真实设备。只想要纯应用镜像时：

```bash
docker compose --profile plain up --build   # 8001→/docs，9998/udp→本地回显
```

本地运行：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
pytest tests/ -v          # 需要 requirements-dev.txt
```

## 在 /docs 里验收

1. 展开 `POST /trace`，按需填：

   ```json
   {
     "target_host": "192.0.2.10",
     "target_port": 9999,
     "expected_instance": "echo-a",
     "max_hops": 6,
     "hop_timeout_ms": 500,
     "source_port": 40000
   }
   ```

   `target_host` 必须是 IPv4；`max_hops` 1～16；`expected_instance` 留空则只报告实际
   实例名、不判定匹配；`source_host`/`source_port` 留空时自动探测出口地址、随机端口，
   **整个诊断内保持不变**。`GET /` 的 `demo_targets` 已给出四个演示请求体。
2. 读结论：

   | `status` | 含义 |
   |---|---|
   | `reply` | 收到目标回显实例应答；`instance_name` 为实际实例名，`instance_matched` 为是否匹配预期 |
   | `instance_unconfirmed` | 旧端把诊断包原样回包，**应答里没有实例名**，无法确认是哪台实例 |
   | `port_unreachable` | 目标端口返回 ICMP 端口不可达，**单独报告并停止** |
   | `no_reply` | 在 `max_hops` 内没收到应答；`hops[]` 逐跳列出 TTL 超时/无应答 |
   | `error` | 发送失败或不可用反馈（如网络不可达），在对应跳停止 |

   `hops[]` 每项：`hop`、`status`（`ttl_exceeded` / `reply` / `port_unreachable` /
   `timeout` / `send_error`）、当次 ICMP TTL 超时的 `router_ip`、`rtt_ms`。
3. 演示错投：把目标改成 `192.0.2.11`、预期仍写 `echo-a` → `instance_matched=false`，
   `reason` 指出实际是 `echo-b`。
4. 历史：`GET /traces`、`GET /trace/{trace_id}`（内存保留最近 200 条）。

## 判定规则（需求逐条对应）

- **固定源**：一次诊断只创建一个 UDP socket、绑定一次 `(IPv4, port)`，所有跳共用；
  源地址缺省时先查内核对目标选用的出口地址再绑定。
- **递增 TTL、带编号和序号**：第 1..N 跳依次设置 `IP_TTL`，每跳发一个 `MTPS`
  诊断包（session UUID + seq + hop + nonce），源端口不变。
- **当次按跳返回 ICMP TTL 超时的路由器地址**：ICMP 通过 `IP_RECVERR` 错误队列读取
  （普通 socket，**无需 root**），路由器地址取内核 `sock_extended_err` 中的 offender。
- **等满 500ms 无可归属反馈即记无应答并继续**：每跳窗口默认 `hop_timeout_ms=500`；
  没收到就记 `timeout`，继续下一跳。
- **迟到/无法对应不改判、不算新一跳失败**：反馈按引述报文里的 session/seq 归属；
  seq 更小或内核接收时间已出窗口 → 计入 `late_feedback`；别的会话/未来的 seq/
  没有可归属信息 → 计入 `unmatched_feedback`。两者都**不会**改判已结束的跳，
  也**不会**被当成新一跳的结果。
- **ICMP 只引述完整 MTUP 头也能归跳**：只要引述中含有完整的 40 字节 `MTPS` 头就
  可按 session/seq/hop 归属，不要求引述完整负载。
- **回显端回包带实例名**：回显端收到诊断包后回 `MTRP`（session + seq + nonce +
  实例名），收到本次对应应答即停止，返回实际实例名与 `instance_matched`。
- **旧端原样回包 → 实例无法确认**：回包仍是 `MTPS`、没有实例名，报
  `instance_unconfirmed`（`instance_name=null`），不猜实例名。
- **目标 ICMP 端口不可达 → 单独报告并停止**：`port_unreachable`，`reached=false`。
- **原 MTUP 探测仍原样回显**：`/probe` 的报文与回显行为不变；诊断包用独立 magic，
  不与探测报文混淆。

## 最大负载探测（`/probe`，原有功能）

1. `PUT /echo/config` 设置回显端行为：`{"mode": "normal", "drop_threshold": 1000}`
   或 `{"mode": "disconnect"}`；也可设置 `instance_name` 与 `trace_mode`
   （`instance`=回带实例名，`legacy`=原样回显诊断包）。校验失败返回 422，原配置不变。
2. `POST /probe`（Body 可全部缺省）：

   ```json
   {"min_size": 576, "max_size": 1400, "timeout_ms": 500, "small_size": 64}
   ```

3. 结论：

   | `status` | 含义 | `max_confirmed_size` |
   |---|---|---|
   | `ok` | 已确认最大可用负载 | 确认值（等于 `max_size` 时 `reached_range_max=true`） |
   | `below_range` | 链路正常，但范围下限都确认不了 | `null` |
   | `undetermined` | 大包失败后小包复核也失败，链路不确定 | 已确认下界，**绝不把故障当尺寸上限** |
   | `invalidated` | 探测期间回显端配置被修改，本次结论作废 | `null` |

   `attempts[]` 列出每次 `probe` 与 `link-verify` 的尺寸、结果、RTT。
4. 历史：`GET /probes`、`GET /probe/{probe_id}`。

探测与回显 socket 均设置 `IP_MTU_DISCOVER/IP_PMTUDISC_DO`（DF=1）；报文头为
`magic | UUID | seq | size | 填充`，只有全部对应的回包才采信；大包失败先用
`small_size` 复核链路；回显配置带单调 `epoch`，探测期间变化则结论作废。

## 权限说明

逐跳诊断读取的是**普通 UDP socket 的 ICMP 错误队列**（`IP_RECVERR`），不需要 root
或 `CAP_NET_RAW`。Compose 演示中 `lab` 容器需要的权限只用于**搭建演示拓扑**：

| 能力 | 用途 |
|---|---|
| `SYS_ADMIN` | `ip netns add` 建网络命名空间 |
| `NET_ADMIN` | veth / 网桥 / 路由 / `ip_forward` |

生产环境把 `/trace` 指向真实设备时，纯应用镜像无需任何额外能力。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `ECHO_HOST` | `0.0.0.0` | 本地回显端监听地址 |
| `ECHO_PORT` | `9999` | 本地回显端 UDP 端口 |
| `PROBE_TARGET_HOST` | `127.0.0.1` | `/probe` 默认目标（可用请求体覆盖） |
| `ECHO_ADVERTISE_HOST` | 同 `PROBE_TARGET_HOST` | 首页展示的默认回显地址 |
| `ALLOW_TOPOLOGY` | `1` | `0` 时 lab 容器跳过演示拓扑 |

## 项目结构

```
app/
  main.py        # FastAPI 路由与生命周期
  traceroute.py  # 逐跳诊断引擎（MTPS/MTRP 报文、IP_RECVERR、归属规则）
  echo_server.py # 回显端（MTUP 原样回显 + 诊断包回实例名/旧端模式）
  lab_echo.py    # Compose 演示用的独立回显进程
  prober.py      # 二分负载探测
  packets.py     # MTUP 探测报文编解码
  netutil.py     # DF / TTL socket 选项
demo/
  lab_topology.sh  # 演示拓扑：r1/r2 真实路由器 + 三个回显实例
tests/
  test_api.py      # API、MTUP 探测、/trace 端到端
  test_trace.py    # 报文编解码、归属规则、迟到/无关反馈、固定源
Dockerfile（app/lab 两阶段）/ docker-compose.yml
```
