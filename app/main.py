"""FastAPI 入口：最大负载探测 + 逐跳诊断 + 回显端配置。

- ``GET  /``                    服务简介
- ``GET  /echo/config``         查看回显端当前配置与 epoch
- ``PUT  /echo/config``         设置丢弃阈值 / 断联 / 实例名（校验失败保留原状态）
- ``POST /probe``               发起一次最大负载探测（默认范围 576~1400 字节）
- ``POST /trace``               逐跳诊断：固定源、递增 TTL、核对中间跳与回显实例
- ``GET  /trace/{id}``          查询历史诊断结论
- ``GET  /traces``              历史诊断结论列表
- ``GET  /probe/{id}``          查询历史探测结论
- ``GET  /probes``              历史探测结论列表

交互式文档见 ``/docs``。
"""
from __future__ import annotations

import asyncio
import os
import socket
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request

from .echo_server import EchoConfig, EchoProtocol, EchoState
from .netutil import set_dont_fragment
from .prober import ProbeRequest, ProbeResult, Prober
from .traceroute import TraceRequest, TraceResult, TraceRunner

ECHO_HOST = os.environ.get("ECHO_HOST", "0.0.0.0")
ECHO_PORT = int(os.environ.get("ECHO_PORT", "9999"))
PROBE_TARGET_HOST = os.environ.get("PROBE_TARGET_HOST", "127.0.0.1")
# 回显端的可达 IPv4 地址：Compose 中由 environment 注入，/trace 默认目标使用
ECHO_ADVERTISE_HOST = os.environ.get("ECHO_ADVERTISE_HOST", PROBE_TARGET_HOST)

MAX_RESULTS = 200  # 内存中保留的探测/诊断结论条数上限

# Compose 演示拓扑中的回显实例（见 docker-compose.yml / demo/lab_topology.sh）
DEMO_TARGETS = [
    {
        "name": "预期实例（匹配）",
        "request": {
            "target_host": "192.0.2.10",
            "target_port": 9999,
            "expected_instance": "echo-a",
            "max_hops": 6,
        },
    },
    {
        "name": "错投（实际应答 echo-b）",
        "request": {
            "target_host": "192.0.2.11",
            "target_port": 9999,
            "expected_instance": "echo-a",
            "max_hops": 6,
        },
    },
    {
        "name": "旧端（实例无法确认）",
        "request": {
            "target_host": "192.0.2.12",
            "target_port": 9999,
            "expected_instance": "echo-a",
            "max_hops": 6,
        },
    },
    {
        "name": "无人监听（端口不可达）",
        "request": {
            "target_host": "192.0.2.99",
            "target_port": 9999,
            "expected_instance": "echo-a",
            "max_hops": 6,
        },
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    state = EchoState()

    # 回显端 socket：设置 DF，回包同样禁止 IP 分片
    echo_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    set_dont_fragment(echo_sock)
    echo_sock.bind((ECHO_HOST, ECHO_PORT))
    echo_sock.setblocking(False)

    loop = asyncio.get_running_loop()
    echo_protocol = EchoProtocol(state)
    echo_transport, _ = await loop.create_datagram_endpoint(
        lambda: echo_protocol, sock=echo_sock
    )

    app.state.echo_state = state
    app.state.echo_protocol = echo_protocol
    app.state.prober = Prober(state, (PROBE_TARGET_HOST, ECHO_PORT))
    app.state.probes = OrderedDict()  # probe_id -> ProbeResult
    app.state.traces = OrderedDict()  # trace_id -> TraceResult
    try:
        yield
    finally:
        echo_transport.close()


app = FastAPI(
    title="遥测网关 UDP 最大负载探测与逐跳诊断",
    version="2.0.0",
    description=(
        "迁网验收工具：确认遥测 UDP 包经过哪些路由器、最后是哪台回显实例应答。\n\n"
        "**逐跳诊断 `POST /trace`**\n"
        "- 填目标 IPv4、UDP 端口、预期回显实例名与最大跳数（1～16）；\n"
        "- 固定 UDP 源地址与端口，递增 TTL 发出带编号（session）和序号（seq）的诊断包；\n"
        "- 按跳返回当次 ICMP TTL 超时的路由器地址；等满 `hop_timeout_ms`（默认 500ms）"
        "无可归属反馈即记无应答并继续；\n"
        "- 迟到或无法对应的反馈只会累加计数，不改判、不算作新一跳的发送失败；\n"
        "- 回显端用 UDP 回包带回实例名；收到即停止并报告实际实例名与是否匹配；"
        "旧端原样回包时报实例无法确认；目标 ICMP 端口不可达时单独报告并停止。\n\n"
        "**最大负载探测 `POST /probe`**（原有功能，行为不变）\n"
        "- DF 位、探测编号、小包复核、配置变更作废；详见 README。"
    ),
    lifespan=lifespan,
)


@app.get("/", summary="服务简介")
async def index() -> dict:
    return {
        "service": "telemetry-gateway-udp-probe",
        "docs": "/docs",
        "endpoints": {
            "config": ["GET /echo/config", "PUT /echo/config"],
            "probe": ["POST /probe", "GET /probes", "GET /probe/{probe_id}"],
            "trace": ["POST /trace", "GET /traces", "GET /trace/{trace_id}"],
        },
        "defaults": {"echo_target": f"{ECHO_ADVERTISE_HOST}:{ECHO_PORT}"},
    }


@app.get("/echo/config", summary="查看回显端配置")
async def get_config(request: Request) -> dict:
    state: EchoState = request.app.state.echo_state
    proto: EchoProtocol = request.app.state.echo_protocol
    return {
        "epoch": state.epoch,
        "config": state.config,
        "listen": f"{ECHO_HOST}:{ECHO_PORT}",
        "advertise": f"{ECHO_ADVERTISE_HOST}:{ECHO_PORT}",
        "stats": {
            "echoed": proto.echoed,
            "dropped": proto.dropped,
            "trace_replied": proto.trace_replied,
            "trace_echoed": proto.trace_echoed,
        },
    }


@app.put("/echo/config", summary="设置丢弃阈值 / 断联 / 实例名")
async def put_config(cfg: EchoConfig, request: Request) -> dict:
    # 入参先经 Pydantic 校验；校验失败直接 422，不会进入这里，原状态保持不变
    state: EchoState = request.app.state.echo_state
    epoch = state.apply(cfg)
    return {"epoch": epoch, "config": state.config}


@app.post("/probe", response_model=ProbeResult, summary="发起一次最大负载探测")
async def run_probe(req: ProbeRequest, request: Request) -> ProbeResult:
    prober: Prober = request.app.state.prober
    try:
        result = await prober.probe(req)
    except OSError as exc:
        # 目标地址无法解析/不可达等，探测未能发起
        raise HTTPException(status_code=400, detail=f"无法发起探测: {exc}") from exc
    results: OrderedDict[str, ProbeResult] = request.app.state.probes
    results[result.probe_id] = result
    while len(results) > MAX_RESULTS:
        results.popitem(last=False)
    return result


@app.post("/trace", response_model=TraceResult, summary="逐跳诊断：核对中间跳与回显实例")
async def run_trace(req: TraceRequest, request: Request) -> TraceResult:
    runner = TraceRunner()
    try:
        result = await runner.run(req)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"无法发起诊断: {exc}") from exc
    traces: OrderedDict[str, TraceResult] = request.app.state.traces
    traces[result.trace_id] = result
    while len(traces) > MAX_RESULTS:
        traces.popitem(last=False)
    return result


@app.get("/trace/{trace_id}", response_model=TraceResult, summary="查询历史诊断结论")
async def get_trace(trace_id: str, request: Request) -> TraceResult:
    traces: OrderedDict[str, TraceResult] = request.app.state.traces
    try:
        return traces[trace_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="trace_id 不存在或已被淘汰") from None


@app.get("/traces", summary="历史诊断结论列表")
async def list_traces(request: Request) -> list[dict]:
    traces: OrderedDict[str, TraceResult] = request.app.state.traces
    return [
        {
            "trace_id": r.trace_id,
            "status": r.status,
            "target": r.target,
            "instance_name": r.instance_name,
            "instance_matched": r.instance_matched,
            "reason": r.reason,
            "finished_at": r.finished_at,
        }
        for r in reversed(list(traces.values()))
    ]


@app.get("/probe/{probe_id}", response_model=ProbeResult, summary="查询历史探测结论")
async def get_probe(probe_id: str, request: Request) -> ProbeResult:
    results: OrderedDict[str, ProbeResult] = request.app.state.probes
    try:
        return results[probe_id]
    except KeyError:
        raise HTTPException(status_code=404, detail="probe_id 不存在或已被淘汰") from None


@app.get("/probes", summary="历史探测结论列表")
async def list_probes(request: Request) -> list[dict]:
    results: OrderedDict[str, ProbeResult] = request.app.state.probes
    return [
        {
            "probe_id": r.probe_id,
            "status": r.status,
            "max_confirmed_size": r.max_confirmed_size,
            "reason": r.reason,
            "finished_at": r.finished_at,
        }
        for r in reversed(list(results.values()))
    ]
