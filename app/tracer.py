"""迁网验收路由追踪引擎。

流程（与需求逐条对应）：

- 在 ``/docs`` 提交目标 IPv4、UDP 端口、预期回显实例名、最大跳数（1~16）；
- 整个运行使用**固定 UDP 源地址与源端口**（同一 socket 只 bind/connect 一次），
  从 TTL=1 开始逐跳递增，每跳发出带本次运行编号（UUID）与序号的 MTTR 诊断包；
- 每跳等待 500ms：
  - 收到可归属的 ICMP TTL 超时（引述**完整 MTUP 头**且编号/序号对应）→
    记录该跳路由器地址，进入下一 TTL；
  - 收到回显端 MTRE 应答 → 停止，返回实际实例名及与预期是否匹配；
  - 收到旧端原样回包 → 报告"实例无法确认"并停止；
  - 收到可归属的 ICMP 端口不可达 → 单独报告并停止；
  - 等满 500ms 仍无可归属反馈 → 该跳标记无应答，继续下一 TTL；
- 迟到或无法对应的反馈（编号/序号不符、引述不完整）一律计入 stray，
  **不改变既有判定，也不算作新一跳的发送失败**；只有真正的 sendto 异常
  才记为发送失败。
"""
from __future__ import annotations

import asyncio
import errno
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .icmp import IcmpFeedback, IcmpKind
from .icmp_receiver import IcmpReceiver, open_icmp_receiver
from .packets import (
    HEADER_SIZE,
    build_trace_packet,
    is_trace_request,
    parse_packet,
    parse_trace_reply,
)

HOP_TIMEOUT_MS = 500  # 需求固定：每跳等满 500 毫秒
MAX_INSTANCE_NAME_LEN = 64


# ---------------------------------------------------------------------------
# API 模型
# ---------------------------------------------------------------------------


class TraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_ipv4: str = Field(..., description="目标回显端 IPv4 地址")
    target_port: int = Field(..., ge=1, le=65535, description="目标 UDP 端口")
    expected_instance: str = Field(
        ..., min_length=1, max_length=MAX_INSTANCE_NAME_LEN, description="预期回显实例名"
    )
    max_hops: int = Field(..., ge=1, le=16, description="最大跳数（1~16）")

    @field_validator("target_ipv4")
    @classmethod
    def _must_be_ipv4(cls, v: str) -> str:
        try:
            socket.inet_pton(socket.AF_INET, v)
        except OSError:
            raise ValueError("target_ipv4 必须是合法的 IPv4 地址") from None
        return v

    @field_validator("expected_instance")
    @classmethod
    def _name_no_newline(cls, v: str) -> str:
        if any(ch in v for ch in ("\r", "\n")):
            raise ValueError("实例名不能包含换行符")
        return v


class HopResult(BaseModel):
    hop: int = Field(..., description="跳数（TTL 序号，从 1 开始）")
    ttl: int
    status: str = Field(
        ...,
        description=(
            "router=ICMP TTL 超时归跳；no_response=等满 500ms 无可归属反馈；"
            "echo=回显端应答（终跳）；legacy_echo=旧端原样回包（终跳）；"
            "port_unreachable=ICMP 端口不可达（终跳）；"
            "dest_unreachable=其他 ICMP 目的不可达（终跳）；send_error=发送失败"
        ),
    )
    router: Optional[str] = Field(None, description="归跳路由器/主机 IPv4")
    instance_name: Optional[str] = Field(None, description="终跳回显实例名（MTRE）")
    rtt_ms: Optional[float] = None
    detail: Optional[str] = None


class TraceResult(BaseModel):
    trace_id: str
    status: str = Field(
        ...,
        description=(
            "reached=收到实例名应答；mismatch=收到应答但实例名与预期不符；"
            "instance_unconfirmed=旧端原样回包；port_unreachable=目标端口不可达；"
            "dest_unreachable=其他目的不可达；max_hops_exceeded=达到最大跳数仍无终态；"
            "send_failed=socket 发送失败"
        ),
    )
    target_ipv4: str
    target_port: int
    source_ipv4: str = Field(..., description="本次运行固定的 UDP 源地址")
    source_port: int = Field(..., description="本次运行固定的 UDP 源端口")
    expected_instance: str
    instance_name: Optional[str] = Field(None, description="实际应答的实例名")
    matched: Optional[bool] = Field(None, description="实际实例名是否与预期匹配")
    max_hops: int
    hops: list[HopResult]
    reason: Optional[str] = Field(None, description="终止原因（正常应答时为 null）")
    stray_feedback: int = Field(0, description="迟到/无法对应/引述不完整的反馈数（不改判）")
    icmp_available: bool = Field(..., description="ICMP 接收后端是否可用")
    hop_timeout_ms: int
    started_at: datetime
    finished_at: datetime
    duration_ms: float


# ---------------------------------------------------------------------------
# 反馈后端：真实 socket 实现 + 可注入的测试替身接口
# ---------------------------------------------------------------------------


class FeedbackBackend(Protocol):
    icmp_available: bool

    def send_ttl(self, packet: bytes, ttl: int) -> None: ...

    async def get(self) -> tuple[str, object]: ...

    def close(self) -> None: ...


class _UdpReader(threading.Thread):
    """后台线程阻塞 recvfrom，把 UDP 数据报线程安全地送回事件循环。"""

    # 这些 errno 只在 socket 被关闭时出现，出现即退出线程
    _FATAL_ERRNOS = {errno.EBADF, errno.ENOTSOCK, errno.EINVAL}

    def __init__(
        self,
        sock: socket.socket,
        loop: asyncio.AbstractEventLoop,
        queue: "asyncio.Queue[tuple[str, object]]",
    ) -> None:
        super().__init__(name="trace-udp-reader", daemon=True)
        self._sock = sock
        self._loop = loop
        self._queue = queue
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError as exc:
                if self._stop.is_set() or exc.errno in self._FATAL_ERRNOS:
                    return
                # 未启用 IP_RECVERR 的回退场景下，异步 ICMP 错误可能以
                # ECONNREFUSED 形式在此冒头：忽略并继续，ICMP 归跳由
                # raw 后端负责，绝不能让读线程退出
                continue
            self._loop.call_soon_threadsafe(self._queue.put_nowait, ("udp", (data, addr)))

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


class SocketFeedbackBackend:
    """真实后端：固定源 socket + IP_TTL 递增 + IP_RECVERR/raw ICMP。"""

    def __init__(self, host: str, port: int) -> None:
        self._loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[tuple[str, object]] = asyncio.Queue()
        # 整个运行只 bind/connect 一次 → 固定源地址、固定源端口
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 0))
        sock.connect((host, port))
        sock.setblocking(True)
        self._sock = sock
        self.source_ipv4, self.source_port = sock.getsockname()

        self._reader = _UdpReader(sock, self._loop, self.queue)
        self._reader.start()

        self._icmp: Optional[IcmpReceiver] = open_icmp_receiver(
            sock, self.source_port, port
        )
        self.icmp_available = self._icmp is not None
        if self._icmp is not None:
            self._icmp.start(lambda fb: self.queue.put_nowait(("icmp", fb)))

    def send_ttl(self, packet: bytes, ttl: int) -> None:
        # 每跳发送前设置 TTL；源地址/端口保持不变
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        self._sock.send(packet)

    async def get(self) -> tuple[str, object]:
        return await self.queue.get()

    def close(self) -> None:
        if self._icmp is not None:
            self._icmp.close()
        self._reader.stop()
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 追踪引擎
# ---------------------------------------------------------------------------


class Tracer:
    def __init__(
        self,
        backend_factory: Optional[type[FeedbackBackend]] = None,
        hop_timeout_ms: int = HOP_TIMEOUT_MS,
    ) -> None:
        self._backend_factory = backend_factory or SocketFeedbackBackend
        self._hop_timeout_ms = hop_timeout_ms

    async def trace(
        self,
        req: TraceRequest,
        _trace_id: Optional[uuid.UUID] = None,
    ) -> TraceResult:
        trace_id = _trace_id or uuid.uuid4()
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()
        timeout_s = self._hop_timeout_ms / 1000.0

        backend = self._backend_factory(req.target_ipv4, req.target_port)
        hops: list[HopResult] = []
        stray = 0
        seq = 0
        terminal: Optional[str] = None
        instance_name: Optional[str] = None
        terminal_detail: Optional[str] = None

        def drain_nowait() -> None:
            """排空后端队列里已经就绪的反馈（用于关闭前统计迟到反馈）。"""
            nonlocal stray
            while not backend.queue.empty():  # type: ignore[attr-defined]
                backend.queue.get_nowait()  # type: ignore[attr-defined]
                stray += 1

        try:
            for ttl in range(1, req.max_hops + 1):
                if terminal is not None:
                    break
                seq += 1
                my_seq = seq
                packet = build_trace_packet(trace_id, my_seq)
                t_send = time.monotonic()
                try:
                    backend.send_ttl(packet, ttl)
                except OSError as exc:
                    # 只有真正的发送异常才算发送失败；迟到 ICMP 不算
                    hops.append(
                        HopResult(
                            hop=ttl, ttl=ttl, status="send_error",
                            detail=f"{type(exc).__name__}: {exc}",
                        )
                    )
                    terminal = "send_failed"
                    terminal_detail = f"TTL={ttl} 诊断包发送失败：{exc}"
                    break

                deadline = t_send + timeout_s
                hop_done = False
                while not hop_done:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        # 等满 500ms 无可归属反馈 → 无应答，继续下一 TTL
                        hops.append(HopResult(hop=ttl, ttl=ttl, status="no_response"))
                        hop_done = True
                        break
                    try:
                        kind, obj = await asyncio.wait_for(backend.get(), remaining)
                    except asyncio.TimeoutError:
                        hops.append(HopResult(hop=ttl, ttl=ttl, status="no_response"))
                        hop_done = True
                        break

                    rtt = round((time.monotonic() - t_send) * 1000.0, 3)

                    if kind == "icmp":
                        fb: IcmpFeedback = obj  # type: ignore[assignment]
                        # 不可归属反馈（引述中无完整 MTUP 头）：只能是终止性
                        # 目的不可达，由 socket 层保证来源；不参与逐跳归跳，
                        # 也不按编号/序号拒收
                        if not fb.attributable:
                            if fb.kind is IcmpKind.PORT_UNREACHABLE:
                                hops.append(
                                    HopResult(
                                        hop=ttl, ttl=ttl,
                                        status="port_unreachable",
                                        router=fb.reporter, rtt_ms=rtt,
                                        detail=(
                                            "目标返回 ICMP 端口不可达（引述不含完整 "
                                            "MTUP 头，按 socket 归属为终止信号）"
                                        ),
                                    )
                                )
                                terminal = "port_unreachable"
                                terminal_detail = (
                                    f"{req.target_ipv4}:{req.target_port} 返回 ICMP "
                                    "端口不可达，单独报告并停止追踪"
                                )
                                hop_done = True
                                continue
                            hops.append(
                                HopResult(
                                    hop=ttl, ttl=ttl, status="dest_unreachable",
                                    router=fb.reporter, rtt_ms=rtt,
                                    detail=(
                                        f"ICMP 目的不可达 "
                                        f"(type {fb.icmp_type}/code {fb.icmp_code}，"
                                        "引述不含完整 MTUP 头)"
                                    ),
                                )
                            )
                            terminal = "dest_unreachable"
                            terminal_detail = (
                                f"目标路径返回 ICMP 目的不可达 "
                                f"(type {fb.icmp_type}/code {fb.icmp_code})，停止追踪"
                            )
                            hop_done = True
                            continue

                        # 可归属反馈：编号/序号必须对应；迟到（旧序号）或串运行
                        # 的反馈不改判
                        if fb.session_id != trace_id or fb.seq != my_seq:
                            stray += 1
                            continue
                        if fb.kind is IcmpKind.TTL_EXCEEDED:
                            hops.append(
                                HopResult(
                                    hop=ttl, ttl=ttl, status="router",
                                    router=fb.reporter, rtt_ms=rtt,
                                )
                            )
                            hop_done = True
                        elif fb.kind is IcmpKind.PORT_UNREACHABLE:
                            hops.append(
                                HopResult(
                                    hop=ttl, ttl=ttl, status="port_unreachable",
                                    router=fb.reporter, rtt_ms=rtt,
                                    detail=(
                                        f"目标返回 ICMP 端口不可达 "
                                        f"(type {fb.icmp_type}/code {fb.icmp_code})"
                                    ),
                                )
                            )
                            terminal = "port_unreachable"
                            terminal_detail = (
                                f"{req.target_ipv4}:{req.target_port} 返回 ICMP 端口不可达，"
                                "单独报告并停止追踪"
                            )
                            hop_done = True
                        else:
                            hops.append(
                                HopResult(
                                    hop=ttl, ttl=ttl, status="dest_unreachable",
                                    router=fb.reporter, rtt_ms=rtt,
                                    detail=(
                                        f"ICMP 目的不可达 "
                                        f"(type {fb.icmp_type}/code {fb.icmp_code})"
                                    ),
                                )
                            )
                            terminal = "dest_unreachable"
                            terminal_detail = (
                                f"目标路径返回 ICMP 目的不可达 "
                                f"(type {fb.icmp_type}/code {fb.icmp_code})，停止追踪"
                            )
                            hop_done = True
                        continue

                    # kind == "udp"：回显端数据报
                    data, _addr = obj  # type: ignore[assignment]
                    head = parse_packet(data)
                    if head is None or head.session_id != trace_id or head.seq != my_seq:
                        # 不对应/迟到/残缺回包：拒收，继续等，绝不改判
                        stray += 1
                        continue

                    reply = parse_trace_reply(data)
                    if reply is not None:
                        instance_name = reply.instance_name
                        hops.append(
                            HopResult(
                                hop=ttl, ttl=ttl, status="echo",
                                router=req.target_ipv4,
                                instance_name=instance_name, rtt_ms=rtt,
                            )
                        )
                        terminal = (
                            "reached"
                            if instance_name == req.expected_instance
                            else "mismatch"
                        )
                        terminal_detail = None
                        hop_done = True
                        continue

                    # 合法 MTUP 头但不是 MTRE：旧端原样回包（含 MTTR 原文）
                    if head.size == len(data) and (
                        is_trace_request(data) or len(data) >= HEADER_SIZE
                    ):
                        hops.append(
                            HopResult(
                                hop=ttl, ttl=ttl, status="legacy_echo",
                                router=req.target_ipv4, rtt_ms=rtt,
                                detail="对端原样回送诊断包，未携带实例名（旧回显端）",
                            )
                        )
                        terminal = "instance_unconfirmed"
                        terminal_detail = (
                            "对端原样回包且未返回实例名，应答实例无法确认"
                        )
                        hop_done = True
                        continue

                    stray += 1

            if terminal is None:
                terminal = "max_hops_exceeded"
                terminal_detail = (
                    f"达到最大跳数 {req.max_hops} 仍未收到回显端应答或终止性 ICMP 反馈"
                )

            drain_nowait()
        finally:
            backend.close()

        matched: Optional[bool]
        if terminal in ("reached", "mismatch"):
            matched = terminal == "reached"
        else:
            matched = None

        finished_at = datetime.now(timezone.utc)
        return TraceResult(
            trace_id=str(trace_id),
            status=terminal,
            target_ipv4=req.target_ipv4,
            target_port=req.target_port,
            source_ipv4=backend.source_ipv4,  # type: ignore[attr-defined]
            source_port=backend.source_port,  # type: ignore[attr-defined]
            expected_instance=req.expected_instance,
            instance_name=instance_name,
            matched=matched,
            max_hops=req.max_hops,
            hops=hops,
            reason=terminal_detail,
            stray_feedback=stray,
            icmp_available=backend.icmp_available,
            hop_timeout_ms=self._hop_timeout_ms,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
        )
