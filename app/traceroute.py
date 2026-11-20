"""逐跳诊断：固定源地址/端口，递增 TTL，核对中间路由器与最终回显实例。

需求与实现对应关系：

- **固定 UDP 源地址与端口**：一次诊断只创建一个 UDP socket、绑定一次
  ``(IPv4, port)``，全部跳共用；源地址缺省时先查询出口地址再绑定，源端口缺省
  为随机端口，整个任务保持不变。
- **递增 TTL + 带编号/序号的诊断包**：第 1..max_hops 跳依次设置 ``IP_TTL``，
  每跳发出一个 ``MTPS`` 诊断包（session UUID + seq + hop + nonce）。
- **当次按跳返回 ICMP TTL 超时的路由器地址**：ICMP 通过 ``IP_RECVERR`` 错误队列
  读取（无需 root），路由器地址取 ``sock_extended_err`` 中的 offender。
- **等满 500ms 即弃**：每跳只采信发送后 ``hop_timeout_ms``（默认 500ms）内到达、
  且能归属到本跳的反馈；否则记 ``timeout`` 并继续下一跳。
- **迟到/无法对应不改判**：反馈按引述报文中的 session/seq 归属；引述只包含完整
  MTUP 头也能归跳。迟到反馈计入 ``late_feedback``，无法归属的计入
  ``unmatched_feedback``，既不改判已结束的跳，也不算作新一跳的失败。
- **回显实例**：收到本次 session+seq+nonce 对应、带实例名的 ``MTRP`` 应答即停止，
  返回实际实例名与 ``instance_matched``。旧端原样回显诊断包（回包仍是 MTPS、
  没有实例名）→ ``instance_unconfirmed``；目标返回 ICMP 端口不可达 →
  ``port_unreachable`` 单独报告并停止。
- MTUP 原探测报文仍由回显端原样回显，互不影响。
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Protocol, Literal, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from .netutil import set_ttl

# ---------------------------------------------------------------------------
# 诊断报文格式
# ---------------------------------------------------------------------------

TRACE_MAGIC = b"MTPS"
# | magic 4 | session 16 | seq 4 | hop 4 | nonce 8 | size 4 | padding |
TRACE_HEADER = struct.Struct("!4s16sIIQI")
TRACE_HEADER_SIZE = TRACE_HEADER.size  # 40
DEFAULT_TRACE_SIZE = 128

REPLY_MAGIC = b"MTRP"
# 实例名最长 64 字节，保证应答远小于常见 MTU，不会被 IP 分片
MAX_INSTANCE_NAME_BYTES = 64
# | magic 4 | session 16 | seq 4 | nonce 8 | name_len 1 | name（定长 64B）|
_REPLY_FIXED = struct.Struct("!4s16sIQB")
REPLY_SIZE = _REPLY_FIXED.size + MAX_INSTANCE_NAME_BYTES  # 97


def build_trace_packet(
    session_id: uuid.UUID, seq: int, hop: int, nonce: int, size: int = DEFAULT_TRACE_SIZE
) -> bytes:
    """构造总长恰好为 size 字节的诊断包（size >= 40）。"""
    size = max(size, TRACE_HEADER_SIZE)
    return TRACE_HEADER.pack(
        TRACE_MAGIC, session_id.bytes, seq, hop, nonce, size
    ) + bytes(size - TRACE_HEADER_SIZE)


@dataclass(frozen=True)
class TracePacket:
    session_id: uuid.UUID
    seq: int
    hop: int
    nonce: int
    size: int


def parse_trace_packet(data: bytes) -> TracePacket | None:
    if len(data) < TRACE_HEADER_SIZE:
        return None
    magic, sid, seq, hop, nonce, size = TRACE_HEADER.unpack(data[:TRACE_HEADER_SIZE])
    if magic != TRACE_MAGIC or size != len(data) or size < TRACE_HEADER_SIZE:
        return None
    return TracePacket(uuid.UUID(bytes=sid), seq, hop, nonce, size)


def build_trace_reply(session_id: uuid.UUID, seq: int, nonce: int, name: str) -> bytes:
    raw = name.encode("utf-8")[:MAX_INSTANCE_NAME_BYTES]
    return _REPLY_FIXED.pack(
        REPLY_MAGIC, session_id.bytes, seq, nonce, len(raw)
    ) + raw.ljust(MAX_INSTANCE_NAME_BYTES, b"\x00")


@dataclass(frozen=True)
class TraceReply:
    session_id: uuid.UUID
    seq: int
    nonce: int
    instance_name: str


def parse_trace_reply(data: bytes) -> TraceReply | None:
    if len(data) != REPLY_SIZE:
        return None
    magic, sid, seq, nonce, name_len = _REPLY_FIXED.unpack(data[: _REPLY_FIXED.size])
    if magic != REPLY_MAGIC or name_len > MAX_INSTANCE_NAME_BYTES:
        return None
    try:
        name = data[_REPLY_FIXED.size : _REPLY_FIXED.size + name_len].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return TraceReply(uuid.UUID(bytes=sid), seq, nonce, name)


def embedded_trace_header(data: bytes) -> bytes | None:
    """在 ICMP 引述中找出完整的诊断报文头。

    - 引述可能从 IP 头开始，也可能只剩 UDP 负载，故按 magic 搜索；
    - 只有 40 字节头完整即可归跳，不要求完整负载（"只引述完整 MTUP 头也能归跳"）；
    - 若引述长度已覆盖声明的报文长度，则必须完全一致，避免把拼接/损坏报文当真。
    """
    start = data.find(TRACE_MAGIC)
    if start < 0 or len(data) - start < TRACE_HEADER_SIZE:
        return None
    header = data[start : start + TRACE_HEADER_SIZE]
    _magic, _sid, _seq, _hop, _nonce, size = TRACE_HEADER.unpack(header)
    if size < TRACE_HEADER_SIZE or len(data) - start > size:
        return None
    return header


def parse_embedded_trace(data: bytes) -> TracePacket | None:
    header = embedded_trace_header(data)
    if header is None:
        return None
    _magic, sid, seq, hop, nonce, size = TRACE_HEADER.unpack(header)
    # 引述可能被截断，不要求 size == len(data)
    return TracePacket(uuid.UUID(bytes=sid), seq, hop, nonce, size)


# ---------------------------------------------------------------------------
# ICMP 错误队列（IP_RECVERR）
# ---------------------------------------------------------------------------

IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 8192)
IP_TTL = getattr(socket, "IP_TTL", 2)

ICMP_DEST_UNREACH = 3
ICMP_TIME_EXCEEDED = 11
ICMP_PORT_UNREACH = 3


@dataclass(frozen=True)
class RawError:
    """错误队列中的一条消息。"""

    errno: int
    icmp_type: int
    icmp_code: int
    offender_ip: Optional[str]
    quoted: bytes
    arrival: Optional[float]  # 内核接收时间（epoch 秒）；无时间戳为 None


def decode_error_message(data: bytes, cmsgs) -> RawError:  # noqa: ANN001
    """解析 ``recvmsg(MSG_ERRQUEUE)`` 的负载与辅助数据。"""
    errno = 0
    etype = 0
    ecode = 0
    offender: Optional[str] = None
    arrival: Optional[float] = None
    for level, typ, payload in cmsgs:
        if level == socket.IPPROTO_IP and typ == IP_RECVERR and len(payload) >= 7:
            errno, _origin, etype, ecode = struct.unpack("IBBB", payload[:7])
            # Linux 在 struct sock_extended_err（16 字节）之后紧跟 offender 的 sockaddr_in
            # sa_family 为本地字节序；后续字段按网络字节序
            if len(payload) >= 32 and struct.unpack("=H", payload[16:18])[0] == socket.AF_INET:
                offender = socket.inet_ntoa(payload[20:24])
        elif level == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS and len(payload) >= 16:
            sec, nsec = struct.unpack("qq", payload[:16])
            arrival = sec + nsec / 1e9
    return RawError(errno, etype, ecode, offender, data, arrival)


@dataclass(frozen=True)
class Feedback:
    """已解析、待归属的反馈。"""

    kind: Literal["ttl_exceeded", "port_unreachable", "unreachable", "error"]
    router_ip: Optional[str]
    seq: Optional[int]  # 引述里完整 MTUP 头中的 seq；没有完整头时为 None
    arrival: Optional[float]
    detail: Optional[str]
    ours: bool  # 引述属于本诊断会话


def analyze_error(raw: RawError, session_id: uuid.UUID) -> Feedback:
    embedded = parse_embedded_trace(raw.quoted)
    ours = embedded is not None and embedded.session_id == session_id
    if raw.icmp_type == ICMP_TIME_EXCEEDED:
        kind: Literal["ttl_exceeded", "port_unreachable", "unreachable", "error"] = (
            "ttl_exceeded"
        )
        detail = None
    elif raw.icmp_type == ICMP_DEST_UNREACH and raw.icmp_code == ICMP_PORT_UNREACH:
        kind, detail = "port_unreachable", "ICMP 端口不可达"
    elif raw.icmp_type == ICMP_DEST_UNREACH:
        kind, detail = "unreachable", f"ICMP 目的不可达（code {raw.icmp_code}）"
    else:
        kind = "error"
        detail = (
            os.strerror(raw.errno) if raw.errno else f"ICMP type {raw.icmp_type}"
        )
    return Feedback(
        kind=kind,
        router_ip=raw.offender_ip,
        seq=None if embedded is None else embedded.seq,
        arrival=raw.arrival,
        detail=detail,
        ours=ours,
    )


Attribution = Literal["current", "late", "unmatched"]


def attribute_feedback(
    fb: Feedback,
    *,
    seq: int,
    sent_wall: float,
    error_deadline_wall: float,
) -> Attribution:
    """判断 ICMP 反馈是否属于当前这一跳的发送。

    - 引述带 seq：按 seq 归属；seq 更小 = 上一跳的迟到反馈，seq 更大 = 无法对应；
    - 没有完整 MTUP 头：只能用内核接收时间判断是否落在本跳窗口内；
      若此前已有跳超时，迟到反馈可能在当前窗口才被读取，无法安全归属，一律不采信；
    - 越过本跳截止时间的一律算迟到：不改判、不记到下一跳。
    """
    if not fb.ours:
        return "unmatched"
    if fb.arrival is not None and (
        fb.arrival > error_deadline_wall or fb.arrival < sent_wall - 0.05
    ):
        # 到达时间落在本跳窗口之外：迟到反馈，不能改判任何一跳
        return "late"
    if fb.seq is not None:
        if fb.seq != seq:
            return "late" if fb.seq < seq else "unmatched"
        return "current"
    if fb.arrival is None:
        return "unmatched"
    return "current"


# ---------------------------------------------------------------------------
# 传输层（真实 socket / 测试替身共用）
# ---------------------------------------------------------------------------


@runtime_checkable
class Transport(Protocol):
    recverr: bool
    source_ip: str
    source_port: int

    def set_ttl(self, ttl: int) -> bool: ...

    def send(self, payload: bytes) -> None: ...

    def drain(self) -> tuple[list[RawError], list[tuple[bytes, Optional[float]]]]: ...

    async def wait(self, timeout: float) -> None: ...

    def close(self) -> None: ...


class UdpTransport:
    """固定源地址/端口的 UDP socket，读取 ICMP 错误队列与普通回包。"""

    def __init__(self, source_ip: str, source_port: int, target: str, target_port: int) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._loop = asyncio.get_running_loop()
        self._event = asyncio.Event()
        self.recverr = False
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self._sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
                self.recverr = True
            except OSError:
                pass
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            except OSError:
                pass
            self._sock.bind((source_ip, source_port))
            self._sock.setblocking(False)
            self._sock.connect((target, target_port))
        except BaseException:
            self._sock.close()
            raise
        self.source_ip, self.source_port = self._sock.getsockname()
        self._loop.add_reader(self._sock.fileno(), self._event.set)

    def set_ttl(self, ttl: int) -> bool:
        return set_ttl(self._sock, ttl)

    def send(self, payload: bytes) -> None:
        self._sock.send(payload)

    def drain(self) -> tuple[list[RawError], list[tuple[bytes, Optional[float]]]]:
        errors: list[RawError] = []
        while True:
            try:
                data, cmsgs, _flags, _addr = self._sock.recvmsg(
                    65535, 4096, MSG_ERRQUEUE
                )
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            errors.append(decode_error_message(data, cmsgs))
        datagrams: list[tuple[bytes, Optional[float]]] = []
        while True:
            try:
                data, cmsgs, _flags, _addr = self._sock.recvmsg(65535, 4096)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            arrival: Optional[float] = None
            for level, typ, payload in cmsgs:
                if level == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS and len(payload) >= 16:
                    sec, nsec = struct.unpack("qq", payload[:16])
                    arrival = sec + nsec / 1e9
            datagrams.append((data, arrival))
        return errors, datagrams

    async def wait(self, timeout: float) -> None:
        if timeout <= 0:
            return
        try:
            await asyncio.wait_for(self._event.wait(), timeout)
        except asyncio.TimeoutError:
            pass
        finally:
            self._event.clear()

    def close(self) -> None:
        try:
            self._loop.remove_reader(self._sock.fileno())
        except (OSError, ValueError):
            pass
        self._sock.close()


def discover_source_ip(target: str, port: int) -> Optional[str]:
    """查询内核对目标实际选用的出口地址（不发送任何报文）。"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((target, port))
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


# ---------------------------------------------------------------------------
# API 模型
# ---------------------------------------------------------------------------

MIN_HOPS = 1
MAX_HOPS = 16


class TraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_host: IPvAnyAddress = Field(..., description="目标 IPv4 地址")
    target_port: int = Field(..., ge=1, le=65535, description="目标 UDP 端口")
    expected_instance: Optional[str] = Field(
        None,
        max_length=MAX_INSTANCE_NAME_BYTES,
        description="预期回显实例名；留空则只报告实际实例名，不判定匹配",
    )
    max_hops: int = Field(8, ge=MIN_HOPS, le=MAX_HOPS, description="最大跳数（1～16）")
    hop_timeout_ms: int = Field(
        500, ge=50, le=5000, description="每跳等待可归属反馈的窗口（毫秒，默认 500）"
    )
    reply_timeout_ms: int = Field(
        1000, ge=50, le=10000, description="最后一跳等待实例应答的额外窗口（毫秒）"
    )
    source_host: Optional[IPvAnyAddress] = Field(
        None, description="固定 UDP 源地址；留空自动探测出口地址（整个任务固定）"
    )
    source_port: Optional[int] = Field(
        None, ge=1, le=65535, description="固定 UDP 源端口；留空为随机端口（整个任务固定）"
    )


class HopOut(BaseModel):
    hop: int
    status: Literal[
        "ttl_exceeded", "reply", "port_unreachable", "timeout", "send_error"
    ]
    router_ip: Optional[str] = Field(None, description="当次 ICMP TTL 超时的路由器地址")
    rtt_ms: Optional[float] = None
    detail: Optional[str] = None


TraceStatus = Literal[
    "reply", "instance_unconfirmed", "port_unreachable", "no_reply", "error"
]


class TraceResult(BaseModel):
    trace_id: str
    status: TraceStatus
    target: str
    expected_instance: Optional[str]
    max_hops: int
    source: str = Field(..., description="本次固定的 UDP 源地址:端口")
    hops: list[HopOut]
    instance_name: Optional[str] = Field(
        None, description="回显应答中的实际实例名；旧端原样回包等无法确认时为 null"
    )
    instance_matched: Optional[bool] = Field(
        None, description="实际实例名是否与预期一致；预期或实际缺失时为 null"
    )
    reached: bool = Field(False, description="是否收到目标回显端的应答")
    reason: Optional[str] = None
    late_feedback: int = Field(0, description="迟到、未采信的反馈数")
    unmatched_feedback: int = Field(0, description="无法归属到本任务的反馈数")
    icmp_error_queue: bool = Field(
        ..., description="是否成功启用 IP_RECVERR；否则无法接收 ICMP TTL 超时"
    )
    started_at: datetime
    finished_at: datetime
    duration_ms: float


# ---------------------------------------------------------------------------
# 诊断引擎
# ---------------------------------------------------------------------------


class TraceRunner:
    """逐跳诊断引擎。

    ``transport_factory(target_ip, target_port) -> Transport`` 用于测试注入；
    生产环境使用固定源地址/端口的 :class:`UdpTransport`。
    """

    def __init__(self, transport_factory=None) -> None:  # noqa: ANN001
        self._factory = transport_factory

    async def run(self, req: TraceRequest) -> TraceResult:
        target_ip = str(req.target_host)
        trace_id = uuid.uuid4()
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()

        source_ip = str(req.source_host) if req.source_host is not None else None
        if source_ip is None:
            source_ip = discover_source_ip(target_ip, req.target_port) or "0.0.0.0"

        try:
            if self._factory is not None:
                transport: Transport = self._factory(target_ip, req.target_port)
            else:
                transport = UdpTransport(
                    source_ip, req.source_port or 0, target_ip, req.target_port
                )
        except OSError as exc:
            raise OSError(
                f"无法绑定源 {source_ip}:{req.source_port or 0} 或连接目标 "
                f"{target_ip}:{req.target_port}: {exc}"
            ) from exc

        try:
            outcome = await self._trace(req, trace_id, target_ip, transport)
        finally:
            transport.close()

        finished_at = datetime.now(timezone.utc)
        return TraceResult(
            trace_id=str(trace_id),
            status=outcome.status,
            target=f"{target_ip}:{req.target_port}",
            expected_instance=req.expected_instance,
            max_hops=req.max_hops,
            source=outcome.source,
            hops=outcome.hops,
            instance_name=outcome.instance_name,
            instance_matched=outcome.instance_matched,
            reached=outcome.reached,
            reason=outcome.reason,
            late_feedback=outcome.late,
            unmatched_feedback=outcome.unmatched,
            icmp_error_queue=transport.recverr,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
        )

    async def _trace(
        self,
        req: TraceRequest,
        trace_id: uuid.UUID,
        target_ip: str,
        transport: Transport,
    ) -> "_Outcome":
        hops: list[HopOut] = []
        status: TraceStatus = "no_reply"
        reason: Optional[str] = None
        instance_name: Optional[str] = None
        instance_matched: Optional[bool] = None
        reached = False
        late = 0
        unmatched = 0
        stale_possible = False
        seq = 0

        # 发送前清空队列：之前残留的反馈不属于任何一跳
        old_errors, old_datagrams = transport.drain()
        unmatched += len(old_errors)
        unmatched += sum(1 for data, _arr in old_datagrams if parse_trace_packet(data)
                         or parse_trace_reply(data))

        for hop in range(1, req.max_hops + 1):
            if not transport.set_ttl(hop):
                hops.append(
                    HopOut(hop=hop, status="send_error", detail="无法设置 IP_TTL")
                )
                status = "error"
                reason = "本机不支持设置 IP_TTL，无法按跳探测"
                break

            seq += 1
            nonce = uuid.uuid4().int & 0xFFFFFFFFFFFFFFFF
            payload = build_trace_packet(trace_id, seq, hop, nonce)
            sent_wall = time.time()
            sent_mono = time.monotonic()
            if hop == req.max_hops:
                wait_seconds = max(
                    req.hop_timeout_ms, req.reply_timeout_ms
                ) / 1000.0
            else:
                wait_seconds = req.hop_timeout_ms / 1000.0
            try:
                transport.send(payload)
            except OSError as exc:
                hops.append(
                    HopOut(
                        hop=hop,
                        status="send_error",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
                )
                status = "error"
                reason = f"第 {hop} 跳发送失败: {exc}"
                break

            hop_deadline_wall = sent_wall + req.hop_timeout_ms / 1000.0
            wait_deadline = sent_mono + wait_seconds

            feedback: Optional[Feedback] = None
            replied = False
            raw_echo = False
            reply_at: Optional[float] = None

            while True:
                errors, datagrams = transport.drain()
                now = time.monotonic()

                for raw in errors:
                    fb = analyze_error(raw, trace_id)
                    where = attribute_feedback(
                        fb,
                        seq=seq,
                        sent_wall=sent_wall,
                        error_deadline_wall=hop_deadline_wall,
                    )
                    if where == "unmatched":
                        unmatched += 1
                        continue
                    # 无完整 MTUP 头时，若此前已有跳超时，迟到反馈可能在当前
                    # 窗口才被读取，无法安全归属，不采信也不改判。
                    if (
                        where == "current"
                        and fb.seq is None
                        and stale_possible
                    ):
                        unmatched += 1
                        continue
                    if where == "late":
                        late += 1
                        continue
                    if feedback is None:
                        feedback = fb

                for data, arrival in datagrams:
                    parsed = parse_trace_packet(data)
                    if parsed is not None:
                        if parsed.session_id == trace_id and parsed.seq == seq:
                            # 旧端原样回包：没有实例名
                            raw_echo = True
                        elif parsed.session_id == trace_id and parsed.seq < seq:
                            late += 1  # 上一跳的迟到回包
                        else:
                            unmatched += 1
                        continue
                    reply = parse_trace_reply(data)
                    if reply is not None:
                        if (
                            reply.session_id == trace_id
                            and reply.seq == seq
                            and reply.nonce == nonce
                        ):
                            reply_deadline_wall = sent_wall + wait_seconds
                            if arrival is not None and arrival > reply_deadline_wall:
                                late += 1
                                continue
                            instance_name = reply.instance_name
                            replied = True
                            reply_at = arrival if arrival is not None else time.time()
                        elif reply.session_id == trace_id and reply.seq < seq:
                            late += 1
                        else:
                            unmatched += 1
                        continue
                    unmatched += 1

                if replied or raw_echo or feedback is not None:
                    break
                if now >= wait_deadline:
                    break
                await transport.wait(wait_deadline - now)

            if replied:
                arrived = reply_at if reply_at is not None else time.time()
                rtt_ms = round((arrived - sent_wall) * 1000.0, 3)
                hops.append(
                    HopOut(hop=hop, status="reply", router_ip=target_ip, rtt_ms=rtt_ms)
                )
                reached = True
                status = "reply"
                instance_matched = (
                    None
                    if req.expected_instance is None
                    else instance_name == req.expected_instance
                )
                if req.expected_instance is not None and not instance_matched:
                    reason = (
                        f"实际回显实例为 {instance_name!r}，"
                        f"与预期 {req.expected_instance!r} 不匹配"
                    )
                break

            if raw_echo:
                hops.append(
                    HopOut(
                        hop=hop,
                        status="reply",
                        router_ip=target_ip,
                        rtt_ms=round((time.monotonic() - sent_mono) * 1000.0, 3),
                    )
                )
                reached = True
                status = "instance_unconfirmed"
                reason = "收到旧端的原样回显，应答中没有实例名，无法确认回显实例"
                break

            if feedback is not None:
                rtt_ms = _feedback_rtt(feedback, sent_wall, sent_mono)
                if feedback.kind == "ttl_exceeded":
                    hops.append(
                        HopOut(
                            hop=hop,
                            status="ttl_exceeded",
                            router_ip=feedback.router_ip,
                            rtt_ms=rtt_ms,
                        )
                    )
                    continue
                if feedback.kind == "port_unreachable":
                    hops.append(
                        HopOut(
                            hop=hop,
                            status="port_unreachable",
                            router_ip=feedback.router_ip,
                            rtt_ms=rtt_ms,
                            detail=feedback.detail,
                        )
                    )
                    status = "port_unreachable"
                    reason = (
                        f"{feedback.router_ip or target_ip} 返回 ICMP 端口不可达，"
                        f"目标 {target_ip}:{req.target_port} 没有回显实例在监听"
                    )
                    break
                hops.append(
                    HopOut(
                        hop=hop,
                        status="send_error",
                        router_ip=feedback.router_ip,
                        detail=feedback.detail,
                    )
                )
                status = "error"
                reason = f"第 {hop} 跳收到不可用反馈: {feedback.detail}"
                break

            # 等满窗口仍无可归属反馈：本跳无应答，继续下一跳
            hops.append(HopOut(hop=hop, status="timeout"))
            # 之后到达的无完整 MTUP 头反馈无法安全归属，一律只计数
            stale_possible = True

        if status == "no_reply":
            reason = f"在 {req.max_hops} 跳内未收到目标回显实例的应答"
            if not transport.recverr:
                reason += "；本机不支持 IP_RECVERR，无法接收 ICMP TTL 超时"

        return _Outcome(
            hops=hops,
            status=status,
            reason=reason,
            instance_name=instance_name,
            instance_matched=instance_matched,
            reached=reached,
            late=late,
            unmatched=unmatched,
            source=_transport_source(transport),
        )


def _feedback_rtt(fb: Feedback, sent_wall: float, sent_mono: float) -> Optional[float]:
    if fb.arrival is not None:
        return round((fb.arrival - sent_wall) * 1000.0, 3)
    return round((time.monotonic() - sent_mono) * 1000.0, 3)


def _transport_source(transport: Transport) -> str:
    ip = getattr(transport, "source_ip", "0.0.0.0")
    port = getattr(transport, "source_port", 0)
    return f"{ip}:{port}"


@dataclass
class _Outcome:
    hops: list[HopOut]
    status: TraceStatus
    reason: Optional[str]
    instance_name: Optional[str]
    instance_matched: Optional[bool]
    reached: bool
    late: int
    unmatched: int
    source: str
