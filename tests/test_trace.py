"""逐跳诊断测试：报文编解码、归属规则、固定源、回显实例语义。

网络相关的用例全部使用注入的假 Transport（``TraceRunner(transport_factory=...)``），
可在无 root、无网络特权的环境稳定运行；真实 socket 的行为另有端到端用例。
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import pytest

from app.traceroute import (
    REPLY_SIZE,
    TRACE_HEADER_SIZE,
    Feedback,
    RawError,
    TraceRequest,
    TraceRunner,
    analyze_error,
    attribute_feedback,
    build_trace_packet,
    build_trace_reply,
    parse_embedded_trace,
    parse_trace_packet,
    parse_trace_reply,
)

SID = uuid.uuid4()


# ---------------------------------------------------------------------------
# 报文
# ---------------------------------------------------------------------------


class TestCodec:
    def test_trace_packet_roundtrip_and_header_only(self):
        data = build_trace_packet(SID, 3, 2, 0xDEADBEEF, size=64)
        pkt = parse_trace_packet(data)
        assert pkt is not None
        assert (pkt.session_id, pkt.seq, pkt.hop, pkt.nonce, pkt.size) == (
            SID, 3, 2, 0xDEADBEEF, 64,
        )
        # ICMP 只引述完整 MTUP 头（40 字节）也能解析
        header_only = parse_embedded_trace(data[:TRACE_HEADER_SIZE])
        assert header_only is not None and header_only.seq == 3
        assert parse_embedded_trace(data[: TRACE_HEADER_SIZE - 1]) is None

    def test_trace_packet_rejects_bad_size(self):
        data = bytearray(build_trace_packet(SID, 1, 1, 1, size=64))
        data[-1] = 0
        assert parse_trace_packet(bytes(data[:-1])) is None  # 长度不自洽

    def test_reply_roundtrip(self):
        reply = build_trace_reply(SID, 7, 42, "echo-a")
        assert len(reply) == REPLY_SIZE
        assert len(reply) < 512  # 保证不会被分片
        parsed = parse_trace_reply(reply)
        assert parsed is not None
        assert (parsed.session_id, parsed.seq, parsed.nonce, parsed.instance_name) == (
            SID, 7, 42, "echo-a",
        )

    def test_reply_rejects_garbage_and_long_names(self):
        assert parse_trace_reply(b"") is None
        assert parse_trace_reply(b"MTRP" + b"\x00" * 200) is None
        long_name = "x" * 64
        reply = build_trace_reply(SID, 1, 1, long_name)
        assert parse_trace_reply(reply).instance_name == long_name  # 截断到 64 字节仍可解析


# ---------------------------------------------------------------------------
# ICMP 反馈归属
# ---------------------------------------------------------------------------


def _raw(seq: int, *, arrival: Optional[float], ip: str = "10.0.0.1", icmp_type: int = 11,
         code: int = 0, session: uuid.UUID = SID, header_only: bool = True) -> RawError:
    data = build_trace_packet(session, seq, seq, 1, size=128)
    quoted = data[:TRACE_HEADER_SIZE] if header_only else data
    return RawError(110, icmp_type, code, ip, quoted, arrival)


class TestAttribution:
    def test_header_only_feedback_attributed_to_hop(self):
        now = time.time()
        fb = analyze_error(_raw(2, arrival=now - 0.01), SID)
        assert fb.kind == "ttl_exceeded" and fb.seq == 2 and fb.ours
        assert fb.router_ip == "10.0.0.1"
        assert (
            attribute_feedback(fb, seq=2, sent_wall=now - 0.5, error_deadline_wall=now)
            == "current"
        )

    def test_late_feedback_is_not_attributed_to_new_hop(self):
        now = time.time()
        # 第 1 跳的反馈在第 2 跳窗口里才被读到：只能算迟到
        fb = analyze_error(_raw(1, arrival=now - 0.01), SID)
        assert (
            attribute_feedback(fb, seq=2, sent_wall=now - 0.2, error_deadline_wall=now)
            == "late"
        )
        # 内核时间戳已超出本跳窗口
        stale = analyze_error(_raw(2, arrival=now - 2.0), SID)
        assert (
            attribute_feedback(stale, seq=2, sent_wall=now - 0.1, error_deadline_wall=now)
            == "late"
        )

    def test_other_session_and_future_seq_unmatched(self):
        now = time.time()
        other = analyze_error(_raw(2, arrival=now, session=uuid.uuid4()), SID)
        assert not other.ours
        assert (
            attribute_feedback(other, seq=2, sent_wall=now - 1, error_deadline_wall=now + 1)
            == "unmatched"
        )
        future = analyze_error(_raw(9, arrival=now), SID)
        assert (
            attribute_feedback(future, seq=2, sent_wall=now - 1, error_deadline_wall=now + 1)
            == "unmatched"
        )

    def test_no_embedded_header_cannot_be_attributed(self):
        now = time.time()
        raw = RawError(110, 11, 0, "10.0.0.1", b"garbage-quote", None)
        fb = analyze_error(raw, SID)
        assert fb.seq is None
        assert (
            attribute_feedback(fb, seq=2, sent_wall=now - 0.1, error_deadline_wall=now)
            == "unmatched"
        )
        # 有时间戳且落在窗口内才按时间归属
        timed = Feedback("ttl_exceeded", "10.0.0.1", None, now - 0.05, None, True)
        assert (
            attribute_feedback(timed, seq=2, sent_wall=now - 0.1, error_deadline_wall=now)
            == "current"
        )

    def test_port_unreachable_detected(self):
        now = time.time()
        fb = analyze_error(_raw(3, arrival=now, icmp_type=3, code=3), SID)
        assert fb.kind == "port_unreachable"


# ---------------------------------------------------------------------------
# 假 Transport：可编排每跳的反馈与迟到/无关反馈
# ---------------------------------------------------------------------------


@dataclass
class _FakeTransport:
    """按发送顺序回放脚本化事件。

    ``script[hop]`` 为发送该跳后应立即产生的错误/数据报列表。
    ``pending_late`` 为在下一跳才被读取的反馈，用于验证迟到不改判。
    """

    script: dict[int, list[tuple[str, object]]] = field(default_factory=dict)
    pending_late: list[tuple[str, object]] = field(default_factory=list)
    send_errors: dict[int, OSError] = field(default_factory=dict)
    src_ip: str = "172.30.0.9"
    src_port: int = 40000
    recverr: bool = True
    events: list[tuple[str, object]] = field(default_factory=list)
    sent: list[bytes] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)
    hop: int = 0
    closed: bool = False

    @property
    def source_ip(self) -> str:
        return self.src_ip

    @property
    def source_port(self) -> int:
        return self.src_port

    def set_ttl(self, ttl: int) -> bool:
        self.ttls.append(ttl)
        return True

    def send(self, payload: bytes) -> None:
        self.hop += 1
        self.sent.append(payload)
        exc = self.send_errors.get(self.hop)
        if exc is not None:
            raise exc
        self.events = list(self.script.get(self.hop, []))
        self.events.extend(self.pending_late)
        self.pending_late = []

    def drain(self):
        errors = [obj for kind, obj in self.events if kind == "error"]
        datagrams = [obj for kind, obj in self.events if kind == "data"]
        self.events = []
        return errors, datagrams

    async def wait(self, timeout: float) -> None:
        await asyncio.sleep(min(timeout, 0.01))

    def close(self) -> None:
        self.closed = True


def _run(fake: _FakeTransport, **kw) -> object:
    kw.setdefault("target_host", "192.0.2.10")
    kw.setdefault("target_port", 9999)
    kw.setdefault("max_hops", 4)
    kw.setdefault("hop_timeout_ms", 100)
    kw.setdefault("source_host", "172.30.0.9")
    req = TraceRequest(**kw)
    runner = TraceRunner(transport_factory=lambda target, port: fake)
    return asyncio.run(runner.run(req))


def _err(seq: int, ip: str, *, arrival: Optional[float] = None, icmp_type: int = 11,
         code: int = 0, session: uuid.UUID = SID, header_only: bool = True) -> tuple[str, object]:
    return (
        "error",
        _raw(
            seq, arrival=arrival, ip=ip, icmp_type=icmp_type, code=code,
            session=session, header_only=header_only,
        ),
    )


def _err_for(session: uuid.UUID, seq: int, ip: str, **kw) -> tuple[str, object]:
    kw.setdefault("arrival", time.time())
    return _err(seq, ip, session=session, **kw)


class _RunnerWithSession:
    """把 TraceRunner 生成的 session 暴露给脚本，便于构造回包。"""

    def __init__(self) -> None:
        self.fake = _FakeTransport()
        self.trace_id: Optional[uuid.UUID] = None

    def __call__(self, target: str, port: int) -> _FakeTransport:
        return self.fake

    async def wrap(self, req: TraceRequest):
        runner = TraceRunner(transport_factory=self)
        real_run = runner.run

        # 从第一个发出的报文取 session
        async def run(req_: TraceRequest):
            return await real_run(req_)

        return await run(req)


# ---------------------------------------------------------------------------
# 场景：中间跳、无应答继续、无效反馈、回显实例
# ---------------------------------------------------------------------------


class TestTraceScenarios:
    def _make(self):
        fake = _FakeTransport()
        holder = {}

        def factory(target, port):
            return fake

        return fake, holder, factory

    def _run(self, fake, factory, **kw):
        kw.setdefault("target_host", "192.0.2.10")
        kw.setdefault("target_port", 9999)
        kw.setdefault("max_hops", 4)
        kw.setdefault("hop_timeout_ms", 100)
        kw.setdefault("source_host", "172.30.0.9")
        req = TraceRequest(**kw)
        return asyncio.run(TraceRunner(transport_factory=factory).run(req))

    def test_middle_hops_then_reply_matched(self):
        fake, _, factory = self._make()

        # 回包必须带本次 session/seq/nonce，先让第 3 跳"收到"某个应答：
        # 这里用一个小技巧——在第 3 跳发送时根据其负载构造应答。
        original_send = fake.send

        def send(payload):
            original_send(payload)
            pkt = parse_trace_packet(payload)
            if fake.hop == 1:
                fake.events = [_err_for(pkt.session_id, 1, "172.30.0.1")]
            elif fake.hop == 2:
                fake.events = [_err_for(pkt.session_id, 2, "10.1.0.1")]
            elif fake.hop == 3:
                fake.events = [
                    _err_for(pkt.session_id, 3, "10.2.0.1"),
                    ("data", (build_trace_reply(pkt.session_id, pkt.seq, pkt.nonce, "echo-a"), None)),
                ]

        fake.send = send
        res = self._run(fake, factory, expected_instance="echo-a")
        assert [h.status for h in res.hops] == ["ttl_exceeded", "ttl_exceeded", "reply"]
        assert [h.router_ip for h in res.hops[:2]] == ["172.30.0.1", "10.1.0.1"]
        assert res.instance_name == "echo-a"
        assert res.instance_matched is True
        assert res.status == "reply" and res.reached
        # 固定源：所有发送共用同一个（假）socket，源地址端口保持不变
        assert res.source == "172.30.0.9:40000"
        assert len(fake.sent) == 3

    def test_mismatched_instance_reported(self):
        fake, _, factory = self._make()
        original_send = fake.send

        def send(payload):
            original_send(payload)
            pkt = parse_trace_packet(payload)
            if fake.hop == 1:
                fake.events = [_err_for(pkt.session_id, 1, "172.30.0.1")]
            elif fake.hop == 2:
                fake.events = [
                    ("data", (build_trace_reply(pkt.session_id, pkt.seq, pkt.nonce, "echo-b"), None)),
                ]

        fake.send = send
        res = self._run(fake, factory, expected_instance="echo-a")
        assert res.status == "reply"
        assert res.instance_name == "echo-b"
        assert res.instance_matched is False
        assert "不匹配" in res.reason

    def test_no_feedback_times_out_each_hop_and_continues(self):
        fake, _, factory = self._make()
        res = self._run(fake, factory, max_hops=3)
        assert [h.status for h in res.hops] == ["timeout", "timeout", "timeout"]
        assert res.status == "no_reply" and not res.reached
        # 每个无应答的跳仍然继续发送下一跳
        assert len(fake.sent) == 3
        assert fake.ttls == [1, 2, 3]

    def test_late_feedback_from_previous_hop_does_not_fail_new_hop(self):
        fake, _, factory = self._make()
        original_send = fake.send

        def send(payload):
            original_send(payload)
            pkt = parse_trace_packet(payload)
            if fake.hop == 2:
                # 第 2 跳窗口里读到第 1 跳的 TTL 超时（迟到，无内核时间戳）
                fake.events = [_err(1, "172.30.0.1", session=pkt.session_id, arrival=None)]

        fake.send = send
        res = self._run(fake, factory, max_hops=3)
        assert [h.status for h in res.hops] == ["timeout", "timeout", "timeout"]
        assert res.late_feedback == 1
        assert res.unmatched_feedback == 0

    def test_unrelated_feedback_counted_not_attributed(self):
        fake, _, factory = self._make()
        fake.script = {
            1: [
                _err(1, "10.0.0.1", session=uuid.uuid4()),  # 别的探测会话
                _err(1, "10.0.0.2", header_only=False),  # 找不到完整 MTUP 头且无时间戳
            ]
        }
        res = self._run(fake, factory, max_hops=2)
        assert [h.status for h in res.hops] == ["timeout", "timeout"]
        assert res.unmatched_feedback == 2

    def test_legacy_raw_echo_reports_unconfirmed_instance(self):
        fake, _, factory = self._make()
        original_send = fake.send

        def send(payload):
            original_send(payload)
            pkt = parse_trace_packet(payload)
            if fake.hop == 1:
                fake.events = [_err_for(pkt.session_id, 1, "172.30.0.1")]
            elif fake.hop == 2:
                fake.events = [("data", (payload, None))]  # 旧端原样回包

        fake.send = send
        res = self._run(fake, factory, expected_instance="echo-a")
        assert res.status == "instance_unconfirmed"
        assert res.instance_name is None and res.instance_matched is None
        assert res.reached is True
        assert "无法确认" in res.reason

    def test_port_unreachable_reported_and_stops(self):
        fake, _, factory = self._make()
        original_send = fake.send

        def send(payload):
            original_send(payload)
            pkt = parse_trace_packet(payload)
            if fake.hop == 1:
                fake.events = [_err_for(pkt.session_id, 1, "172.30.0.1")]
            elif fake.hop == 2:
                fake.events = [
                    _err_for(pkt.session_id, 2, "192.0.2.99", icmp_type=3, code=3),
                ]

        fake.send = send
        res = self._run(fake, factory, max_hops=6)
        assert res.status == "port_unreachable"
        assert [h.status for h in res.hops][-1] == "port_unreachable"
        assert res.hops[-1].router_ip == "192.0.2.99"
        assert res.instance_name is None
        # 停止：只发送了 2 跳
        assert len(fake.sent) == 2

    def test_stray_reply_from_previous_hop_not_matched(self):
        fake, _, factory = self._make()
        original_send = fake.send
        state = {"first": None}

        def send(payload):
            original_send(payload)
            pkt = parse_trace_packet(payload)
            if fake.hop == 1:
                state["first"] = pkt
            elif fake.hop == 2:
                fake.events = [
                    ("data", (build_trace_reply(state["first"].session_id, state["first"].seq,
                                                state["first"].nonce, "echo-a"), None)),
                ]

        fake.send = send
        res = self._run(fake, factory, max_hops=2)
        assert [h.status for h in res.hops] == ["timeout", "timeout"]
        assert res.late_feedback == 1
        assert res.instance_name is None

    def test_send_error_stops_with_error_status(self):
        fake, _, factory = self._make()
        fake.send_errors = {1: OSError(101, "Network is unreachable")}
        res = self._run(fake, factory, max_hops=4)
        assert res.status == "error"
        assert res.hops[0].status == "send_error"
        assert len(fake.sent) == 1
        assert fake.closed


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------


class TestRequestValidation:
    @pytest.mark.parametrize(
        "bad",
        [
            {"target_host": "192.0.2.10", "target_port": 9999, "max_hops": 0},
            {"target_host": "192.0.2.10", "target_port": 9999, "max_hops": 17},
            {"target_host": "192.0.2.10", "target_port": 0},
            {"target_host": "192.0.2.10", "target_port": 70000},
            {"target_host": "not-an-ip", "target_port": 9999},
            {"target_host": "192.0.2.10", "target_port": 9999, "expected_instance": "x" * 65},
            {"target_host": "192.0.2.10", "target_port": 9999, "extra": 1},
        ],
    )
    def test_rejects_bad_input(self, bad):
        with pytest.raises(Exception):
            TraceRequest(**bad)

    def test_max_hops_bounds_accepted(self):
        assert TraceRequest(target_host="192.0.2.10", target_port=9999, max_hops=1)
        assert TraceRequest(target_host="192.0.2.10", target_port=9999, max_hops=16)


# ---------------------------------------------------------------------------
# 固定源 / 端口复用
# ---------------------------------------------------------------------------


class TestDefaultSourceDiscovery:
    def test_discover_source_ip_returns_loopback_for_loopback_target(self):
        from app.traceroute import discover_source_ip

        assert discover_source_ip("127.0.0.1", 9999) == "127.0.0.1"

    def test_fake_transport_reports_its_fixed_source(self):
        fake = _FakeTransport(src_ip="172.30.0.9", src_port=41000)
        factory = lambda target, port: fake  # noqa: E731
        res = TestTraceScenarios()._run(fake, factory, max_hops=1)
        assert res.source == "172.30.0.9:41000"
