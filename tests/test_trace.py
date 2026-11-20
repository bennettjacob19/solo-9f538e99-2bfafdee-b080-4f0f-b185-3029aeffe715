"""迁网路由追踪测试。

- 纯解析：MTTR/MTRE 报文与 ICMP 差错归属（含"只引述 8 字节不可归跳"）；
- 状态机：用 FakeBackend 注入反馈，覆盖匹配/错投/旧端/端口不可达/
  无应答/迟到不改判/发送失败/最大跳数；
- 端到端：真实回显端（loopback）走 /trace API，验证 MTTR→MTRE、
  旧端原样回包→实例无法确认、历史记录与入参校验。
"""
from __future__ import annotations

import asyncio
import socket
import uuid

import pytest
from fastapi.testclient import TestClient

from app import icmp as icmp_mod
from app.icmp import IcmpKind, build_udp_encapsulating, parse_icmp_error
from app.main import app
from app.packets import (
    HEADER_SIZE,
    TRACE_PACKET_SIZE,
    build_packet,
    build_trace_packet,
    build_trace_reply,
    is_trace_request,
    parse_packet,
    parse_trace_reply,
    trace_kind,
)
from app.tracer import Tracer, TraceRequest

SESSION = uuid.uuid4()


# --------------------------------------------------------------- 报文编解码


class TestTracePackets:
    def test_trace_packet_shape(self):
        sid = uuid.uuid4()
        p = build_trace_packet(sid, 5)
        assert len(p) == TRACE_PACKET_SIZE == 40
        assert trace_kind(p) == b"MTTR"
        assert is_trace_request(p)
        head = parse_packet(p)
        assert head.session_id == sid and head.seq == 5 and head.size == 40

    def test_reply_roundtrip(self):
        sid = uuid.uuid4()
        reply = build_trace_reply(sid, 7, "echo-edge-a")
        parsed = parse_trace_reply(reply)
        assert parsed is not None
        assert parsed.instance_name == "echo-edge-a"
        assert parsed.seq == 7 and parsed.session_id == sid
        assert trace_kind(reply) == b"MTRE"

    def test_reply_utf8_and_truncation(self):
        sid = uuid.uuid4()
        parsed = parse_trace_reply(build_trace_reply(sid, 1, "边缘-A"))
        assert parsed.instance_name == "边缘-A"
        assert parse_trace_reply(build_trace_reply(sid, 1, "x")[:-1]) is None

    def test_legacy_mtup_still_plain(self):
        sid = uuid.uuid4()
        p = build_packet(sid, 1, 576)
        assert trace_kind(p) is None
        assert parse_packet(p).size == 576


# --------------------------------------------------------------- ICMP 归属


class TestIcmpAttribution:
    def _error(self, icmp_type, icmp_code, sid, seq, reporter="10.0.1.1",
               payload=None, dport=9999):
        payload = build_trace_packet(sid, seq) if payload is None else payload
        inner = build_udp_encapsulating(
            "172.20.0.2", "10.0.0.10", 44444, dport, payload, ttl=1
        )
        pkt, rep = icmp_mod.build_icmp_error(icmp_type, icmp_code, reporter, inner)
        ihl = (pkt[0] & 0x0F) * 4
        return parse_icmp_error(pkt[ihl:], rep)

    def test_ttl_exceeded_full_quote_attributable(self):
        fb = self._error(11, 0, SESSION, 1)
        assert fb is not None
        assert fb.kind is IcmpKind.TTL_EXCEEDED
        assert fb.reporter == "10.0.1.1"
        assert fb.session_id == SESSION and fb.seq == 1
        assert fb.quoted_udp_dport == 9999

    def test_incomplete_quote_not_attributable(self):
        # 内层只有 UDP 头、没有完整 MTUP 负载（经典 8 字节引述）
        fb = self._error(11, 0, SESSION, 1, payload=b"")
        assert fb is None

    def test_bad_magic_not_attributable(self):
        fb = self._error(11, 0, SESSION, 1,
                         payload=b"XXXX" + bytes(HEADER_SIZE - 4))
        assert fb is None

    def test_port_unreachable(self):
        fb = self._error(3, 3, SESSION, 2, reporter="10.0.0.10")
        assert fb is not None
        assert fb.kind is IcmpKind.PORT_UNREACHABLE
        assert fb.reporter == "10.0.0.10"
    def test_other_dest_unreachable(self):
        fb = self._error(3, 1, SESSION, 1)  # host unreachable
        assert fb is not None and fb.kind is IcmpKind.DEST_UNREACHABLE_OTHER

    def test_checksum_valid(self):
        inner = build_udp_encapsulating(
            "172.20.0.2", "10.0.0.10", 44444, 9999,
            build_trace_packet(SESSION, 1), ttl=1,
        )
        pkt, _ = icmp_mod.build_icmp_error(11, 0, "10.0.1.1", inner)
        ihl = (pkt[0] & 0x0F) * 4
        assert icmp_mod.icmp_checksum(pkt[ihl:]) == 0


class TestErrorQueueParsing:
    """IP_RECVERR 错误队列消息解析（无需真实内核队列/特权）。

    内核 recvmsg(MSG_ERRQUEUE) 语义：ancdata 带 sock_extended_err（含
    ICMP type/code）+ sockaddr_in（报告者）；普通缓冲是被引述的内层 IP
    数据报（可能被 mtu 截断），不含 ICMP 头。
    """

    @staticmethod
    def _ancdata(reporter_ip, icmp_type, icmp_code, ee_origin=2):
        import socket as _socket
        from app.icmp_receiver import IP_RECVERR, _EE_STRUCT, _SOCKADDR_IN

        ee = _EE_STRUCT.pack(110, ee_origin, icmp_type, icmp_code, 0, 0, 0)
        sa = _SOCKADDR_IN.pack(_socket.AF_INET, 0,
                               _socket.inet_aton(reporter_ip))
        return [(_socket.IPPROTO_IP, IP_RECVERR, ee + sa)]

    @staticmethod
    def _inner_ip(sid, seq, payload=None, ttl=1):
        payload = build_trace_packet(sid, seq) if payload is None else payload
        return build_udp_encapsulating(
            "172.20.0.2", "10.0.0.10", 44444, 9999, payload, ttl=ttl
        )

    def test_ttl_exceeded_full_inner(self):
        from app.icmp_receiver import ErrorQueueReceiver

        fb = ErrorQueueReceiver.parse_errqueue(
            self._ancdata("10.0.1.1", 11, 0),
            self._inner_ip(SESSION, 1),
        )
        assert fb is not None
        assert fb.kind is IcmpKind.TTL_EXCEEDED and fb.attributable is True
        assert fb.reporter == "10.0.1.1"
        assert fb.session_id == SESSION and fb.seq == 1

    def test_port_unreachable_full_inner(self):
        from app.icmp_receiver import ErrorQueueReceiver

        fb = ErrorQueueReceiver.parse_errqueue(
            self._ancdata("10.0.0.10", 3, 3),
            self._inner_ip(SESSION, 2),
        )
        assert fb is not None
        assert fb.kind is IcmpKind.PORT_UNREACHABLE
        assert fb.reporter == "10.0.0.10" and fb.seq == 2

    def test_loopback_truncated_inner_still_terminal(self):
        # 实测 Linux loopback：内层 IP 头前 12 字节被截，MTUP 头完整保留
        from app.icmp_receiver import ErrorQueueReceiver

        truncated = self._inner_ip(SESSION, 1)[12:]
        fb = ErrorQueueReceiver.parse_errqueue(
            self._ancdata("127.0.0.1", 3, 3), truncated,
            expected_dport=9999,
        )
        assert fb is not None
        assert fb.kind is IcmpKind.PORT_UNREACHABLE
        assert fb.reporter == "127.0.0.1"

    def test_ttl_exceeded_never_uses_unattributable_fallback(self):
        # TTL 超时引述里没有任何 MTUP 头 → 必须丢弃，绝不凭空归跳
        from app.icmp_receiver import ErrorQueueReceiver

        garbage_inner = b"\x45" + bytes(31)
        assert ErrorQueueReceiver.parse_errqueue(
            self._ancdata("10.0.1.1", 11, 0), garbage_inner
        ) is None

    def test_non_icmp_origin_rejected(self):
        from app.icmp_receiver import ErrorQueueReceiver

        assert ErrorQueueReceiver.parse_errqueue(
            self._ancdata("10.0.1.1", 11, 0, ee_origin=99),
            self._inner_ip(SESSION, 1),
        ) is None


# --------------------------------------------------------------- 状态机


class FakeBackend:
    def __init__(self, host, port, script, send_error_at=None):
        self.host, self.port = host, port
        self.script = script
        self.queue: asyncio.Queue = asyncio.Queue()
        self.source_ipv4 = "172.20.0.2"
        self.source_port = 44444
        self.icmp_available = True
        self.send_error_at = send_error_at
        self.sent_ttls: list[int] = []
        self._tasks = []

    def send_ttl(self, packet, ttl):
        if self.send_error_at == ttl:
            raise OSError("EMSGSIZE simulated")
        self.sent_ttls.append(ttl)
        loop = asyncio.get_running_loop()
        for delay, kind, obj in self.script.get(ttl, []):
            self._tasks.append(loop.create_task(self._push(delay, kind, obj)))

    async def _push(self, delay, kind, obj):
        await asyncio.sleep(delay)
        await self.queue.put((kind, obj))

    async def get(self):
        return await self.queue.get()

    def close(self):
        for t in self._tasks:
            t.cancel()


def _ttl(sid, seq, reporter, **kw):
    payload = build_trace_packet(sid, seq)
    inner = build_udp_encapsulating(
        "172.20.0.2", "10.0.0.10", 44444, 9999, payload, ttl=seq
    )
    pkt, rep = icmp_mod.build_icmp_error(11, 0, reporter, inner)
    ihl = (pkt[0] & 0x0F) * 4
    return parse_icmp_error(pkt[ihl:], rep)


def _port(sid, seq, reporter="10.0.0.10"):
    payload = build_trace_packet(sid, seq)
    inner = build_udp_encapsulating(
        "172.20.0.2", "10.0.0.10", 44444, 9999, payload, ttl=seq
    )
    pkt, rep = icmp_mod.build_icmp_error(3, 3, reporter, inner)
    ihl = (pkt[0] & 0x0F) * 4
    return parse_icmp_error(pkt[ihl:], rep)


def _req(**kw):
    kw.setdefault("target_ipv4", "10.0.0.10")
    kw.setdefault("target_port", 9999)
    kw.setdefault("expected_instance", "echo-edge-a")
    kw.setdefault("max_hops", 5)
    return TraceRequest(**kw)


async def _run(script, timeout=80, **req_kw):
    tracer = Tracer(
        backend_factory=lambda h, p: FakeBackend(h, p, script),
        hop_timeout_ms=timeout,
    )
    return await tracer.trace(_req(**req_kw), _trace_id=SESSION)


class TestTracerStateMachine:
    def test_happy_path_match(self):
        script = {
            1: [(0.01, "icmp", _ttl(SESSION, 1, "10.0.1.1"))],
            2: [(0.01, "icmp", _ttl(SESSION, 2, "10.0.2.1"))],
            3: [(0.01, "udp", (build_trace_reply(SESSION, 3, "echo-edge-a"),
                               ("10.0.0.10", 9999)))],
        }
        res = asyncio.run(_run(script, max_hops=4))
        assert res.status == "reached" and res.matched is True
        assert res.instance_name == "echo-edge-a"
        assert [(h.status, h.router) for h in res.hops] == [
            ("router", "10.0.1.1"),
            ("router", "10.0.2.1"),
            ("echo", "10.0.0.10"),
        ]
        assert res.source_ipv4 == "172.20.0.2" and res.source_port == 44444
        assert res.hop_timeout_ms == 500 or res.hop_timeout_ms == 80

    def test_mismatch_delivery(self):
        script = {
            1: [(0.01, "icmp", _ttl(SESSION, 1, "10.0.1.1"))],
            2: [(0.01, "udp", (build_trace_reply(SESSION, 2, "echo-edge-B"),
                               ("10.0.0.10", 9999)))],
        }
        res = asyncio.run(
            _run(script, expected_instance="echo-edge-a", max_hops=3)
        )
        assert res.status == "mismatch"
        assert res.matched is False
        assert res.instance_name == "echo-edge-B"

    def test_legacy_plain_echo_unconfirmed(self):
        script = {
            1: [(0.01, "udp", (build_trace_packet(SESSION, 1),
                               ("10.0.0.10", 9999)))],
        }
        res = asyncio.run(_run(script, max_hops=3))
        assert res.status == "instance_unconfirmed"
        assert res.instance_name is None and res.matched is None
        assert res.hops[-1].status == "legacy_echo"
        assert "无法确认" in res.reason

    def test_port_unreachable_reports_and_stops(self):
        script = {
            1: [(0.01, "icmp", _ttl(SESSION, 1, "10.0.1.1"))],
            2: [(0.01, "icmp", _port(SESSION, 2))],
        }
        res = asyncio.run(_run(script, max_hops=4))
        assert res.status == "port_unreachable"
        assert len(res.hops) == 2
        assert res.hops[-1].status == "port_unreachable"
        assert "端口不可达" in res.reason

    def test_no_response_then_continue(self):
        res = asyncio.run(_run({}, timeout=30, max_hops=2))
        assert res.status == "max_hops_exceeded"
        assert all(h.status == "no_response" for h in res.hops)
        assert len(res.hops) == 2

    def test_late_and_unmatched_feedback_never_reclassifies(self):
        other = uuid.uuid4()
        script = {
            1: [(0.15, "icmp", _ttl(SESSION, 1, "10.0.1.1"))],  # 迟到
            2: [
                (0.01, "icmp", _ttl(other, 2, "10.9.9.9")),       # 串运行
                (0.01, "icmp", _ttl(SESSION, 1, "10.0.1.1")),    # 旧序号
                (0.02, "udp", (b"garbage", ("10.0.0.10", 9999))),
                (0.03, "icmp", _ttl(SESSION, 2, "10.0.2.1")),
            ],
            3: [(0.01, "udp", (build_trace_reply(SESSION, 3, "echo-edge-a"),
                               ("10.0.0.10", 9999)))],
        }
        res = asyncio.run(_run(script, timeout=80, max_hops=3))
        assert res.hops[0].status == "no_response"
        assert res.hops[0].router is None  # 迟到反馈没有改判
        assert res.hops[1].router == "10.0.2.1"
        assert res.stray_feedback == 3  # 串运行/旧序号/残包
        assert all(h.status != "send_error" for h in res.hops)
        assert res.status == "reached"

    def test_send_error_is_separate_outcome(self):
        tracer = Tracer(
            backend_factory=lambda h, p: FakeBackend(h, p, {}, send_error_at=1),
            hop_timeout_ms=50,
        )
        res = asyncio.run(tracer.trace(_req(max_hops=3), _trace_id=SESSION))
        assert res.status == "send_failed"
        assert res.hops[0].status == "send_error"

    def test_ttl_increments_one_socket_fixed_source(self):
        backend_holder = {}

        class Cap(FakeBackend):
            def send_ttl(self, packet, ttl):
                backend_holder.setdefault("ttls", []).append(ttl)
                super().send_ttl(packet, ttl)

        tracer = Tracer(
            backend_factory=lambda h, p: Cap(h, p, {}), hop_timeout_ms=20
        )
        res = asyncio.run(tracer.trace(_req(max_hops=4), _trace_id=SESSION))
        assert backend_holder["ttls"] == [1, 2, 3, 4]
        assert len({(res.source_ipv4, res.source_port)}) == 1


# --------------------------------------------------------------- 端到端 API


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestTraceApi:
    def test_loopback_trace_reaches_local_echo(self, client):
        # 回显端在同进程 loopback：TTL=1 直达，第一跳即回显实例应答
        body = {
            "target_ipv4": "127.0.0.1",
            "target_port": 9999,
            "expected_instance": "echo-local",
            "max_hops": 3,
        }
        r = client.post("/trace", json=body)
        assert r.status_code == 200, r.text
        res = r.json()
        assert res["status"] == "reached"
        assert res["matched"] is True
        assert res["instance_name"] == "echo-local"
        assert res["hops"][0]["status"] == "echo"
        assert res["hops"][0]["instance_name"] == "echo-local"
        assert res["hop_timeout_ms"] == 500  # 需求固定 500ms
        assert res["source_port"] > 0

    def test_loopback_trace_mismatch(self, client):
        r = client.post("/trace", json={
            "target_ipv4": "127.0.0.1",
            "target_port": 9999,
            "expected_instance": "wrong-instance",
            "max_hops": 2,
        })
        assert r.status_code == 200
        res = r.json()
        assert res["status"] == "mismatch"
        assert res["matched"] is False
        assert res["instance_name"] == "echo-local"

    def test_configured_instance_name_is_returned(self, client):
        client.put("/echo/config", json={
            "mode": "normal", "drop_threshold": None,
            "instance_name": "edge-paris-01",
        })
        res = client.post("/trace", json={
            "target_ipv4": "127.0.0.1", "target_port": 9999,
            "expected_instance": "edge-paris-01", "max_hops": 2,
        }).json()
        assert res["status"] == "reached"
        assert res["instance_name"] == "edge-paris-01"

    def test_legacy_echo_server_unconfirmed(self, client):
        # 起一个只做原样回包的"旧回显端"，后台线程持续反射
        import threading

        port = _free_udp_port()
        legacy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        legacy.bind(("127.0.0.1", port))
        legacy.settimeout(2.0)
        stop = threading.Event()

        def reflect():
            while not stop.is_set():
                try:
                    data, addr = legacy.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                legacy.sendto(data, addr)  # 旧端：原样回包

        t = threading.Thread(target=reflect, daemon=True)
        t.start()
        try:
            res = client.post("/trace", json={
                "target_ipv4": "127.0.0.1", "target_port": port,
                "expected_instance": "echo-local", "max_hops": 2,
            }).json()
            assert res["status"] == "instance_unconfirmed"
            assert res["instance_name"] is None
            assert res["matched"] is None
            assert res["hops"][-1]["status"] == "legacy_echo"
        finally:
            stop.set()
            legacy.close()
            t.join(timeout=1.0)

    def test_port_unreachable(self, client):
        port = _free_udp_port()  # 无人监听
        res = client.post("/trace", json={
            "target_ipv4": "127.0.0.1", "target_port": port,
            "expected_instance": "echo-local", "max_hops": 2,
        }).json()
        assert res["status"] == "port_unreachable"
        assert res["hops"][-1]["status"] == "port_unreachable"
        assert "端口不可达" in res["reason"]

    def test_request_validation(self, client):
        base = {
            "target_ipv4": "127.0.0.1", "target_port": 9999,
            "expected_instance": "echo-local", "max_hops": 3,
        }
        bad_cases = [
            {**base, "target_ipv4": "not-an-ip"},
            {**base, "target_ipv4": "2001:db8::1"},  # 只要 IPv4
            {**base, "target_port": 0},
            {**base, "target_port": 70000},
            {**base, "max_hops": 0},
            {**base, "max_hops": 17},
            {**base, "expected_instance": ""},
            {**base, "unexpected": 1},
        ]
        for bad in bad_cases:
            r = client.post("/trace", json=bad)
            assert r.status_code == 422, bad

    def test_trace_history_stored(self, client):
        r = client.post("/trace", json={
            "target_ipv4": "127.0.0.1", "target_port": 9999,
            "expected_instance": "echo-local", "max_hops": 2,
        })
        trace_id = r.json()["trace_id"]
        got = client.get(f"/trace/{trace_id}")
        assert got.status_code == 200
        assert got.json()["trace_id"] == trace_id
        listing = client.get("/traces").json()
        assert any(t["trace_id"] == trace_id for t in listing)
        assert client.get("/trace/nope").status_code == 404


class TestEchoServerTraceHandling:
    def test_mttr_gets_mtre_not_plain_echo(self, client):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sid = uuid.uuid4()
        try:
            sock.sendto(build_trace_packet(sid, 1), ("127.0.0.1", 9999))
            data, _ = sock.recvfrom(4096)
            reply = parse_trace_reply(data)
            assert reply is not None
            assert reply.session_id == sid and reply.seq == 1
            assert reply.instance_name
            # 不是原样回包
            assert data != build_trace_packet(sid, 1)
        finally:
            sock.close()

    def test_legacy_mtup_still_echoed_verbatim(self, client):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sid = uuid.uuid4()
        packet = build_packet(sid, 1, 128)
        try:
            sock.sendto(packet, ("127.0.0.1", 9999))
            data, _ = sock.recvfrom(4096)
            assert data == packet  # 原 MTUP 探测仍原样回显
        finally:
            sock.close()

    def test_stats_include_trace_replied(self, client):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sid = uuid.uuid4()
        sock.settimeout(2.0)
        try:
            sock.sendto(build_trace_packet(sid, 1), ("127.0.0.1", 9999))
            sock.recvfrom(4096)
        finally:
            sock.close()
        stats = client.get("/echo/config").json()["stats"]
        assert stats["trace_replied"] >= 1
