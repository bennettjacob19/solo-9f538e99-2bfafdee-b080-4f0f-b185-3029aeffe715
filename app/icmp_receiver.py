"""ICMP 反馈接收：两种后端，对上层呈现统一的反馈队列。

后端 1（默认，无需特权）：在 UDP socket 上开启 ``IP_RECVERR``，
内核把异步 ICMP 差错放进 socket 错误队列，后台线程用
``recvmsg(MSG_ERRQUEUE)`` 取出并解析。普通容器即可工作。

后端 2（回退，需 CAP_NET_RAW / root）：``SOCK_RAW/IPPROTO_ICMP``
收全部 ICMP，按引述的内层 UDP 源/目的端口过滤本运行的报文。

两种后端解析出的 :class:`IcmpFeedback` 都已经过"完整 MTUP 头 +
magic"校验；无法归属的反馈在解析层即被丢弃，绝不会改判或算发送失败。
"""
from __future__ import annotations

import asyncio
import socket
import struct
import threading
from typing import Callable, Optional

from .icmp import IcmpFeedback, parse_errqueue_datagram, parse_icmp_error

# Linux 常量兜底（部分 Python 构建未导出）
IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 8192)
SO_EE_ORIGIN_ICMP = 2
# struct sock_extended_err { u32 ee_errno; u8 ee_origin; u8 ee_type;
#   u8 ee_code; u8 ee_pad; u32 ee_info; u32 ee_data; }  -> 4+1+1+1+1+4+4 = 16
_EE_STRUCT = struct.Struct("!IBBBBII")
# struct sockaddr_in { sa_family_t(2, 本机字节序) ; in_port(2) ;
#   struct in_addr(4) ; char sin_zero(8) } —— 内核错误队列里放 16 字节
_SOCKADDR_IN = struct.Struct("=HH4s8x")


class IcmpReceiver:
    """统一接口：后台线程把可归属反馈投递给回调。"""

    def start(self, on_feedback: Callable[[IcmpFeedback], None]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class _ThreadedReceiver(IcmpReceiver):
    """后台线程轮询的公共骨架。"""

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._on_feedback: Optional[Callable[[IcmpFeedback], None]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _emit(self, fb: IcmpFeedback) -> None:
        cb = self._on_feedback
        loop = self._loop
        if cb is None:
            return
        if loop is not None and loop.is_running():
            # 从线程安全地把反馈送回事件循环协程
            loop.call_soon_threadsafe(cb, fb)
        else:  # pragma: no cover - 纯线程测试路径
            cb(fb)

    def start(self, on_feedback: Callable[[IcmpFeedback], None]) -> None:
        self._on_feedback = on_feedback
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=self.__class__.__name__, daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._wake()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=1.0)

    def _wake(self) -> None:
        """可选：唤醒阻塞中的接收循环。"""

    def _run(self) -> None:  # pragma: no cover - 由子类覆盖
        raise NotImplementedError


class ErrorQueueReceiver(_ThreadedReceiver):
    """基于 UDP socket IP_RECVERR 错误队列的接收端（无需特权）。"""

    def __init__(self, udp_sock: socket.socket, expected_dport: int = 0) -> None:
        super().__init__()
        self._sock = udp_sock
        self._expected_dport = expected_dport
        udp_sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)

    def _run(self) -> None:
        sock = self._sock
        while not self._stop.is_set():
            try:
                msg, ancdata, _flags, _addr = sock.recvmsg(
                    256, 1024, MSG_ERRQUEUE
                )
            except BlockingIOError:
                # 错误队列暂时为空：短轮询，保证 stop 能及时生效
                if self._stop.wait(0.02):
                    break
                continue
            except OSError:
                break
            fb = self._from_ancdata(ancdata, msg)
            if fb is not None:
                self._emit(fb)

    @staticmethod
    def parse_errqueue(
        ancdata: list[tuple[int, int, bytes]],
        msg: bytes,
        expected_dport: Optional[int] = None,
    ) -> Optional[IcmpFeedback]:
        """解析一次 recvmsg(MSG_ERRQUEUE) 的返回（可独立单测）。

        内核语义（ip_recv_errqueue）：

        - ancdata 里 ``IP_RECVERR`` 控制消息 = ``sock_extended_err``(16B)
          紧跟 ``sockaddr_in``(16B，差错报告者地址)，ICMP type/code 在
          ``sock_extended_err`` 的 ee_type/ee_code 字段；
        - recvmsg 的普通数据缓冲 ``msg`` 是**被引述的内层 IP 数据报**
          （已按 mtu 截断，不含 ICMP 头），交给
          :func:`parse_errqueue_datagram` 做三级归属校验。
        """
        ee_data: Optional[bytes] = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.IPPROTO_IP and cmsg_type == IP_RECVERR:
                ee_data = cmsg_data
        if ee_data is None or len(ee_data) < _EE_STRUCT.size + _SOCKADDR_IN.size:
            return None
        (
            _ee_errno, ee_origin, ee_type, ee_code, _pad,
            _ee_info, _ee_data,
        ) = _EE_STRUCT.unpack(ee_data[: _EE_STRUCT.size])
        if ee_origin != SO_EE_ORIGIN_ICMP:
            return None
        _family, _port, addr_bytes = _SOCKADDR_IN.unpack(
            ee_data[_EE_STRUCT.size:_EE_STRUCT.size + _SOCKADDR_IN.size]
        )
        reporter = socket.inet_ntoa(addr_bytes)
        return parse_errqueue_datagram(
            msg, ee_type, ee_code, reporter, expected_dport=expected_dport
        )

    def _from_ancdata(
        self, ancdata: list[tuple[int, int, bytes]], msg: bytes
    ) -> Optional[IcmpFeedback]:
        return self.parse_errqueue(
            ancdata, msg, expected_dport=self._expected_dport
        )


class RawIcmpReceiver(_ThreadedReceiver):
    """基于 raw ICMP socket 的接收端（需要 CAP_NET_RAW）。"""

    def __init__(self, udp_sport: int, udp_dport: int) -> None:
        super().__init__()
        self._sport = udp_sport
        self._dport = udp_dport
        self._sock: Optional[socket.socket] = None

    def _run(self) -> None:
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
        except OSError:
            # 无特权：静默退出，上层通过 available()/调用结果感知
            return
        self._sock = sock
        sock.settimeout(0.1)
        try:
            while not self._stop.is_set():
                try:
                    packet, _addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                fb = self._parse_raw(packet)
                if fb is not None:
                    self._emit(fb)
        finally:
            sock.close()

    def _parse_raw(self, packet: bytes) -> Optional[IcmpFeedback]:
        if len(packet) < 20:
            return None
        version_ihl = packet[0]
        if (version_ihl >> 4) != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        if len(packet) < ihl + 8:
            return None
        reporter = socket.inet_ntoa(packet[12:16])
        icmp_payload = packet[ihl:]
        fb = parse_icmp_error(
            icmp_payload, reporter, expected_dport=self._dport
        )
        if fb is None:
            return None
        # raw socket 能看到整机所有 ICMP：严格路径按引述的 UDP 端口对过滤；
        # 部分引述回退读不到端口（quoted_udp_dport=0），已由 expected_dport
        # 在解析层确认归属，这里放行
        if fb.quoted_udp_dport and fb.quoted_udp_dport != self._dport:
            return None
        return fb

    def _wake(self) -> None:
        sock = self._sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def open_icmp_receiver(
    udp_sock: socket.socket, udp_sport: int, udp_dport: int
) -> Optional[IcmpReceiver]:
    """按可用性选择后端；都不可用时返回 None（调用方报告 ICMP 不可用）。"""
    try:
        return ErrorQueueReceiver(udp_sock, expected_dport=udp_dport)
    except OSError:
        try:
            return RawIcmpReceiver(udp_sport, udp_dport)
        except OSError:
            return None
