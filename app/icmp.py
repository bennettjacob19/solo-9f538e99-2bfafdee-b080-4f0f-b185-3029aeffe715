"""ICMPv4 差错报文解析：把 TTL 超时 / 目的不可达归属于具体一跳。

归属规则（需求硬性要求）：

- 只有当 ICMP 差错报文引述的内层 IP 数据报里包含**完整 MTUP 头**
  （28 字节），且 magic / 本次运行编号 / 序号能对应上时，才把该 ICMP
  归属于某一跳；只引述经典 8 字节（IP 头 + UDP 头）的差错报文无法归属。
- 迟到或无法对应的反馈不改变既有判定，也不算作新一跳的发送失败。
- 目标返回的 ICMP 端口不可达（type 3 / code 3）单独报告并停止。

本模块只做纯字节解析，不接触 socket，便于无特权环境下单测。
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .packets import HEADER_SIZE, MAGIC

IP_HEADER_MIN = 20
UDP_HEADER_LEN = 8


class IcmpKind(str, Enum):
    TTL_EXCEEDED = "ttl_exceeded"          # type 11, code 0
    PORT_UNREACHABLE = "port_unreachable"  # type 3,  code 3
    DEST_UNREACHABLE_OTHER = "dest_unreachable_other"
    OTHER = "other"


@dataclass(frozen=True)
class IcmpFeedback:
    """一条 ICMP 反馈。

    ``session_id`` 为随机 UUID 且 ``attributable=False`` 时，表示该差错
    引述中不含完整 MTUP 头（如 Linux loopback 端口不可达只引述 32 字节），
    无法按编号/序号归属到具体诊断包；这类反馈**只可能是终止性的目的不可达**，
    由 socket 层（IP_RECVERR 按 socket 投递 / raw 按端口过滤）保证来源，
    绝不会被用于 TTL 逐跳归跳。
    """

    kind: IcmpKind
    reporter: str          # 发出该 ICMP 的路由器 / 主机 IPv4
    session_id: uuid.UUID  # 引述报文的本次运行编号；不可归属时为占位 UUID
    seq: int               # 引述报文的序号；不可归属时为 0
    quoted_udp_dport: int  # 引述报文的 UDP 目的端口（辅助核对）
    icmp_type: int
    icmp_code: int
    attributable: bool = True  # 引述是否含完整 MTUP 头、可按编号/序号归属


def _ipv4_header_len(ip_packet: bytes) -> int:
    if len(ip_packet) < IP_HEADER_MIN:
        return 0
    version = ip_packet[0] >> 4
    ihl = ip_packet[0] & 0x0F
    if version != 4 or ihl < 5:
        return 0
    return ihl * 4


def _parse_quoted(inner_ip: bytes) -> Optional[tuple[uuid.UUID, int, int, int]]:
    """从被引述的内层 IP 数据报中提取 (session_id, seq, udp_sport, udp_dport)。

    内层报文必须是 UDP，且 UDP 负载含完整 MTUP 头（magic + UUID + seq）；
    否则返回 None —— 对应"只引述 8 字节、无法归跳"的情况。
    """
    ihl = _ipv4_header_len(inner_ip)
    if not ihl or len(inner_ip) < ihl + UDP_HEADER_LEN:
        return None
    proto = inner_ip[9]
    if proto != 17:  # 不是 UDP
        return None
    sport, dport, udp_len = struct.unpack("!HHH", inner_ip[ihl:ihl + 6])
    udp_payload_start = ihl + UDP_HEADER_LEN
    # 完整 MTUP 头必须在引述范围内，且 UDP 长度字段自洽（有值时）
    if udp_len and udp_len < UDP_HEADER_LEN + HEADER_SIZE:
        return None
    if len(inner_ip) < udp_payload_start + HEADER_SIZE:
        return None
    payload = inner_ip[udp_payload_start:udp_payload_start + HEADER_SIZE]
    magic, sid_bytes, seq, size = struct.unpack("!4s16sII", payload)
    if magic != MAGIC:
        return None
    # size 字段不应小于 MTUP 头本身（进一步排除残缺/拼装引述）
    if size < HEADER_SIZE:
        return None
    return uuid.UUID(bytes=sid_bytes), seq, sport, dport


def _parse_partial_quote(
    inner_ip: bytes,
) -> Optional[tuple[uuid.UUID, int]]:
    """部分引述回退：内层 IP/UDP 头被内核截断，但 MTUP 头完整时的归属。

    Linux loopback 等场景下，``icmp_send`` 引述长度受
    ``min(576, mtu-28)`` 限制，可能只带回内层 IP 头的后段 + 完整 UDP 负载
    （实测 loopback 端口不可达引述从内层 IP 头第 12 字节开始，UDP 头整体
    被截掉，但 28 字节 MTUP 头完整保留）。此时无法读到 UDP 端口，
    但仍可凭 magic + 本次运行编号 + 序号归属；端口核对交给 socket 层
    （IP_RECVERR 错误队列本就按 socket 过滤，或 raw 后端按 dport 过滤）。

    为避免在任意字节流里误匹配 magic，要求：

    - magic 之后的 28 字节完整存在；
    - ``size`` 字段自洽且不小于 MTUP 头长度。

    只回退用于**目的不可达**类差错；TTL 超时归跳仍走严格路径，
    避免把残缺引述误判成新一跳。
    """
    idx = inner_ip.find(MAGIC)
    if idx < 0 or len(inner_ip) < idx + HEADER_SIZE:
        return None
    magic, sid_bytes, seq, size = struct.unpack(
        "!4s16sII", inner_ip[idx:idx + HEADER_SIZE]
    )
    if magic != MAGIC or size < HEADER_SIZE:
        return None
    return uuid.UUID(bytes=sid_bytes), seq


def parse_errqueue_datagram(
    inner_ip: bytes,
    icmp_type: int,
    icmp_code: int,
    reporter: str,
    expected_dport: Optional[int] = None,
) -> Optional[IcmpFeedback]:
    """解析 ``IP_RECVERR`` 错误队列 recvmsg 带出的数据报。

    内核 ``ip_recv_errqueue`` 语义：recvmsg 的普通缓冲是**被引述的内层 IP
    数据报**（已按 ``min(576, mtu-28)`` 截断，不含 ICMP 头）；ICMP 类型/代码
    在 ancdata 的 ``sock_extended_err`` 里。本函数据此走与
    :func:`parse_icmp_error` 相同的三级归属逻辑。
    """
    if icmp_type == 11 and icmp_code == 0:
        kind = IcmpKind.TTL_EXCEEDED
    elif icmp_type == 3 and icmp_code == 3:
        kind = IcmpKind.PORT_UNREACHABLE
    elif icmp_type == 3:
        kind = IcmpKind.DEST_UNREACHABLE_OTHER
    else:
        kind = IcmpKind.OTHER

    quoted = _parse_quoted(inner_ip)
    if quoted is not None:
        session_id, seq, _sport, dport = quoted
        return IcmpFeedback(
            kind=kind, reporter=reporter, session_id=session_id, seq=seq,
            quoted_udp_dport=dport, icmp_type=icmp_type, icmp_code=icmp_code,
            attributable=True,
        )

    partial: Optional[tuple[uuid.UUID, int]] = None
    if icmp_type == 3:
        partial = _parse_partial_quote(inner_ip)
    if partial is not None:
        session_id, seq = partial
        return IcmpFeedback(
            kind=kind, reporter=reporter, session_id=session_id, seq=seq,
            quoted_udp_dport=(expected_dport or 0),
            icmp_type=icmp_type, icmp_code=icmp_code, attributable=True,
        )

    # 无完整 MTUP 头引述：仅终止性目的不可达可降级为不可归属反馈
    if icmp_type != 3:
        return None
    return IcmpFeedback(
        kind=kind, reporter=reporter,
        session_id=uuid.UUID(int=0), seq=0,
        quoted_udp_dport=(expected_dport or 0),
        icmp_type=icmp_type, icmp_code=icmp_code, attributable=False,
    )


def parse_icmp_error(
    icmp_payload: bytes,
    reporter: str,
    expected_dport: Optional[int] = None,
) -> Optional[IcmpFeedback]:
    """解析 ICMP 差错报文（不含外层 IP 头）。

    ``reporter`` 为外层 IP 头的源地址（由 socket 层提供）。
    ``expected_dport`` 用于部分引述回退时的端口核对（raw 后端）。

    归属优先级：

    1. 完整内层 IP/UDP + 完整 MTUP 头（严格路径）：TTL 超时与目的不可达均可，
       按本次运行编号 + 序号精确归属；
    2. 部分引述但含完整 MTUP 头（仅目的不可达）：凭 magic/编号/序号归属；
    3. 引述中完全没有 MTUP 头（仅目的不可达，如 loopback 只引述 32B）：
       返回 ``attributable=False`` 的终止性反馈，由 socket 层保证来源，
       调用方不得把它用于 TTL 逐跳归跳，只能作为目的不可达终止信号。

    TTL 超时（type 11）在任何情况下都必须含完整 MTUP 头，否则返回 None。
    """
    if len(icmp_payload) < 8:
        return None
    icmp_type, icmp_code = icmp_payload[0], icmp_payload[1]
    # 差错报文固定 8 字节 ICMP 头，其后是被引述的内层 IP 数据报
    inner_ip = icmp_payload[8:]
    quoted = _parse_quoted(inner_ip)

    partial: Optional[tuple[uuid.UUID, int]] = None
    if quoted is None and icmp_type == 3:
        # 严格路径失败：目的不可达尝试部分引述（含完整 MTUP 头）回退
        partial = _parse_partial_quote(inner_ip)

    if icmp_type == 11 and icmp_code == 0:
        kind = IcmpKind.TTL_EXCEEDED
    elif icmp_type == 3 and icmp_code == 3:
        kind = IcmpKind.PORT_UNREACHABLE
    elif icmp_type == 3:
        kind = IcmpKind.DEST_UNREACHABLE_OTHER
    else:
        kind = IcmpKind.OTHER

    if quoted is not None:
        session_id, seq, sport, dport = quoted
        return IcmpFeedback(
            kind=kind, reporter=reporter, session_id=session_id, seq=seq,
            quoted_udp_dport=dport, icmp_type=icmp_type, icmp_code=icmp_code,
            attributable=True,
        )

    if partial is not None:
        session_id, seq = partial
        return IcmpFeedback(
            kind=kind, reporter=reporter, session_id=session_id, seq=seq,
            quoted_udp_dport=(expected_dport or 0),
            icmp_type=icmp_type, icmp_code=icmp_code, attributable=True,
        )

    # 无任何 MTUP 头引述：只有终止性目的不可达可降级为不可归属反馈；
    # TTL 超时 / 其他差错一律丢弃（绝不凭空归跳）
    if icmp_type != 3:
        return None
    return IcmpFeedback(
        kind=kind, reporter=reporter,
        session_id=uuid.UUID(int=0), seq=0,
        quoted_udp_dport=(expected_dport or 0),
        icmp_type=icmp_type, icmp_code=icmp_code, attributable=False,
    )


def icmp_checksum(data: bytes) -> int:
    """RFC 1071 校验和（构造测试报文用；真实报文由内核校验）。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ---------------------------------------------------------------------------
# 测试辅助：构造可被 parse_icmp_error 解析的 ICMP 差错报文（含外层 IP 头）
# ---------------------------------------------------------------------------


def build_ipv4(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    identification: int = 0,
    ttl: int = 64,
) -> bytes:
    """构造一个不带选项的 20 字节 IPv4 报文（测试辅助）。"""
    total_len = IP_HEADER_MIN + len(payload)
    head = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, identification, 0, ttl, proto, 0,
        socket_inet_aton(src), socket_inet_aton(dst),
    )
    return head + payload


def socket_inet_aton(ip: str) -> bytes:
    import socket

    return socket.inet_aton(ip)


def build_udp_encapsulating(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    udp_payload: bytes,
    ttl: int,
) -> bytes:
    """构造内层 IP/UDP 数据报（测试辅助，校验和填 0）。"""
    udp_head = struct.pack("!HHHH", sport, dport, UDP_HEADER_LEN + len(udp_payload), 0)
    return build_ipv4(src_ip, dst_ip, 17, udp_head + udp_payload, ttl=ttl)


def build_icmp_error(
    icmp_type: int,
    icmp_code: int,
    reporter: str,
    inner_ip: bytes,
) -> tuple[bytes, str]:
    """构造 (外层IP头+ICMP差错报文, reporter)（测试辅助）。"""
    body = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0) + inner_ip
    csum = icmp_checksum(body)
    body = struct.pack("!BBHI", icmp_type, icmp_code, csum, 0) + inner_ip
    # 外层 IP 头仅用于让接收侧取源地址；测试里直接把 reporter 传回去
    return build_ipv4(reporter, "10.0.0.1", 1, body), reporter
