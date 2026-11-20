"""探测 / 诊断报文编解码。

两类报文共享同一个 28 字节 MTUP 头，保证 ICMP 引述到完整 MTUP 头时
即可按本次运行编号 + 序号归属到具体一跳：

1. 最大负载探测报文（MTUP，原样保留）::

    | 0..3   | 4..19        | 20..23 | 24..27 | 28 .. size-1 |
    | magic  | 本次探测编号  | seq    | size   | padding      |
    | "MTUP" | UUID(16B)    | uint32 | uint32 | 0x00 ...     |

2. 迁网诊断报文（MTTR），总长 40 字节::

    | MTUP 头 28B                      | 28..31   | 32..39  |
    | magic="MTUP" | UUID | seq | size | kind    | 保留    |
    |                                  | "MTTR"  | 0x00    |

   回显端识别 kind="MTTR" 后，回送实例名应答报文（MTRE）::

    | MTUP 头 28B                      | 28..31   | 32..33        | 34 ..       |
    | magic="MTUP" | UUID | seq | size | kind    | name_len (n)  | 实例名 UTF-8 |
    |                                  | "MTRE"  | uint16        |             |

- 每个报文都携带本次运行编号（session UUID）与序号 seq；
- size 字段为整个 UDP 负载长度，接收方据此校验报文未被截断/拼装；
- 只有 magic / 探测编号 / seq / size 全部对应的回包才被采信；
- 旧回显端不认识 kind，仍按 MTUP 原样回包，探测端据此报告"实例无法确认"。
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

MAGIC = b"MTUP"
_HEADER = struct.Struct("!4s16sII")
HEADER_SIZE = _HEADER.size  # 28
# UDP 负载理论上限：65535 - 20(IPv4 头) - 8(UDP 头)
MAX_UDP_PAYLOAD = 65507

# 诊断报文标记与定长
TRACE_KIND = b"MTTR"
REPLY_KIND = b"MTRE"
TRACE_PACKET_SIZE = HEADER_SIZE + 4 + 8  # 40
_MAX_INSTANCE_NAME_LEN = 255


@dataclass(frozen=True)
class Packet:
    session_id: uuid.UUID
    seq: int
    size: int  # 整个 UDP 负载长度


@dataclass(frozen=True)
class TraceReply:
    """回显端实例名应答（kind=MTRE）。"""

    session_id: uuid.UUID
    seq: int
    size: int
    instance_name: str


def build_packet(session_id: uuid.UUID, seq: int, size: int) -> bytes:
    """构造一个总长恰好为 size 字节的 MTUP 探测报文。"""
    if size < HEADER_SIZE:
        raise ValueError(f"报文长度 {size} 小于头部长度 {HEADER_SIZE}")
    if size > MAX_UDP_PAYLOAD:
        raise ValueError(f"报文长度 {size} 超过 UDP 负载上限 {MAX_UDP_PAYLOAD}")
    return _HEADER.pack(MAGIC, session_id.bytes, seq, size) + bytes(size - HEADER_SIZE)


def build_trace_packet(session_id: uuid.UUID, seq: int) -> bytes:
    """构造迁网诊断报文（MTTR，固定 40 字节）。

    报文刻意保持短小：路由器在 ICMP 差错报文中通常只引述前 ~576 字节，
    完整 MTUP 头 + kind 都能被引述回来，保证可归属。
    """
    return (
        _HEADER.pack(MAGIC, session_id.bytes, seq, TRACE_PACKET_SIZE)
        + TRACE_KIND
        + bytes(8)
    )


def build_trace_reply(session_id: uuid.UUID, seq: int, instance_name: str) -> bytes:
    """构造回显端实例名应答报文（MTRE）。"""
    name_bytes = instance_name.encode("utf-8")
    if len(name_bytes) > _MAX_INSTANCE_NAME_LEN:
        raise ValueError(f"实例名 UTF-8 编码后超过 {_MAX_INSTANCE_NAME_LEN} 字节")
    total = HEADER_SIZE + 4 + 2 + len(name_bytes)
    return (
        _HEADER.pack(MAGIC, session_id.bytes, seq, total)
        + REPLY_KIND
        + struct.pack("!H", len(name_bytes))
        + name_bytes
    )


def parse_packet(data: bytes) -> Packet | None:
    """解析 MTUP 头；magic 不符或长度不自洽时返回 None。

    MTTR / MTRE 报文同样带有合法 MTUP 头，本函数返回其公共头信息；
    调用方需要区分诊断报文时再用 :func:`trace_kind` / :func:`parse_trace_reply`。
    """
    if len(data) < HEADER_SIZE:
        return None
    magic, sid, seq, size = _HEADER.unpack(data[:HEADER_SIZE])
    if magic != MAGIC or size != len(data):
        return None
    return Packet(session_id=uuid.UUID(bytes=sid), seq=seq, size=size)


def trace_kind(data: bytes) -> bytes | None:
    """返回诊断报文的 4 字节 kind（MTTR/MTRE）；普通 MTUP 报文返回 None。"""
    if len(data) < HEADER_SIZE + 4:
        return None
    kind = data[HEADER_SIZE:HEADER_SIZE + 4]
    return kind if kind in (TRACE_KIND, REPLY_KIND) else None


def is_trace_request(data: bytes) -> bool:
    """是否为迁网诊断请求（MTTR）。"""
    return trace_kind(data) == TRACE_KIND


def parse_trace_reply(data: bytes) -> TraceReply | None:
    """解析实例名应答（MTRE）；不合法或非 MTRE 时返回 None。"""
    head = parse_packet(data)
    if head is None or trace_kind(data) != REPLY_KIND:
        return None
    if len(data) < HEADER_SIZE + 6:
        return None
    (name_len,) = struct.unpack("!H", data[HEADER_SIZE + 4:HEADER_SIZE + 6])
    if len(data) != HEADER_SIZE + 6 + name_len:
        return None
    try:
        name = data[HEADER_SIZE + 6:].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return TraceReply(
        session_id=head.session_id, seq=head.seq, size=head.size, instance_name=name
    )
