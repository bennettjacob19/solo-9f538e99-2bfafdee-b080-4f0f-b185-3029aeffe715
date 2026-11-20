"""本地 UDP 回显端。

两类报文分别处理：

- **MTUP 最大负载探测报文**：原样回送（行为保持不变），受丢弃阈值 / 断联配置约束；
- **MTTR 迁网诊断报文**：不做原样回包，而是回送 MTRE 应答，携带本实例名，
  供追踪端确认"最后是哪台回显实例应答"。

行为可通过 API 动态配置：
- ``drop_threshold``: UDP 负载超过该字节数即丢弃（模拟"大包不通"）；
- ``mode = "disconnect"``: 丢弃一切报文（模拟断联）。

每次成功变更配置都会使 ``epoch`` 单调递增。探测任务在开始与结束时比对
epoch：若探测期间配置发生变化，本次结论作废。
"""
from __future__ import annotations

import asyncio
import os
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .packets import (
    MAX_UDP_PAYLOAD,
    build_trace_reply,
    is_trace_request,
    parse_packet,
)

# 实例名可由环境变量指定（compose 里每台回显实例不同）
DEFAULT_INSTANCE_NAME = os.environ.get("ECHO_INSTANCE_NAME", "echo-local")
MAX_INSTANCE_NAME_LEN = 64


class EchoConfig(BaseModel):
    """回显端行为配置。校验失败时调用方不得改动现有状态。"""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["normal", "disconnect"] = Field(
        default="normal",
        description="normal=按阈值丢弃；disconnect=断联，丢弃一切报文",
    )
    drop_threshold: Optional[int] = Field(
        default=None,
        ge=0,
        le=MAX_UDP_PAYLOAD,
        description="UDP 负载超过该字节数即丢弃；null 表示不丢弃",
    )
    instance_name: str = Field(
        default=DEFAULT_INSTANCE_NAME,
        min_length=1,
        max_length=MAX_INSTANCE_NAME_LEN,
        description="本回显实例名（MTTR 诊断包的 MTRE 应答携带此名称）",
    )


class EchoState:
    """回显端共享状态（配置 + 世代号）。仅在事件循环内访问，替换是原子的。"""

    def __init__(self) -> None:
        self.config = EchoConfig()
        self.epoch = 0

    def apply(self, cfg: EchoConfig) -> int:
        """应用已通过校验的新配置，返回新 epoch。校验失败时不应调用本方法。"""
        self.config = cfg
        self.epoch += 1
        return self.epoch


class EchoProtocol(asyncio.DatagramProtocol):
    """回显协议：MTUP 原样回送、MTTR 回实例名应答，按配置丢弃。"""

    def __init__(self, state: EchoState) -> None:
        self.state = state
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.echoed = 0          # MTUP 原样回包数
        self.trace_replied = 0  # MTTR → MTRE 实例名应答数
        self.dropped = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        cfg = self.state.config
        if cfg.mode == "disconnect":
            self.dropped += 1
            return
        if cfg.drop_threshold is not None and len(data) > cfg.drop_threshold:
            self.dropped += 1
            return
        head = parse_packet(data)
        if head is None:
            self.dropped += 1
            return
        assert self.transport is not None

        if is_trace_request(data):
            # 迁网诊断包：回实例名应答（MTRE），而不是原样回包
            reply = build_trace_reply(head.session_id, head.seq, cfg.instance_name)
            self.transport.sendto(reply, addr)
            self.trace_replied += 1
            return

        # 普通 MTUP 探测（以及 MTRE 之类不应出现在服务端的报文）：原样回显
        self.transport.sendto(data, addr)
        self.echoed += 1

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass
