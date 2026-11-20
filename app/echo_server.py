"""UDP 回显端：原样回显 MTUP 探测报文，并为 MTPS 诊断包回复实例名。

- MTUP 探测报文（``/probe`` 使用）：原样回显，行为与既有版本一致；
- MTPS 诊断包（``/trace`` 使用）：回送 ``MTRP`` 应答，带本次 session/seq/nonce
  与本实例名，供逐跳诊断确认"最后是哪台回显实例应答"；
- ``echo_instance_mode = "legacy"`` 时把收到的诊断包原样回显（模拟不识别实例名的旧端），
  用于演示"实例无法确认"。

行为可通过 API 动态配置：
- ``drop_threshold``: UDP 负载超过该字节数即丢弃（模拟"大包不通"）；
- ``mode = "disconnect"``: 丢弃一切报文（模拟断联）。

每次成功变更配置都会使 ``epoch`` 单调递增。探测任务在开始与结束时比对
epoch：若探测期间配置发生变化，本次结论作废。
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .packets import MAX_UDP_PAYLOAD, parse_packet
from .traceroute import build_trace_reply, parse_trace_packet

DEFAULT_INSTANCE_NAME = "echo-a"


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
        max_length=64,
        description="本回显实例名，诊断应答会带回该名字",
    )
    trace_mode: Literal["instance", "legacy"] = Field(
        default="instance",
        description="instance=诊断包回带实例名；legacy=原样回显诊断包（模拟旧端）",
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


class EchoProtocol:
    """回显协议：原样回送合法探测报文，按配置丢弃；诊断包按配置回带实例名。"""

    def __init__(self, state: EchoState, transport=None) -> None:  # noqa: ANN001
        self.state = state
        self.transport = transport
        self.echoed = 0
        self.dropped = 0
        self.trace_replied = 0
        self.trace_echoed = 0

    def connection_made(self, transport) -> None:  # noqa: ANN001
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        cfg = self.state.config
        if cfg.mode == "disconnect":
            self.dropped += 1
            return
        if cfg.drop_threshold is not None and len(data) > cfg.drop_threshold:
            self.dropped += 1
            return
        trace = parse_trace_packet(data)
        if trace is not None:
            if cfg.trace_mode == "legacy":
                self._send(data, addr)
                self.trace_echoed += 1
            else:
                self._send(
                    build_trace_reply(
                        trace.session_id, trace.seq, trace.nonce, cfg.instance_name
                    ),
                    addr,
                )
                self.trace_replied += 1
            return
        if parse_packet(data) is None:
            self.dropped += 1
            return
        self._send(data, addr)
        self.echoed += 1

    def _send(self, data: bytes, addr) -> None:  # noqa: ANN001
        assert self.transport is not None
        try:
            self.transport.sendto(data, addr)
        except OSError:
            # 回包发送失败（如对端已关闭）不应影响回显端继续工作
            self.dropped += 1

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass

    def connection_lost(self, exc: Optional[Exception]) -> None:  # pragma: no cover
        pass
