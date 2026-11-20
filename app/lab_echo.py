"""实验室回显端：Compose 演示专用的独立 UDP 回显进程。

与 ``app.echo_server`` 共用回显逻辑，固定实例名，可选旧端行为（只原样回显）。
不对外提供 HTTP 配置接口，行为在启动参数中确定。

用法::

    python -m app.lab_echo --name echo-a --bind 10.99.0.10 --port 9999
    python -m app.lab_echo --name legacy --bind 10.99.0.12 --port 9999 --legacy
"""
from __future__ import annotations

import argparse
import asyncio
import signal
import socket

from .echo_server import EchoConfig, EchoProtocol, EchoState
from .netutil import set_dont_fragment


def sysctl_disable_rp_filter() -> None:
    """绑定非本地地址（演示拓扑）时关闭 rp_filter，避免回包被源地址校验丢弃。"""
    for path in (
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "/proc/sys/net/ipv4/conf/default/rp_filter",
    ):
        try:
            with open(path, "w", encoding="ascii") as fh:
                fh.write("0\n")
        except OSError:
            pass


async def serve(name: str, bind: str, port: int, legacy: bool) -> None:
    state = EchoState()
    state.config = EchoConfig(
        instance_name=name, trace_mode="legacy" if legacy else "instance"
    )
    state.epoch = 1  # 非默认行为已在启动时确定
    if bind not in ("0.0.0.0", ""):
        sysctl_disable_rp_filter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    set_dont_fragment(sock)
    sock.bind((bind, port))
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        lambda: EchoProtocol(state), sock=sock
    )
    print(
        f"lab-echo listening on {bind}:{port} instance={name!r} "
        f"trace_mode={state.config.trace_mode}",
        flush=True,
    )

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - 非 Unix
            pass
    try:
        await stop.wait()
    finally:
        transport.close()
        print(
            f"lab-echo stopped: replied={proto.trace_replied} "
            f"legacy_echoed={proto.trace_echoed} mtup_echoed={proto.echoed} "
            f"dropped={proto.dropped}",
            flush=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Compose 演示用 UDP 回显端")
    parser.add_argument("--name", required=True, help="实例名，诊断应答会带回")
    parser.add_argument("--bind", default="0.0.0.0", help="监听地址（演示中为虚拟目标 IP）")
    parser.add_argument("--port", type=int, default=9999, help="监听 UDP 端口")
    parser.add_argument(
        "--legacy", action="store_true", help="旧端行为：诊断包原样回显，不带实例名"
    )
    args = parser.parse_args()
    asyncio.run(serve(args.name, args.bind, args.port, args.legacy))


if __name__ == "__main__":
    main()
