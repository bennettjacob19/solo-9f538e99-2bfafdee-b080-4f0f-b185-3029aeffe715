#!/bin/sh
# Compose 演示拓扑：用 Linux 网络命名空间搭出真实的 IPv4 转发路径。
#
#   probe(172.30.0.2) --veth-- r1(172.30.0.1 / 10.1.0.1) --veth-- r2(10.1.0.2 / 192.0.2.1)
#                                                                     |
#                                                    bridge 192.0.2.0/24
#                                                      |        |        |       |
#                                                   echo-a   echo-b  echo-legacy  void
#                                                   .10       .11       .12      .99
#
# 中间跳是真正的内核路由器（ip_forward=1），ICMP TTL 超时由它们自己回送；
# probe 本体运行在容器默认命名空间（最左侧客户端），回显实例运行在各自命名空间。
# 建立 netns 需要 CAP_SYS_ADMIN；veth/路由/网桥需要 CAP_NET_ADMIN。
# 权限不足时脚本会打印警告并降级：只保留本地回显（127.0.0.1:9999）。
set -u

PY=python
PIDS=""

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

warn() {
    echo "[lab] 警告: $*" >&2
}

setup() {
    ip netns add r1 2>/dev/null || return 1
    ip netns exec r1 ip link set lo up
    for ns in r2 echo-a echo-b echo-legacy void; do
        ip netns add "$ns" 2>/dev/null || return 1
        ip netns exec "$ns" ip link set lo up
    done

    # 客户端 <-> r1
    ip link add cli0 type veth peer name r1in || return 1
    ip addr add 172.30.0.2/24 dev cli0
    ip link set cli0 up
    ip link set r1in netns r1
    ip netns exec r1 ip addr add 172.30.0.1/24 dev r1in
    ip netns exec r1 ip link set r1in up
    ip route add 192.0.2.0/24 via 172.30.0.1

    # r1 <-> r2
    ip link add r1out type veth peer name r2in || return 1
    ip link set r1out netns r1
    ip link set r2in netns r2
    ip netns exec r1 ip addr add 10.1.0.1/24 dev r1out
    ip netns exec r1 ip link set r1out up
    ip netns exec r2 ip addr add 10.1.0.2/24 dev r2in
    ip netns exec r2 ip link set r2in up
    ip netns exec r1 ip route add 192.0.2.0/24 via 10.1.0.2
    ip netns exec r2 ip route add 172.30.0.0/24 via 10.1.0.1

    for ns in r1 r2; do
        ip netns exec "$ns" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' || return 1
        ip netns exec "$ns" sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'
        ip netns exec "$ns" sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects'
        ip netns exec "$ns" sh -c 'echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects'
    done

    # r2 上的目标网段
    ip netns exec r2 ip link add br0 type bridge || return 1
    ip netns exec r2 ip addr add 192.0.2.1/24 dev br0
    ip netns exec r2 ip link set br0 up

    attach_target echo-a veth-ea 192.0.2.10 || return 1
    attach_target echo-b veth-eb 192.0.2.11 || return 1
    attach_target echo-legacy veth-el 192.0.2.12 || return 1
    attach_target void veth-void 192.0.2.99 || return 1  # 有地址、无监听 → 端口不可达

    ip netns exec echo-a $PY -m app.lab_echo --name echo-a --bind 192.0.2.10 --port 9999 &
    PIDS="$PIDS $!"
    ip netns exec echo-b $PY -m app.lab_echo --name echo-b --bind 192.0.2.11 --port 9999 &
    PIDS="$PIDS $!"
    ip netns exec echo-legacy $PY -m app.lab_echo --name legacy --bind 192.0.2.12 \
        --port 9999 --legacy &
    PIDS="$PIDS $!"

    echo "[lab] 拓扑就绪：客户端 172.30.0.2 → 中间跳 172.30.0.1 / 10.1.0.2 → 目标 192.0.2.0/24"
    return 0
}

attach_target() {
    # $1 命名空间  $2 r2 侧接口名  $3 目标地址
    ip link add "$2" type veth peer name eth0 || return 1
    ip link set "$2" netns r2
    ip link set eth0 netns "$1"
    ip netns exec r2 ip link set "$2" master br0
    ip netns exec r2 ip link set "$2" up
    ip netns exec "$1" ip addr add "$3/24" dev eth0
    ip netns exec "$1" ip link set eth0 up
    ip netns exec "$1" ip route add default via 192.0.2.1
}

if [ "${ALLOW_TOPOLOGY:-1}" = "1" ]; then
    if ! setup; then
        warn "演示拓扑搭建失败（需要 NET_ADMIN + SYS_ADMIN）"
        warn "仅本地回显可用：/trace 目标 127.0.0.1:9999；详见 README「权限说明」"
    fi
else
    echo "[lab] ALLOW_TOPOLOGY=0：跳过演示拓扑，仅本地回显"
fi

echo "[lab] 启动 API：http://localhost:8000/docs"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
