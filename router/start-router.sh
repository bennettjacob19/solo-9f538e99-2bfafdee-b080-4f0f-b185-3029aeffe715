#!/bin/sh
# 真实 Linux 路由器容器入口：开启 IPv4 转发，并放行两个子网之间的转发。
# Docker 默认 DOCKER-USER 链会拒绝跨用户网络的转发，这里显式放行。
set -eu

echo 1 > /proc/sys/net/ipv4/ip_forward

# 兼容 iptables-nft 与 iptables-legacy；规则已存在时忽略报错
iptables -I DOCKER-USER -s 172.30.0.0/16 -d 10.1.0.0/24 -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -s 10.1.0.0/24 -d 172.30.0.0/16 -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -s 172.30.0.0/16 -d 10.1.0.0/24 -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -s 10.1.0.0/24 -d 172.30.0.0/16 -j ACCEPT 2>/dev/null || true

echo "[router] IPv4 forwarding enabled; routes:"
ip route

# 常驻：路由器本身不提供业务服务，仅做转发与 TTL 超时应答
exec tail -f /dev/null
