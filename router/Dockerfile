# 真实 Linux 路由器：仅做 IPv4 转发与 TTL 超时 / 目的不可达应答。
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY start-router.sh /usr/local/bin/start-router.sh
RUN chmod +x /usr/local/bin/start-router.sh

ENTRYPOINT ["/usr/local/bin/start-router.sh"]
