FROM telemetry-udp-probe:latest

# 演示拓扑需要：iproute2（建 netns/veth/路由）以及 NET_ADMIN。
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY demo/lab_topology.sh /usr/local/bin/lab_topology.sh
RUN chmod +x /usr/local/bin/lab_topology.sh

# 以 root 建网络命名空间，再启动 API
ENTRYPOINT ["/usr/local/bin/lab_topology.sh"]
