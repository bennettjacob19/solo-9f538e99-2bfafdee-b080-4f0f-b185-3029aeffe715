FROM python:3.12-slim AS app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# 8000/tcp: HTTP API 与 /docs；9999/udp: 本地回显端
EXPOSE 8000/tcp 9999/udp

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/',timeout=2)" || exit 1

# 逐跳诊断使用普通 UDP socket 的 IP_RECVERR 错误队列读取 ICMP，无需 root。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


# 演示镜像：额外安装 iproute2，启动时用网络命名空间搭出真实 IPv4 路由器路径。
FROM app AS lab

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY demo/lab_topology.sh /usr/local/bin/lab_topology.sh
RUN chmod +x /usr/local/bin/lab_topology.sh

ENTRYPOINT ["/usr/local/bin/lab_topology.sh"]
