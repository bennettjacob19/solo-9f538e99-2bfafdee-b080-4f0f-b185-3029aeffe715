FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# iproute2: compose 演示中探针容器需要 `ip route` 指向真实路由器
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# 8000/tcp: HTTP API 与 /docs；9999/udp: 本地回显端
EXPOSE 8000/tcp 9999/udp

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/',timeout=2)" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
