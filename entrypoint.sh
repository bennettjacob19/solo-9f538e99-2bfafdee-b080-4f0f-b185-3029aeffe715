#!/bin/sh
# 容器入口：
# - 探针容器（默认）：先把发往 echo 子网的路由指向真实路由器，再启动 uvicorn；
# - 回显实例容器（SKIP_ROUTE_SETUP=1）：直接启动 uvicorn。
set -eu

if [ "${SKIP_ROUTE_SETUP:-0}" != "1" ]; then
    ROUTER_IP="${ROUTER_IP:-172.30.0.1}"
    ECHO_SUBNET="${ECHO_SUBNET:-10.1.0.0/24}"

    i=1
    while [ "$i" -le 10 ]; do
        if ip route replace "$ECHO_SUBNET" via "$ROUTER_IP" dev eth0 2>/dev/null; then
            echo "[entrypoint] route $ECHO_SUBNET via $ROUTER_IP installed"
            break
        fi
        echo "[entrypoint] waiting for networking ($i)..."
        i=$((i + 1))
        sleep 0.5
    done
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
