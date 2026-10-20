#!/bin/sh
set -e

mkdir -p /var/log/backend /var/run/fail2ban

echo "[entrypoint] Iniciando Fail2Ban..."
# -x: fuerza el arranque aunque haya un socket viejo de un run anterior.
fail2ban-client -x start

# Da un respiro a fail2ban-server (arranca en background) antes de pedirle estado.
sleep 1
fail2ban-client status || true

echo "[entrypoint] Iniciando la app Flask..."
python app.py &
APP_PID=$!

# Al recibir SIGTERM (docker stop), apaga ambos limpiamente.
trap 'echo "[entrypoint] Deteniendo..."; fail2ban-client stop; kill $APP_PID 2>/dev/null' TERM INT

wait $APP_PID
