#!/usr/bin/with-contenv bashio
set +e +u +o pipefail
IP=$(bashio::config 'camera_ip')
PORT=$(bashio::config 'port')
WD=$(bashio::config 'watchdog_interval')
ARGS=(-u "$(bashio::config 'username')" -p "$(bashio::config 'password')" --port "$PORT" --log-level "$(bashio::config 'log_level')")
[ -n "$IP" ] && ARGS+=(-a "$IP")

start_bridge() {
  bashio::log.info "Pornesc bridge PPPP (camera: ${IP:-broadcast}, port: $PORT)"
  /opt/pppp/bin/python -m aiopppp "${ARGS[@]}" &
  PID=$!
}

trap 'kill $PID 2>/dev/null; exit 0' TERM INT
start_bridge
sleep 30
FAILS=0
while true; do
  sleep "$WD" & wait $!
  if ! kill -0 "$PID" 2>/dev/null; then
    bashio::log.warning "Bridge oprit, repornesc"
    start_bridge; FAILS=0; sleep 30; continue
  fi
  DEVS=$(curl -s --max-time 5 "http://127.0.0.1:$PORT/" | grep -o '<h2>[^<]*</h2>' | sed 's/<[^>]*>//g')
  OK=0
  for d in $DEVS; do
    B=$(curl -s --max-time 6 -o /dev/null -w '%{size_download}' "http://127.0.0.1:$PORT/$d/v")
    [ "${B:-0}" -gt 20000 ] && OK=1
  done
  if [ "$OK" = 1 ]; then FAILS=0; else FAILS=$((FAILS+1)); bashio::log.warning "Watchdog: fără video (${FAILS}/3)"; fi
  if [ "$FAILS" -ge 3 ]; then
    bashio::log.warning "Watchdog: repornesc bridge-ul"
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
    start_bridge; FAILS=0; sleep 30
  fi
done
