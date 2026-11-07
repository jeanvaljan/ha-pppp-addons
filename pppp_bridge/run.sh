#!/usr/bin/with-contenv bashio
IP=$(bashio::config 'camera_ip')
ARGS=(-u "$(bashio::config 'username')" -p "$(bashio::config 'password')" --port "$(bashio::config 'port')" --log-level "$(bashio::config 'log_level')")
[ -n "$IP" ] && ARGS+=(-a "$IP")
bashio::log.info "Pornesc bridge PPPP (camera: ${IP:-broadcast}, port: $(bashio::config 'port'))"
exec /opt/pppp/bin/python -m aiopppp "${ARGS[@]}"
