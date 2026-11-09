#!/usr/bin/with-contenv bashio
set +e +u +o pipefail
export TCP_HOST="$(bashio::config 'tcp_host')"
export TCP_PORT="$(bashio::config 'tcp_port')"
export TCP_CAPTURE="$(bashio::config 'tcp_capture')"
export LOG_LEVEL="$(bashio::config 'log_level')"
bashio::log.info "Pornesc Naxclow Local (HTTP :80, TCP :${TCP_PORT})"
exec python3 /server.py
