#!/usr/bin/with-contenv bashio
set +e +u +o pipefail
export TCP_HOST="$(bashio::config 'tcp_host')"
export TCP_PORT="$(bashio::config 'tcp_port')"
export TCP_CAPTURE="$(bashio::config 'tcp_capture')"
export MODE="$(bashio::config 'mode')"
export UPSTREAM_HTTP="$(bashio::config 'upstream_http')"
export UPSTREAM_TCP="$(bashio::config 'upstream_tcp')"
export AUTO_STREAM="$(bashio::config 'auto_stream')"
export MAX_STREAM="$(bashio::config 'max_stream')"
export LOG_LEVEL="$(bashio::config 'log_level')"
bashio::log.info "Pornesc Naxclow Local (mod ${MODE}, HTTP :80, TCP :${TCP_PORT})"
exec python3 /server.py
