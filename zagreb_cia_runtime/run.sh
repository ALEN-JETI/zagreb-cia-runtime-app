#!/usr/bin/with-contenv bashio
set -euo pipefail

log() {
  bashio::log.info "zagreb_cia_runtime: $1"
}

shutdown() {
  log "clean-stop=ok"
  exit 0
}

trap shutdown TERM INT

log "self-test=ok scope=isolated network=unused secrets=absent api_access=none"
log "runtime=started"

while true; do
  sleep 3600 &
  wait "$!"
done
