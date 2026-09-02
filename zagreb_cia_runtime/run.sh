#!/usr/bin/with-contenv bashio
set -euo pipefail

log() {
  bashio::log.info "zagreb_cia_runtime: $1"
}

log "self-test=ok scope=isolated network=otbr-read-only-on-demand secrets=absent api_access=none"
log "runtime=started"

exec python3 -u /cia_observer_dispatcher.py
