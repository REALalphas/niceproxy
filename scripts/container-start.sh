#!/bin/sh
set -eu
cd /app/web
export NICEPROXY_ALPHA_STATE_DIR="${NICEPROXY_ALPHA_STATE_DIR:-/data/ui}"
NICEPROXY_UI_DIR="$(node scripts/alpha-bootstrap.mjs --prepare)"
export NICEPROXY_UI_DIR
exec /usr/local/bin/niceproxy "$@"
