#!/bin/bash
set -e
export LC_ALL=C
cd /home/satc/SaTC
# SaTC's front-end parser needs its local Node service. No host port is published.
npm --prefix /home/satc/SaTC/jsparse run start >/tmp/satc-jsparse.log 2>&1 &
ready=false
for attempt in {1..100}; do
    if (echo > /dev/tcp/127.0.0.1/3000) 2>/dev/null; then
        ready=true
        break
    fi
    sleep 0.1
done
if [ "$ready" != true ]; then
    cat /tmp/satc-jsparse.log >&2
    exit 1
fi
exec "$@"
