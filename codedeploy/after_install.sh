#!/bin/bash
set -euxo pipefail
id -u narcd >/dev/null || useradd --system --shell /sbin/nologin --no-create-home narcd
for d in /var/log/narcd /var/db/narcd; do
    mkdir -p "$d"
    chown -R narcd:narcd "$d"
done
setcap 'cap_net_bind_service=+ep' /opt/narcd/bin/narcd
