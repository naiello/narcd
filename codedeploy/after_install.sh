#!/bin/bash
set -euxo pipefail
id -u narcd >/dev/null || useradd --system --shell /sbin/nologin --no-create-home narcd
for d in /var/log/narcd /var/db/narcd; do
    mkdir -p "$d"
    chown -R narcd:narcd "$d"
done
setcap 'cap_bpf,cap_perfmon,cap_net_admin,cap_net_bind_service=+eip' /opt/narcd/bin/narcd

# Set network interface settings for compatibility with XDP
iface=$(ip route get 1.1.1.1 | sed -n 's/.*dev \([^\ ]*\).*/\1/p')
ip link set dev "${iface}" mtu 1500
ethtool -L "${iface}" combined 1

systemctl daemon-reload
