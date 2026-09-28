#!/bin/bash
# Detaches XDP programs from all interfaces listed in the XDP Firewall config.
# The firewall detaches itself when it exits cleanly; the systemd service runs this as a fallback (e.g. after a crash).
CFG="${1:-/etc/xdpfw/xdpfw.conf}"

if [ ! -f "$CFG" ]; then
    exit 0
fi

# Strip comments, join lines, and extract the interface setting (a single string or a list of strings).
interfaces=$(sed -e 's|//.*$||' -e 's|#.*$||' "$CFG" | tr '\n' ' ' | grep -oE '(^|[;{[:space:]])interface[[:space:]]*[=:][[:space:]]*(\([^)]*\)|"[^"]*")' | grep -oE '"[^"]+"' | tr -d '"')

for iface in $interfaces; do
    ip link set dev "$iface" xdp off 2>/dev/null
    ip link set dev "$iface" xdpgeneric off 2>/dev/null
done

exit 0
