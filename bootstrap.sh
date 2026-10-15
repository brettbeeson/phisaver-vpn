#!/bin/bash
# Build the OpenVPN + dnsmasq server on Ubuntu. Idempotent.
# Run on the host after `vpn server push` has staged files in ~/vpn-stage:
#   server.conf update-vpn-hosts.sh dnsmasq-vpn.conf openvpn-override.conf
#   ca.crt server.crt server.key ta.key crl.pem [ipp.txt]
set -euo pipefail

STAGE="${STAGE:-$HOME/vpn-stage}"
CONF=/etc/openvpn/server
LIB=/var/lib/openvpn

for f in server.conf update-vpn-hosts.sh dnsmasq-vpn.conf openvpn-override.conf \
         ca.crt server.crt server.key ta.key crl.pem; do
  [ -f "$STAGE/$f" ] || { echo "missing $STAGE/$f; run 'vpn server push' first" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y openvpn dnsmasq

# Forwarding is not needed for client-to-client but matches the old server.
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-openvpn.conf >/dev/null
sudo sysctl --system >/dev/null

sudo install -d -m 0755 "$CONF"
sudo install -m 0644 "$STAGE/server.conf"        "$CONF/server.conf"
sudo install -m 0755 "$STAGE/update-vpn-hosts.sh" "$CONF/update-vpn-hosts.sh"
sudo install -m 0644 "$STAGE/ca.crt"             "$CONF/ca.crt"
sudo install -m 0644 "$STAGE/server.crt"         "$CONF/server.crt"
sudo install -m 0644 "$STAGE/crl.pem"            "$CONF/crl.pem"
sudo install -m 0600 "$STAGE/server.key"         "$CONF/server.key"
sudo install -m 0600 "$STAGE/ta.key"             "$CONF/ta.key"

# State dir is written by the hook after OpenVPN drops to nobody.
sudo install -d -o nobody -g nogroup -m 0755 "$LIB" "$LIB/hosts.d"
sudo touch "$LIB/vpn-hosts.lock" "$LIB/hosts.d/vpn-hosts"
sudo chown nobody:nogroup "$LIB/vpn-hosts.lock" "$LIB/hosts.d/vpn-hosts"
if [ -f "$STAGE/ipp.txt" ] && [ ! -s "$LIB/ipp.txt" ]; then
  sudo install -o nobody -g nogroup -m 0644 "$STAGE/ipp.txt" "$LIB/ipp.txt"
fi

sudo install -d /etc/systemd/system/openvpn-server@server.service.d
sudo install -m 0644 "$STAGE/openvpn-override.conf" \
  /etc/systemd/system/openvpn-server@server.service.d/override.conf

# systemd-resolved's stub holds 127.0.0.53:53; dnsmasq only binds 10.8.0.1.
sudo install -m 0644 "$STAGE/dnsmasq-vpn.conf" /etc/dnsmasq.d/vpn.conf

sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-server@server
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq

sleep 3
systemctl is-active openvpn-server@server dnsmasq
ip -br addr show tun0 || true
