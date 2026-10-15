#!/bin/bash
# Build and harden the OpenVPN + dnsmasq server on Ubuntu. Safe to re-run: files are only
# rewritten when they differ and OpenVPN is restarted only when its own config changed.
# Run on the host after `vpn server push` has staged files in ~/vpn-stage:
#   server.conf update-vpn-hosts.sh dnsmasq-vpn.conf openvpn-override.conf
#   ca.crt server.crt server.key ta.key crl.pem [ipp.txt]
# The staged copies (which include private keys) are removed at the end unless KEEP_STAGE=1.
set -euo pipefail

STAGE="${STAGE:-$HOME/vpn-stage}"
CONF=/etc/openvpn/server
LIB=/var/lib/openvpn
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-vpn-hardening.conf
SSH_USERS="${SSH_USERS:-$(printf '%s\n' ubuntu "$(id -un)" | sort -u | tr '\n' ' ')}"
# Post-quantum hybrids first, then one well-vetted classical exchange for older clients.
KEX_WANTED="mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com curve25519-sha256"

for f in server.conf update-vpn-hosts.sh dnsmasq-vpn.conf openvpn-override.conf \
         ca.crt server.crt server.key ta.key crl.pem; do
  [ -f "$STAGE/$f" ] || { echo "missing $STAGE/$f; run 'vpn server push' first" >&2; exit 1; }
done

# put MODE SRC DST: install only if the content differs; returns 0 when it changed something.
put() {
  local mode=$1 src=$2 dst=$3
  if sudo cmp -s "$src" "$dst" 2>/dev/null; then
    sudo chmod "$mode" "$dst"
    return 1
  fi
  sudo install -m "$mode" "$src" "$dst"
}

RESTART=0   # OpenVPN needs a restart (identity, keys, config or unit changed)
DAEMON_RELOAD=0

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq openvpn

# State dir is written by the hook after OpenVPN drops to nobody.
sudo install -d -o nobody -g nogroup -m 0755 "$LIB" "$LIB/hosts.d"
sudo touch "$LIB/vpn-hosts.lock" "$LIB/hosts.d/vpn-hosts"
sudo chown nobody:nogroup "$LIB/vpn-hosts.lock" "$LIB/hosts.d/vpn-hosts"

# Write dnsmasq's config before installing it: the package starts the service on install and,
# with its default config, would fight systemd-resolved for port 53 and fail.
sudo install -d -m 0755 /etc/dnsmasq.d
DNSMASQ_CHANGED=0
if put 0644 "$STAGE/dnsmasq-vpn.conf" /etc/dnsmasq.d/vpn.conf; then DNSMASQ_CHANGED=1; fi
sudo apt-get install -y -qq dnsmasq

# Client-to-client traffic is switched inside OpenVPN; the kernel does not forward.
sudo rm -f /etc/sysctl.d/99-openvpn.conf
sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null

sudo install -d -m 0755 "$CONF"
if put 0644 "$STAGE/server.conf" "$CONF/server.conf"; then RESTART=1; fi
if put 0644 "$STAGE/ca.crt" "$CONF/ca.crt"; then RESTART=1; fi
if put 0644 "$STAGE/server.crt" "$CONF/server.crt"; then RESTART=1; fi
if put 0600 "$STAGE/server.key" "$CONF/server.key"; then RESTART=1; fi
if put 0600 "$STAGE/ta.key" "$CONF/ta.key"; then RESTART=1; fi
# The hook is exec'd per event and the CRL is re-read per connection: neither needs a restart.
put 0755 "$STAGE/update-vpn-hosts.sh" "$CONF/update-vpn-hosts.sh" || true
put 0644 "$STAGE/crl.pem" "$CONF/crl.pem" || true

# Seed the address pool only on first install; OpenVPN owns the file afterwards.
if [ -f "$STAGE/ipp.txt" ] && [ ! -s "$LIB/ipp.txt" ]; then
  sudo install -o nobody -g nogroup -m 0644 "$STAGE/ipp.txt" "$LIB/ipp.txt"
fi

sudo install -d /etc/systemd/system/openvpn-server@server.service.d
if put 0644 "$STAGE/openvpn-override.conf" \
     /etc/systemd/system/openvpn-server@server.service.d/override.conf; then
  DAEMON_RELOAD=1
  RESTART=1
fi

# --- SSH hardening -----------------------------------------------------------
# Offer only the key exchanges this sshd supports, so one unknown name can't break sshd.
kex=""
for alg in $KEX_WANTED; do
  if ssh -Q kex | grep -qx "$alg"; then kex="${kex:+$kex,}$alg"; fi
done
case "$kex" in
  *curve25519-sha256*) ;;
  *) echo "sshd lacks curve25519-sha256; refusing to write a KexAlgorithms list" >&2; exit 1 ;;
esac

sshd_tmp=$(mktemp)
cat > "$sshd_tmp" <<SSHD
# Managed by bootstrap.sh. Named 00- so it is read before cloud-init's 50- file (first value wins).
KexAlgorithms $kex
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
X11Forwarding no
AllowUsers $SSH_USERS
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
SSHD
if sudo cmp -s "$sshd_tmp" "$SSHD_DROPIN" 2>/dev/null; then
  echo "sshd hardening unchanged (KexAlgorithms $kex)"
else
  sudo cp -a "$SSHD_DROPIN" "$SSHD_DROPIN.prev" 2>/dev/null || true
  sudo install -m 0644 "$sshd_tmp" "$SSHD_DROPIN"
  if sudo sshd -t; then
    sudo systemctl reload ssh || sudo systemctl restart ssh
    echo "sshd hardening applied (KexAlgorithms $kex)"
  else
    echo "sshd -t rejected the hardening file; reverting" >&2
    if [ -f "$SSHD_DROPIN.prev" ]; then sudo mv "$SSHD_DROPIN.prev" "$SSHD_DROPIN"; else sudo rm -f "$SSHD_DROPIN"; fi
    exit 1
  fi
fi
sudo rm -f "$SSHD_DROPIN.prev" "$sshd_tmp"

# --- services ----------------------------------------------------------------
[ "$DAEMON_RELOAD" = 1 ] && sudo systemctl daemon-reload
sudo systemctl enable openvpn-server@server dnsmasq >/dev/null 2>&1
if systemctl is-active --quiet openvpn-server@server; then
  if [ "$RESTART" = 1 ]; then
    echo "OpenVPN config changed; restarting (clients reconnect within a minute)"
    sudo systemctl restart openvpn-server@server
  fi
else
  sudo systemctl start openvpn-server@server
fi
# dnsmasq reads hosts.d live; restart only when its config changed or it is not running.
if [ "$DNSMASQ_CHANGED" = 1 ] || ! systemctl is-active --quiet dnsmasq; then
  sudo systemctl restart dnsmasq
fi

sleep 3
systemctl is-active openvpn-server@server dnsmasq
ip -br addr show tun0 || true

# --- cleanup -------------------------------------------------------------------
if [ "${KEEP_STAGE:-0}" != 1 ]; then
  shred -u "$STAGE/server.key" "$STAGE/ta.key" 2>/dev/null || true
  rm -rf "$STAGE"
  echo "removed staged files ($STAGE)"
fi
