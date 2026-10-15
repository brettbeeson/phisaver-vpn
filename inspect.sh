#!/bin/bash
# Read-only survey of an OpenVPN host. Run on the server: sudo bash inspect.sh [OUTFILE]
# Writes a summary (no key material, only names/paths/permissions/fingerprints) to OUTFILE.
# Nothing on the system is modified; the only write is OUTFILE.
set -uo pipefail

out="${1:-openvpn-summary-$(hostname)-$(date +%Y%m%d-%H%M%S).txt}"
[ "$(id -u)" -eq 0 ] || { echo "run with sudo (needs to read /etc/openvpn)" >&2; exit 1; }

section() { printf '\n===== %s =====\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@" 2>&1 || true; }
sh_() { printf '$ %s\n' "$1"; bash -c "$1" 2>&1 || true; }

{
section "Host"
run hostname
sh_ 'grep PRETTY_NAME /etc/os-release'
run uname -r
sh_ 'date -u +%FT%TZ'
sh_ 'curl -s --max-time 3 https://checkip.amazonaws.com || echo "(no public ip lookup)"'
sh_ 'ip -br addr'
sh_ 'ip route'

section "OpenVPN packages and version"
sh_ "dpkg -l | awk '/openvpn|easy-rsa|resolvconf|ufw|iptables|netfilter|wireguard/ {print \$2, \$3}'"
sh_ 'openvpn --version | head -1'

section "OpenVPN services"
sh_ "systemctl list-units --all --no-legend 'openvpn*' 'easyrsa*'"
sh_ "systemctl list-unit-files --no-legend 'openvpn*' | head -20"
sh_ "ss -lunp | grep -i openvpn"
sh_ "ss -ltnp | grep -i openvpn"

section "/etc/openvpn tree (name, mode, owner, size)"
sh_ "find /etc/openvpn -printf '%M %u:%g %8s  %p\n' | sort -k4"

section "Config files (comments and blank lines stripped; inline <key>/<secret> blocks omitted)"
for f in $(find /etc/openvpn -maxdepth 2 -type f \( -name '*.conf' -o -name '*.ovpn' \) 2>/dev/null | sort); do
  printf '\n--- %s ---\n' "$f"
  awk '
    /^[[:space:]]*(#|;|$)/ { next }
    /^<(key|secret|tls-auth|tls-crypt|tls-crypt-v2|pkcs12|dh)>/ { skip=1; print "[" $0 " block omitted]"; next }
    /^<\/(key|secret|tls-auth|tls-crypt|tls-crypt-v2|pkcs12|dh)>/ { skip=0; next }
    !skip { print }
  ' "$f"
done

section "Certificates (subject, issuer, validity, SAN) -- public certs only"
for f in $(find /etc/openvpn /root /home -xdev -type f \( -name '*.crt' -o -name '*.pem' \) 2>/dev/null | grep -v private | sort); do
  if openssl x509 -in "$f" -noout 2>/dev/null; then
    printf '\n--- %s ---\n' "$f"
    openssl x509 -in "$f" -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName 2>&1
  fi
done

section "Private key files present (path, mode, type only -- contents NOT read)"
sh_ "find /etc/openvpn /root /home -xdev -type f \( -name '*.key' -o -path '*/private/*' -o -name 'ta.key' -o -name 'dh*.pem' \) -printf '%M %u:%g %8s  %p\n' 2>/dev/null | sort -k4"

section "easy-rsa / PKI locations"
sh_ "find / -xdev -type d \( -name easy-rsa -o -name easyrsa -o -name pki \) 2>/dev/null"
for d in $(find / -xdev -type d -name pki 2>/dev/null); do
  printf '\n--- %s ---\n' "$d"
  sh_ "ls -la '$d' '$d/issued' 2>/dev/null"
  [ -f "$d/index.txt" ] && { echo "index.txt (V=valid R=revoked):"; cat "$d/index.txt"; }
  [ -f "$d/vars" ] && grep -vE '^\s*(#|$)' "$d/vars"
done
sh_ "find / -xdev -name vars -path '*easy*' 2>/dev/null | xargs -r grep -hvE '^\s*(#|\$)'"

section "Client config files (names only)"
sh_ "find / -xdev -name '*.ovpn' -not -path '/proc/*' -printf '%M %u %s  %p\n' 2>/dev/null"
sh_ "ls -la /etc/openvpn/ccd /etc/openvpn/server/ccd 2>/dev/null"

section "Kernel forwarding"
sh_ 'sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding'
sh_ "grep -rHE 'ip_forward|forwarding' /etc/sysctl.conf /etc/sysctl.d 2>/dev/null"

section "Firewall / NAT"
sh_ 'ufw status verbose'
sh_ "grep -vE '^\s*(#|\$)' /etc/default/ufw | grep -E 'FORWARD|IPV6'"
sh_ "sed -n '1,40p' /etc/ufw/before.rules | grep -vE '^\s*#'"
sh_ 'iptables -t nat -S'
sh_ 'iptables -S'
sh_ 'nft list ruleset | head -80'
sh_ "ls -la /etc/iptables /etc/netfilter-persistent 2>/dev/null"
sh_ "dpkg -l | awk '/iptables-persistent|netfilter-persistent/ {print \$2}'"

section "Systemd unit overrides and DNS"
sh_ "ls -la /etc/systemd/system/openvpn* /etc/systemd/system/*openvpn*.d 2>/dev/null"
sh_ 'resolvectl status | head -30'
sh_ 'cat /etc/resolv.conf | grep -v "^#"'

section "Cron / timers touching VPN or PKI"
sh_ "crontab -l 2>/dev/null; ls /etc/cron.d; systemctl list-timers --no-legend | head"

section "Logs (last 30 lines, secrets-free)"
sh_ "journalctl -u 'openvpn*' --no-pager -n 30"
sh_ "ls -la /var/log/openvpn* 2>/dev/null"

section "Connected clients (status file)"
sh_ "find /var/log /run -maxdepth 3 -name '*status*' -path '*openvpn*' -exec cat {} \; 2>/dev/null | head -40"
} > "$out" 2>&1

chmod 600 "$out"
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER": "$out"
echo "Wrote $out ($(wc -l < "$out") lines). No key contents were read."
