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
sh_ "if command -v dpkg >/dev/null; then dpkg -l | awk '/openvpn|easy-rsa|resolvconf|ufw|iptables|netfilter|wireguard/ {print \$2, \$3}'; else rpm -qa | grep -Ei 'openvpn|easy-rsa|iptables|wireguard' | sort; fi"
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

section "Certificates (subject, issuer, validity, fingerprint) -- public certs only"
# Scoped to OpenVPN/PKI dirs; skips package test fixtures. Summarised one line per cert.
cert_dirs=$(find /etc/openvpn /root /home -xdev -type d \( -name pki -o -name keys -o -name issued -o -name openvpn \) \
  -not -path '*/site-packages/*' -not -path '*/.local/*' 2>/dev/null | sort)
cert_files=$( { find /etc/openvpn -maxdepth 2 -type f \( -name '*.crt' -o -name '*.pem' \) 2>/dev/null
  for d in $cert_dirs; do find "$d" -maxdepth 2 -type f -name '*.crt' 2>/dev/null; done; } | sort -u)
echo "cert files considered: $(echo "$cert_files" | grep -c .)"
echo "--- server/CA certs in full ---"
for f in /etc/openvpn/*.crt; do
  [ -f "$f" ] || continue
  printf '\n--- %s ---\n' "$f"
  openssl x509 -in "$f" -noout -subject -issuer -dates -serial -fingerprint -sha256 2>&1 | head -10
  openssl x509 -in "$f" -noout -text 2>/dev/null | grep -E 'Public-Key|Signature Algorithm|CA:|Key Usage|TLS Web|DNS:|IP Address:' | sort -u
done
echo
echo "--- all other certs: CN | notAfter | issuer CN ---"
for f in $cert_files; do
  case "$f" in /etc/openvpn/*.crt) continue ;; esac
  openssl x509 -in "$f" -noout 2>/dev/null || continue
  cn=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,\/]*\).*/\1/p')
  na=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2)
  ic=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed -n 's/.*CN *= *\([^,\/]*\).*/\1/p')
  printf '%s | %s | %s | %s\n' "$cn" "$na" "$ic" "$f"
done

section "Private key files present (path, mode, type only -- contents NOT read)"
sh_ "find /etc/openvpn /root /home -xdev -type f -not -path '*/site-packages/*' \( -name '*.key' -o -path '*/private/*' -o -name 'ta.key' -o -name 'dh*.pem' \) -printf '%M %u:%g %8s  %p\n' 2>/dev/null | sort -k4"

section "easy-rsa / PKI locations"
sh_ "find / -xdev -type d \( -name easy-rsa -o -name easyrsa -o -name pki \) -not -path '*/site-packages/*' -not -path '/usr/*' -not -path '/etc/pki' -not -path '/etc/selinux/*' 2>/dev/null"
for d in $(find / -xdev -type d -name pki -not -path '*/site-packages/*' -not -path '/usr/*' -not -path '/etc/pki' -not -path '/etc/selinux/*' 2>/dev/null); do
  printf '\n--- %s ---\n' "$d"
  sh_ "ls -la '$d' '$d/issued' 2>/dev/null"
  [ -f "$d/index.txt" ] && { echo "index.txt (V=valid R=revoked):"; cat "$d/index.txt"; }
  [ -f "$d/vars" ] && grep -vE '^\s*(#|$)' "$d/vars"
done
sh_ "find / -xdev -name vars -path '*easy*' -not -path '*/site-packages/*' 2>/dev/null | xargs -r grep -hvE '^\s*(#|\$)'"
sh_ "find / -xdev \( -name index.txt -o -name ca.key -o -name crl.pem -o -name serial \) -not -path '*/site-packages/*' -not -path '/usr/*' -not -path '/proc/*' -printf '%M %u %s  %p\n' 2>/dev/null"

section "Client config files (summary)"
sh_ "find / -xdev -name '*.ovpn' -not -path '/usr/*' -not -path '/proc/*' -printf '%h\n' 2>/dev/null | sort | uniq -c"
sh_ "ls -la /etc/openvpn/ccd /etc/openvpn/server/ccd 2>/dev/null"
# One sample client config with inline key/cert/tls blocks stripped, as a template for regeneration.
sample=$(find /home /root -xdev -name '*.ovpn' -not -path '*/site-packages/*' 2>/dev/null | sort | head -1)
if [ -n "$sample" ]; then
  printf '\n--- sample client config: %s (inline blocks omitted) ---\n' "$sample"
  awk '
    /^[[:space:]]*(#|;|$)/ { next }
    /^<(key|cert|ca|secret|tls-auth|tls-crypt|tls-crypt-v2|pkcs12|dh)>/ { skip=1; print "[" $0 " block omitted]"; next }
    /^<\/(key|cert|ca|secret|tls-auth|tls-crypt|tls-crypt-v2|pkcs12|dh)>/ { skip=0; next }
    !skip { print }
  ' "$sample"
fi
echo
echo "--- client names (from .ovpn files and issued keys) ---"
find /home /root -xdev \( -name '*.ovpn' -o -path '*/keys/*.crt' \) -not -path '*/site-packages/*' -printf '%f\n' 2>/dev/null \
  | sed -E 's/\.(ovpn|crt)$//' | sort -u | tr '\n' ' '
echo

section "Hook scripts and persistent IP pool (no secrets)"
sh_ "cat /etc/openvpn/update-vpn-hosts.sh"
sh_ "ls -la /etc/openvpn/*.sh /etc/openvpn/*.swp 2>/dev/null"
sh_ "cat /etc/openvpn/ipp.txt"
sh_ "grep -vE '^\s*(#|\$)' /etc/hosts | head -300"
sh_ "grep -rl 'vpn' /etc/cron* /var/spool/cron /etc/rc.d/rc.local /etc/profile.d 2>/dev/null"

section "DNS (dnsmasq), vpn-hosts and key fingerprints"
sh_ "rpm -q dnsmasq 2>&1; systemctl is-enabled dnsmasq 2>&1; systemctl is-active dnsmasq 2>&1"
sh_ "grep -hvE '^\s*(#|\$)' /etc/dnsmasq.conf /etc/dnsmasq.d/* 2>/dev/null"
sh_ "ss -lunp | grep -i dnsmasq"
sh_ "ls -laR /var/lib/openvpn 2>&1 | head -40"
sh_ "wc -l /var/lib/openvpn/hosts.d/* 2>&1; head -20 /var/lib/openvpn/hosts.d/vpn-hosts 2>&1"
sh_ "systemctl cat dnsmasq 2>/dev/null | head -30"
# Fingerprints only (sha256 of file bytes, key material is not printed) to confirm local pki/ matches.
sh_ "sha256sum /etc/openvpn/ta.key /etc/openvpn/dh.pem /home/*/vpn-server/ta.key /home/*/vpn-server/pki/dh.pem 2>&1 | awk '{print substr(\$1,1,16), \$2}'"
sh_ "openssl dhparam -in /etc/openvpn/dh.pem -noout -text 2>&1 | head -2"
sh_ "openssl x509 -in /etc/openvpn/live.crt -noout -modulus | sha256sum | cut -c1-16; openssl rsa -in /etc/openvpn/server.key -noout -modulus 2>/dev/null | sha256sum | cut -c1-16"
sh_ "ls -la /home/*/vpn-server /home/*/vpn-server/files 2>/dev/null | grep -v '\.ovpn\$' | head -60"
sh_ "ls /home/*/vpn-server/keys 2>/dev/null | grep -vE '\.(crt|key)\$' | head"
section "Legacy issue scripts (no keys)"
for f in /home/*/vpn-server/*.sh /home/*/vpn-server/*.conf /home/*/vpn-server/*.tpl /home/*/vpn-server/*.template; do
  [ -f "$f" ] || continue
  printf '\n--- %s ---\n' "$f"
  grep -vE '^\s*(#|$)' "$f" | awk '/^<(key|secret|tls-auth|cert|ca)>/{s=1;print "[block omitted]";next}/^<\/(key|secret|tls-auth|cert|ca)>/{s=0;next}!s{print}'
done

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
sh_ "ls -la /etc/iptables /etc/netfilter-persistent /etc/sysconfig/iptables 2>/dev/null; cat /etc/sysconfig/iptables 2>/dev/null"
sh_ "systemctl is-enabled iptables netfilter-persistent 2>&1"

section "Systemd unit overrides and DNS"
sh_ "ls -la /etc/systemd/system/openvpn* /etc/systemd/system/*openvpn*.d 2>/dev/null"
sh_ 'resolvectl status | head -30'
sh_ 'cat /etc/resolv.conf | grep -v "^#"'

section "Cron / timers touching VPN or PKI"
sh_ "crontab -l 2>/dev/null; ls /etc/cron.d; systemctl list-timers --no-legend | head"

section "Logs (last 30 lines, secrets-free)"
sh_ "journalctl -u 'openvpn*' --no-pager -n 200 | grep -v 'peer info' | tail -25"
sh_ "systemctl cat openvpn@server 2>/dev/null | head -40"
sh_ "ls -la /var/log/openvpn* 2>/dev/null"

section "Connected clients (status file)"
sh_ "find /var/log /run -maxdepth 3 -name '*status*' -path '*openvpn*' -exec cat {} \; 2>/dev/null | head -40"
} > "$out" 2>&1

chmod 600 "$out"
[ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER": "$out"
echo "Wrote $out ($(wc -l < "$out") lines). No key contents were read."
