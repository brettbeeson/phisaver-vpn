#!/bin/bash
# OpenVPN learn-address hook.
# Maintains hostname -> VPN IP mappings for dnsmasq.
#
# dnsmasq watches hostsdir automatically, so no reload/SIGHUP is required.
#
# Multiple clients may reconnect simultaneously, so flock serialises
# updates and prevents concurrent writers corrupting vpn-hosts.
#
# This is convenience bookkeeping only. It must NEVER break VPN routing,
# so any failure is logged and the script always returns 0 to OpenVPN.
set -u

ACTION="${1:-}"
IP="${2:-}"
NAME="${3:-}"

# dnsmasq.conf references 'hostsdir=/var/lib/openvpn/hosts.d'; vpn-hosts lives there.
HOSTS=/var/lib/openvpn/hosts.d/vpn-hosts
LOCK=/var/lib/openvpn/vpn-hosts.lock

update_hosts()
{
    # Exclusive lock; concurrent hook invocations wait here.
    exec 9>"$LOCK"
    flock -w 10 9 || return 1

    tmp=$(mktemp "${HOSTS}.XXXXXX") || return 1

    case "$ACTION" in
        add|update)
            [ -n "$NAME" ] || return 1
            sed -E \
                "/[[:space:]]${NAME}([[:space:]]|$)/d; /^${IP}[[:space:]]/d" \
                "$HOSTS" > "$tmp" || return 1
            echo "$IP $NAME $NAME.vpn" >> "$tmp" || return 1
            ;;
        delete)
            sed -E \
                "/^${IP}[[:space:]]/d" \
                "$HOSTS" > "$tmp" || return 1
            ;;
        *)
            rm -f "$tmp"
            return 1
            ;;
    esac

    chmod 0644 "$tmp" || return 1
    mv "$tmp" "$HOSTS" || return 1
}

if update_hosts; then
    logger -t openvpn-learn-address \
        "INFO: vpn-hosts updated: action=$ACTION ip=$IP name=${NAME:-<none>}"
else
    logger -t openvpn-learn-address \
        "WARNING: vpn-hosts update failed: action=$ACTION ip=$IP name=${NAME:-<none>}"
fi

# Fail open: never let DNS bookkeeping reject an OpenVPN client route.
exit 0
