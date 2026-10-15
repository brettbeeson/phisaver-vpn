#!/bin/bash
set -euo pipefail

# Install OpenVPN
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y openvpn openvpn-systemd-resolved resolvconf
