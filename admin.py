"""Administer the OpenVPN PKI and server: issue/revoke clients, push server files, read DNS hosts.

pki/ and issued/ are symlinks to private storage; nothing secret lives in this repo.
"""

import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent
PKI = Path(os.environ.get("VPN_PKI", REPO / "pki"))
ISSUED = Path(os.environ.get("VPN_ISSUED", REPO / "issued"))
EASYRSA = REPO / "easyrsa"
OVPN_TEMPLATE = REPO / "client.ovpn.tpl"
SERVER_FILES = REPO / "server"
BOOTSTRAP = REPO / "bootstrap.sh"

DEFAULT_HOST = "live.phisaver.com"  # the current server; override with VPN_HOST
DEFAULT_SERVER_CN = "vpnserver"
STAGE_DIR = "vpn-stage"
HOSTS_PATH = "/var/lib/openvpn/hosts.d/vpn-hosts"
MANAGEMENT_PORT = 7505

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class VPNError(RuntimeError):
    """A VPN administration step could not be completed."""


def validate_name(name: str) -> str:
    if not _NAME.fullmatch(name):
        raise VPNError("name may contain only letters, digits, '.', '_' and '-' and must not start with punctuation")
    return name


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, **kwargs)


def easyrsa(*args: str) -> None:
    _run([str(EASYRSA), "--batch", *args], cwd=REPO, env={**os.environ, "EASYRSA_PKI": str(PKI)})


def require_ca() -> None:
    ca_key = PKI / "private" / "ca.key"
    if not ca_key.is_file() or not os.access(ca_key, os.R_OK):
        raise VPNError(f"CA key unavailable at {ca_key}; link pki/ to the private PKI first")


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(text)
    os.chmod(path, 0o600)


# --- index -----------------------------------------------------------------

def parse_index(text: str) -> list[dict[str, str]]:
    """Parse EasyRSA index.txt rows: status V/R/E, expiry, serial, CN."""
    rows = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        cn = re.search(r"/CN=([^/]+)", parts[5])
        stamp = parts[1].removesuffix("Z")
        expires = datetime.strptime(stamp, "%y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        rows.append(
            {"status": parts[0], "expires": expires.strftime("%Y-%m-%d"), "serial": parts[3], "name": cn.group(1) if cn else "?"}
        )
    return rows


def list_clients() -> list[dict[str, str]]:
    return sorted(parse_index((PKI / "index.txt").read_text()), key=lambda r: r["name"])


# --- client certificates ---------------------------------------------------

def build_ovpn(name: str, ca: str, cert: str, key: str, ta: str, remote: str) -> str:
    """Assemble a self-contained client config (same layout as the legacy make_ovpn.sh)."""
    base = OVPN_TEMPLATE.read_text().replace("{remote}", remote)

    def block(tag: str, body: str) -> str:
        return f"<{tag}>\n{body.strip()}\n</{tag}>\n"

    return base + block("ca", ca) + block("cert", _pem_cert(cert)) + block("key", key) + block("tls-auth", ta)


def _pem_cert(text: str) -> str:
    """Strip openssl's human-readable preamble, leaving only the PEM block."""
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if not match:
        raise VPNError("no PEM certificate found")
    return match.group(0)


def issue_client(name: str, remote: str | None = None) -> tuple[Path, Path, Path]:
    """Generate the key locally, sign it with the CA, and write issued/<name>.{ovpn,crt,key}."""
    validate_name(name)
    require_ca()
    if not ISSUED.is_dir():
        raise VPNError(f"issued directory unavailable: {ISSUED}")
    ovpn, crt, key = (ISSUED / f"{name}.{ext}" for ext in ("ovpn", "crt", "key"))
    if ovpn.exists():
        raise VPNError(f"{ovpn} already exists; revoke and use a new name, or remove it deliberately")
    if any(r["name"] == name and r["status"] == "V" for r in list_clients()):
        raise VPNError(f"{name} already has a valid certificate in the index")

    easyrsa(f"--req-cn={name}", "gen-req", name, "nopass")
    easyrsa("sign-req", "client", name)

    pki_key = PKI / "private" / f"{name}.key"
    pki_crt = PKI / "issued" / f"{name}.crt"
    key_text = pki_key.read_text()
    _write_private(key, key_text)
    pki_key.unlink()  # client keys live only in issued/; pki/private holds only CA and server keys

    cert_text = pki_crt.read_text()
    crt.write_text(_pem_cert(cert_text) + "\n")
    remote = remote or os.environ.get("VPN_REMOTE", DEFAULT_HOST)
    config = build_ovpn(
        name, (PKI / "ca.crt").read_text(), cert_text, key_text, _ta_key_body((PKI / "ta.key").read_text()), remote
    )
    _write_private(ovpn, config)
    return ovpn, crt, key


def _ta_key_body(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith("#"))


def revoke_client(name: str) -> Path:
    """Revoke a client and regenerate the CRL. Returns the CRL path."""
    validate_name(name)
    require_ca()
    easyrsa("revoke", name)
    easyrsa("gen-crl")
    return PKI / "crl.pem"


def ensure_crl() -> Path:
    require_ca()
    crl = PKI / "crl.pem"
    if not crl.is_file():
        easyrsa("gen-crl")
    return crl


def ensure_server_cert(cn: str = DEFAULT_SERVER_CN) -> tuple[Path, Path]:
    validate_name(cn)
    require_ca()
    crt, key = PKI / "issued" / f"{cn}.crt", PKI / "private" / f"{cn}.key"
    if not crt.is_file():
        easyrsa("build-server-full", cn, "nopass")
    return crt, key


# --- IP pool ---------------------------------------------------------------

def dedupe_ipp(text: str) -> str:
    """Keep one row per client name (its highest address) so stale leases don't fill the pool."""
    latest: dict[str, tuple[int, str]] = {}
    for line in text.splitlines():
        name, _, ip = line.partition(",")
        if not name or not ip:
            continue
        key = tuple(int(o) for o in ip.split("."))
        if name not in latest or key > latest[name][0]:
            latest[name] = (key, ip)
    rows = sorted(latest.items(), key=lambda kv: kv[1][0])
    return "".join(f"{name},{ip}\n" for name, (_, ip) in rows)


# --- remote ----------------------------------------------------------------

def _ssh_opts(pem: str | None) -> list[str]:
    opts = ["-o", "StrictHostKeyChecking=accept-new"]
    return opts + (["-i", pem] if pem else [])


def remote_host() -> str:
    return os.environ.get("VPN_HOST", DEFAULT_HOST)


def fetch_hosts(host: str | None = None) -> str:
    result = subprocess.run(
        ["ssh", host or remote_host(), "cat", HOSTS_PATH], check=True, capture_output=True, text=True, timeout=30
    )
    return result.stdout


def fetch_ipp(host: str | None = None) -> str:
    result = subprocess.run(
        ["ssh", host or remote_host(), "sudo", "cat", "/etc/openvpn/ipp.txt"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    return result.stdout


def push_server(host: str, user: str = "ubuntu", pem: str | None = None, cn: str = DEFAULT_SERVER_CN, run: bool = True) -> None:
    """Stage config and credentials on the new host, then run bootstrap.sh there."""
    crt, key = ensure_server_cert(cn)
    crl = ensure_crl()
    sources = {
        "server.conf": SERVER_FILES / "server.conf",
        "update-vpn-hosts.sh": SERVER_FILES / "update-vpn-hosts.sh",
        "dnsmasq-vpn.conf": SERVER_FILES / "dnsmasq-vpn.conf",
        "openvpn-override.conf": SERVER_FILES / "openvpn-override.conf",
        "ca.crt": PKI / "ca.crt",
        "server.crt": crt,
        "server.key": key,
        "ta.key": PKI / "ta.key",
        "crl.pem": crl,
    }
    ipp = PKI / "ipp.txt"
    if ipp.is_file():
        sources["ipp.txt"] = ipp
    for name, path in sources.items():
        if not path.is_file():
            raise VPNError(f"missing {name}: {path}")

    target = f"{user}@{host}"
    ssh = ["ssh", *_ssh_opts(pem), target]
    _run([*ssh, f"umask 077; mkdir -p ~/{STAGE_DIR}"])
    scp = ["scp", *_ssh_opts(pem)]
    for name, path in sources.items():
        _run([*scp, str(path), f"{target}:{STAGE_DIR}/{name}"])
    _run([*scp, str(BOOTSTRAP), f"{target}:bootstrap.sh"])
    if run:
        _run([*ssh, "bash bootstrap.sh"])


def push_crl(host: str, user: str = "ubuntu", pem: str | None = None) -> None:
    crl = ensure_crl()
    target = f"{user}@{host}"
    _run(["scp", *_ssh_opts(pem), str(crl), f"{target}:crl.pem"])
    _run(["ssh", *_ssh_opts(pem), target, "sudo install -m 0644 crl.pem /etc/openvpn/server/crl.pem"])


def kick(name: str, host: str, user: str = "ubuntu", pem: str | None = None) -> None:
    """Disconnect a connected client via the management interface."""
    validate_name(name)
    command = f"printf 'kill {name}\\nquit\\n' | nc -q1 127.0.0.1 {MANAGEMENT_PORT}"
    _run(["ssh", *_ssh_opts(pem), f"{user}@{host}", shlex.quote(command)])
