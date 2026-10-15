# phisaver-vpn

Administers the PhiSaver OpenVPN server (peer-to-peer, `*.vpn` DNS). No keys or secrets live in this repo:

- `pki/`    symlink to private storage: CA key, server key, `ta.key`, index
- `issued/` symlink to private storage: per-client `.ovpn`, `.crt`, `.key`

Environment comes from direnv: `VPN_HOST` (current server, default `live.phisaver.com`),
`VPN_REMOTE` (name written into `.ovpn`), `VPN_PEM` (SSH key for new hosts).

```fish
uv run vpn issue ebac22r1          # key generated locally, signed, written to issued/
uv run vpn list [--all]
uv run vpn revoke NAME [--push --host H]
uv run vpn hosts                   # name -> IP records from the server
uv run vpn server ipp              # pool seed from the old server -> pki/ipp.txt
uv run vpn server push NEW_HOST    # server cert, stage files, run bootstrap.sh
uv run vpn aws launch|status
```

`reconcile-pki.sh PKI SRC_CRT_DIR [--apply]` adopts certs signed by the CA but missing from `index.txt`.
`inspect.sh` surveys an existing server (read-only).
