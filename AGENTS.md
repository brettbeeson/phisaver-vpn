# Agent rules for this repo

## Never run these

- **No git write commands.** Never run `git add`, `commit`, `push`, `pull`, `merge`, `rebase`,
  `reset`, `checkout`/`switch` (to change branches or discard files), `stash`, `tag`, `rm`, `mv`,
  `clean`, or anything else that changes the repo or its history. Read-only git (`status`, `diff`,
  `log`, `show`) is fine. Leave committing to the user.
- **No ssh at all.** Never run `ssh`, `scp`, `sftp`, `rsync` over ssh, `ssh-keygen -R`, or any
  command or script that connects to a remote host over ssh. That includes `uv run vpn server push`,
  `vpn server ipp`, `vpn hosts`, `vpn revoke --push`, `vpn aws launch` (its default `--copy`), and
  `inspect.sh` over ssh. Write or edit the code, then give the user the exact command to run
  themselves.

Reading local files and running local-only tools (tests, `bash -n`, `vpn issue` against a scratch
`VPN_PKI`/`VPN_ISSUED`) is fine.

## Secrets

- `pki/` and `issued/` are symlinks to private storage and are gitignored. Never copy, print, or
  commit their contents (CA key, server key, `ta.key`, client keys).
- Do not read private keys (`*.pem`, `*.key`, `id_rsa`). Inspecting fingerprints or headers is fine.
