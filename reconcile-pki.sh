#!/bin/bash
# Adopt client certs signed by this CA but missing from the local EasyRSA PKI index.
# Public certs only: reads *.crt, never keys. Dry run unless --apply.
#   usage: reconcile-pki.sh PKI_DIR SRC_CRT_DIR [--apply]
set -euo pipefail
pki=${1:?PKI_DIR}; src=${2:?SRC_CRT_DIR}; apply=${3:-}
ca=$pki/ca.crt; idx=$pki/index.txt
[ -f "$ca" ] && [ -f "$idx" ] || { echo "missing $ca or $idx" >&2; exit 1; }
[ "$apply" = --apply ] && cp -n "$idx" "$idx.pre-reconcile"

new=0 known=0 bad=0 clash=0 collide=0
for f in "$src"/*.crt; do
  cn=$(basename "$f" .crt)
  [ "$cn" = ca ] && continue
  if ! openssl verify -CAfile "$ca" "$f" >/dev/null 2>&1; then
    echo "NOT SIGNED BY THIS CA: $f"; bad=$((bad+1)); continue
  fi
  ser=$(openssl x509 -in "$f" -noout -serial | cut -d= -f2)
  # Match on serial AND subject: a second CA instance once reused serials for different clients.
  subj=$(openssl x509 -in "$f" -noout -subject -nameopt compat | sed 's/^subject=//')
  row=$(awk -F'\t' -v s="$ser" '$4==s{print $6; exit}' "$idx")
  if [ -n "$row" ]; then
    if [ "$row" = "$subj" ]; then known=$((known+1))
    else
      echo "SERIAL COLLISION: $cn has serial $ser, already used by $(sed -n 's#.*/CN=\([^/]*\).*#\1#p' <<<"$row")"
      collide=$((collide+1))
    fi
    continue
  fi
  if grep -qF "/CN=$cn/" "$idx"; then
    echo "NAME CLASH (already in index with another serial): $cn serial $ser"; clash=$((clash+1))
  fi
  exp=$(date -u -d "$(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)" +%y%m%d%H%M%SZ)
  echo "ADOPT $cn serial=$ser"
  new=$((new+1))
  if [ "$apply" = --apply ]; then
    printf 'V\t%s\t\t%s\tunknown\t%s\n' "$exp" "$ser" "$subj" >> "$idx"
    cp -n "$f" "$pki/issued/$cn.crt"
    cp -n "$f" "$pki/certs_by_serial/$ser.pem"
  fi
done

# The next serial EasyRSA hands out must exceed every serial in the index.
max=$(awk -F'\t' '{print $4}' "$idx" | while read -r h; do echo $((16#$h)); done | sort -n | tail -1)
next=$((16#$(cat "$pki/serial")))
echo "known=$known adopt=$new clash=$clash collide=$collide bad=$bad; max serial in index=$max, next serial=$next"
if [ "$max" -ge "$next" ]; then
  fix=$(printf '%X' $((max+1))); [ $((${#fix}%2)) = 1 ] && fix=0$fix
  echo "serial file is too low; should be $fix"
  [ "$apply" = --apply ] && echo "$fix" > "$pki/serial" && echo "serial updated"
fi
[ "$apply" = --apply ] || echo "(dry run; re-run with --apply)"
