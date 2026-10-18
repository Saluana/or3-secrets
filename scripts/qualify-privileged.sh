#!/bin/sh
# Docker access is required. No host accounts, credentials, or mounts change.
set -eu
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project"
mkdir -p test-results
image="or3-secrets-task13:$(date +%s)-$$"
trap 'docker image rm "$image" >/dev/null 2>&1 || true' EXIT INT TERM
docker build -f scripts/Qualification.Dockerfile -t "$image" .
# The caller owns receipts; the disk-full process has a non-root effective UID.
receipt_identity=$(node -e 'const s=require("node:fs").statSync("test-results");process.stdout.write(`${s.uid}:${s.gid}`)')
receipt_uid=${receipt_identity%:*}
receipt_gid=${receipt_identity#*:}
[ "$receipt_uid" != 0 ]
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --user "$receipt_uid:$receipt_gid" \
  --tmpfs /tmp:rw,nosuid,nodev,size=8m,mode=1777 \
  --tmpfs "/staging:rw,nosuid,nodev,size=128m,mode=700,uid=$receipt_uid,gid=$receipt_gid" \
  -v "$project:/work:ro" -v "$project/test-results:/receipts" \
  "$image" bun --no-env-file scripts/qualify-disk.ts
docker run --rm --network none --user 0:0 --cap-drop ALL \
  --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 \
  -v "$project:/work:ro" -v "$project/test-results:/receipts" \
  "$image" sh scripts/qualify-isolation.sh
