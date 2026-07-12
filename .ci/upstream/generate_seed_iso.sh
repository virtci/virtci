#!/usr/bin/env bash
set -e

ScriptRoot="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SEED_DIR=$(mktemp -d)
trap 'rm -rf "$SEED_DIR"' EXIT

cat > "$SEED_DIR/user-data" <<'EOF'
#cloud-config
users:
  - name: virtci
    plain_text_passwd: virtci
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
ssh_pwauth: true
EOF

cat > "$SEED_DIR/meta-data" <<EOF
instance-id: virtci-$(cat /proc/sys/kernel/random/uuid)
local-hostname: virtci
EOF

cat > "$SEED_DIR/network-config" <<'EOF'
network:
  version: 2
  ethernets:
    id0:
      match:
        name: "en*"
      dhcp4: true
      optional: true
EOF

genisoimage \
-output "$ScriptRoot/seed.iso" \
-volid cidata \
-joliet \
-rock \
"$SEED_DIR/user-data" \
"$SEED_DIR/meta-data" \
"$SEED_DIR/network-config"

echo "seed.iso created at $ScriptRoot/seed.iso"
