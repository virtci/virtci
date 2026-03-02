#!/usr/bin/env bash
set -e

SEED_DIR=$(mktemp -d)
trap 'rm -rf "$SEED_DIR"' EXIT

cat > "$SEED_DIR/user-data" <<'EOF'
#cloud-config
password: virtci
chpasswd:
expire: false
ssh_pwauth: true
EOF

cat > "$SEED_DIR/meta-data" <<'EOF'
instance-id: virtci-test
local-hostname: debian
EOF

cat > "$SEED_DIR/network-config" <<'EOF'
network:
version: 2
ethernets:
    id0:
    match:
        name: "en*"
    dhcp4: true
EOF

genisoimage \
-output seed.iso \
-volid cidata \
-joliet \
-rock \
"$SEED_DIR/user-data" \
"$SEED_DIR/meta-data" \
"$SEED_DIR/network-config"

echo "seed.iso created at $(pwd)/seed.iso"
