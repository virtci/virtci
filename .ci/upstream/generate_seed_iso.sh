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
write_files:
  - path: /usr/local/sbin/virtci-boot-diag
    permissions: '0755'
    content: |
      #!/bin/sh
      # Cheap diagnostics first (in case journalctl is slow under TCG and gets timed out).
      exec > /dev/console 2>&1
      echo
      echo "=== VIRTCI BOOT DIAGNOSTICS (${1:-?}) ==="
      echo "-- date (utc) --"; date -u
      echo "-- failed units --"; systemctl --failed --no-pager
      echo "-- pending jobs --"; systemctl list-jobs --no-pager
      echo "-- journal (errors) --"; journalctl -xb -p err --no-pager | tail -n 120
      echo "-- journal (tail) --"; journalctl -xb --no-pager | tail -n 200
      echo "=== END VIRTCI BOOT DIAGNOSTICS (${1:-?}) ==="
  - path: /etc/systemd/system/emergency.service.d/10-virtci-dump.conf
    content: |
      [Service]
      ExecStartPre=-/usr/local/sbin/virtci-boot-diag emergency
  - path: /etc/systemd/system/rescue.service.d/10-virtci-dump.conf
    content: |
      [Service]
      ExecStartPre=-/usr/local/sbin/virtci-boot-diag rescue
runcmd:
  # Really tried a lot of stuff for Windows/TCG flakiness. systemd just keeps timing out.
  # This hopefully should fix that. The disks themselves aren't corrupted or anything.
  - |
    awk '($2=="/boot"||$2=="/boot/efi")&&$4!~/nofail/{$4=$4",nofail,x-systemd.device-timeout=5s"}{print}' /etc/fstab > /etc/fstab.virtci && cat /etc/fstab.virtci > /etc/fstab && rm -f /etc/fstab.virtci
  - systemctl mask serial-getty@ttyAMA0.service serial-getty@ttyS0.service
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
