#!/usr/bin/env bash
# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260716
#
# Canonical ships them compressed, gonna try decompressing them? Maybe helps Windows?

set -eu

BaseUrl="https://cloud-images.ubuntu.com/resolute/20260716"

ScriptRoot="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

Images=(
    "resolute-server-cloudimg-amd64.img|1733ea0c2aec6705192d54f60a4cc8a526d734f18170f42a4026521b623fc8a2|x86_64"
    "resolute-server-cloudimg-arm64.img|beb95f1c5ea8c64684af5eed992ac2fa9779416b482bdb068cef9978397900bc|aarch64"
    "resolute-server-cloudimg-riscv64.img|519e6a3ee02ab492deac4fcf6bc9f781b015a383ef44cdaa95ef326bf114ff3b|riscv64"
)

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

if ! command -v qemu-img > /dev/null 2>&1; then
    echo "qemu-img not found. It is needed to decompress the cloud images, so this must run after QEMU is installed." >&2
    exit 1
fi

for entry in "${Images[@]}"; do
    IFS='|' read -r Name Sha Label <<< "$entry"
    dest="$ScriptRoot/$Name"
    stamp="$dest.sha256"
    download="$dest.download"

    if [ -f "$dest" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$Sha" ]; then
        echo "[VirtCI] Ubuntu 26.04 Server $Label already present and decompressed, skipping."
        continue
    fi
    rm -f "$dest" "$stamp" "$download"

    echo "[VirtCI] Downloading Ubuntu 26.04 Server $Label..."
    if ! curl -L --fail --retry 3 --retry-delay 2 -o "$download" "$BaseUrl/$Name"; then
        rc=$?
        rm -f "$download"
        echo "Failed to download Ubuntu 26.04 $Label (curl exit $rc)." >&2
        exit 1
    fi

    if [ "$(file_sha256 "$download")" != "$Sha" ]; then
        rm -f "$download"
        echo "Ubuntu 26.04 $Label SHA256 hash did not match the downloaded file." >&2
        exit 1
    fi
    echo "[VirtCI] Ubuntu 26.04 Server $Label SHA256 verified."

    # No -c
    echo "[VirtCI] Decompressing Ubuntu 26.04 Server $Label..."
    if ! qemu-img convert -O qcow2 "$download" "$dest"; then
        rc=$?
        rm -f "$download" "$dest"
        echo "Failed to decompress Ubuntu 26.04 $Label (qemu-img exit $rc)." >&2
        exit 1
    fi

    rm -f "$download"
    printf '%s' "$Sha" > "$stamp"
    echo "[VirtCI] Ubuntu 26.04 Server $Label ready."
done
