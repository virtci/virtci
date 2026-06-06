#!/usr/bin/env bash
# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260520

set -eu

BaseUrl="https://cloud-images.ubuntu.com/resolute/20260520"

ScriptRoot="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

Images=(
    "resolute-server-cloudimg-amd64.img|dced94c031cc1f23dee14419a3723a5b110df9938de0ac31913a2bfd07c755b4|x86_64"
    "resolute-server-cloudimg-arm64.img|5e091e27d60116efbb0c743b8dd5cb2d15618e414ef04db0817ed43c8e2d7c7b|aarch64"
    "resolute-server-cloudimg-riscv64.img|353d24f14c0b48c55b67877fb5cdd0684ad79d38ed2b72161ddce50f2dfb08a4|riscv64"
)

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

for entry in "${Images[@]}"; do
    IFS='|' read -r Name Sha Label <<< "$entry"
    dest="$ScriptRoot/$Name"

    if [ -f "$dest" ]; then
        if [ "$(file_sha256 "$dest")" = "$Sha" ]; then
            echo "[VirtCI] Ubuntu 26.04 Server $Label already present and verified, skipping."
            continue
        fi
        rm -f "$dest"
    fi

    echo "[VirtCI] Downloading Ubuntu 26.04 Server $Label..."
    if ! curl -L --fail --retry 3 --retry-delay 2 -o "$dest" "$BaseUrl/$Name"; then
        rc=$?
        echo "Failed to download Ubuntu 26.04 $Label (curl exit $rc)." >&2
        exit 1
    fi

    if [ "$(file_sha256 "$dest")" != "$Sha" ]; then
        rm -f "$dest"
        echo "Ubuntu 26.04 $Label SHA256 hash did not match the downloaded file." >&2
        exit 1
    fi
    echo "[VirtCI] Ubuntu 26.04 Server $Label SHA256 verified."
done
