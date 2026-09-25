#!/usr/bin/env bash
# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260921

set -eu

BaseUrl="https://cloud-images.ubuntu.com/resolute/20260921"

ScriptRoot="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

Images=(
    "resolute-server-cloudimg-amd64.img|2d3b9b1f76fc204f684a2313113b1d7c2b35eabba19cfcbcec5eae2aed3cc853|x86_64"
    "resolute-server-cloudimg-arm64.img|3a3c4cd06716edd9e896b20b814227b051c42778c7693cb72eedbdd70642f8f7|aarch64"
    "resolute-server-cloudimg-riscv64.img|7a4402209b9c56e42c6c7824d5a15c97ca849ca78b4b1b37d9fbf4cf8e87d8a2|riscv64"
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
