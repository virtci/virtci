#!/usr/bin/env bash
# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260716

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
