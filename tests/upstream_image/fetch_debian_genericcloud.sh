#!/bin/sh
set -e

# Get SHA512 checksums
# curl -sL https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS | grep genericcloud
# Look for the .qcow2 entries

BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest"
AMD64_IMAGE="debian-12-genericcloud-amd64.qcow2"
AMD64_SHA512="9484213faab270ee150c337ab0e3e08ec70118b353c0c02c365c1e06e4d5cc18473c59b1e187d5edd0805548d4b1570ac07750076b8f55c6e20efb8871f50bfc"
ARM64_IMAGE="debian-12-genericcloud-arm64.qcow2"
ARM64_SHA512="2c6df5c3f6f52e4becae90cf323e16d957cd6089f6c9f62bc7df05a4065b37c28ab14532fb0a789ccb3653d69c9df895971551f6a83bd8864b4d6bfc88d70e3a"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

fetch_image() {
    IMAGE_NAME="$1"
    SHA512="$2"
    IMAGE_PATH="$SCRIPT_DIR/$IMAGE_NAME"

    if [ -f "$IMAGE_PATH" ]; then
        echo "Image already exists at $IMAGE_PATH, verifying checksum."
        if echo "$SHA512  $IMAGE_PATH" | sha512sum -c - 2>/dev/null || echo "$SHA512  $IMAGE_PATH" | shasum -a 512 -c - 2>/dev/null; then
            echo "Checksum valid. Nothing to do."
            return 0
        else
            echo "Checksum mismatch. Re-downloading."
            rm -f "$IMAGE_PATH"
        fi
    fi

    echo "Downloading $IMAGE_NAME."
    curl -L -o "$IMAGE_PATH.tmp" "$BASE_URL/$IMAGE_NAME"

    echo "Verifying checksum."
    if echo "$SHA512  $IMAGE_PATH.tmp" | sha512sum -c - 2>/dev/null || echo "$SHA512  $IMAGE_PATH.tmp" | shasum -a 512 -c - 2>/dev/null; then
        mv "$IMAGE_PATH.tmp" "$IMAGE_PATH"
        echo "Done. Image saved to $IMAGE_PATH"
    else
        rm -f "$IMAGE_PATH.tmp"
        echo "ERROR: Checksum verification failed for $IMAGE_NAME." >&2
        exit 1
    fi
}

fetch_image "$AMD64_IMAGE" "$AMD64_SHA512"
fetch_image "$ARM64_IMAGE" "$ARM64_SHA512"
