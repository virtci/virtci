#!/bin/sh
set -e

# Get SHA512 checksums
# curl -sL https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS | grep genericcloud
# Look for the .qcow2 entries

BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest"
AMD64_IMAGE="debian-12-genericcloud-amd64.qcow2"
AMD64_SHA512="774bee87378198fe9c52285c61de05bd5daac22ea54856040f9b38465e86c960d54f4667dcb71ab1117b372731131704e646a586bdbb48c56b9e5e2583cd0f23"
ARM64_IMAGE="debian-12-genericcloud-arm64.qcow2"
ARM64_SHA512="14e4beb53d23fe2be9cd2b3ea1880037d62e8642af643a3cf78d8fe414b90f09ea21ad97a2dde665aff2e7733e6813418b48dd11a0129382071f7ecdf4b96281"

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
