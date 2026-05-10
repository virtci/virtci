#!/bin/sh
set -e

# Get SHA512 checksums
# curl -sL https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS | grep genericcloud
# Look for the .qcow2 entries

BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest"
AMD64_IMAGE="debian-12-genericcloud-amd64.qcow2"
AMD64_SHA512="a7dc90b7a8e4c17273d7429f2b77b4c30b143b17166dfe896ef05c2a8cad0356931fe0c27af543b6a13940a61e74cba2d6b23ba0904536952e28b14b1c7662db"
ARM64_IMAGE="debian-12-genericcloud-arm64.qcow2"
ARM64_SHA512="429a8b76b88bc2d9f039795600f1d90aa16b308e1ca501e7e16efa0b84db2a99b3d50b9957631f93a54df0d616cde0e19ec255069eab2a0e7f621a750242fdc5"

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
