#!/bin/sh
set -e

# Get SHA512 checksums
# curl -sL https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS | grep genericcloud
# Look for the .qcow2 entries

BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest"
AMD64_IMAGE="debian-12-genericcloud-amd64.qcow2"
AMD64_SHA512="ff1c5b86c680bf29fb65a485296f45da744c9f636cb3c3ecc573b7c51ff88797ef207119e40f07ae9428b9bb539d57b490cdb2beecdfbac25dc95163e1418936"
ARM64_IMAGE="debian-12-genericcloud-arm64.qcow2"
ARM64_SHA512="23331c892f483cc8a0d894931366a3a19c956c0b301a56f792ddd272970fedc8d8aff7e320552bd6632091bfd921ecd7dbdb2fd6cbf783b1f0d46252fbdffa0a"

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
