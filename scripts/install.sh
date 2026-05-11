#!/bin/sh
# VirtCI installer for Linux and macOS.
# Usage: curl --proto '=https' --tlsv1.2 -fsSL https://virtci.com/install.sh | sh

set -eu

BASE_URL="https://github.com/virtci/virtci/releases/latest/download"

err()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

command -v curl >/dev/null 2>&1 || err "curl is required"

if [ "${OS:-}" = "Windows_NT" ]; then
    command -v powershell >/dev/null 2>&1 \
        || err "Windows detected but powershell not found. Run from PowerShell:
  irm https://virtci.com/install.ps1 | iex"
    exec powershell -c "irm https://virtci.com/install.ps1 | iex"
fi

download() {
    curl --proto '=https' --tlsv1.2 -fL --progress-bar "$1" -o "$2"
}

case "$(uname -s)" in
    Darwin)
        command -v brew >/dev/null 2>&1 \
            || err "Homebrew is required on macOS. Install from https://brew.sh"
        exec brew install virtci/virtci/virtci
        ;;
    Linux) ;;
    *) err "unsupported host OS: $(uname -s)" ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  ARCH=x64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "unsupported host architecture: $(uname -m)" ;;
esac

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || err "sudo is required (or run this script as root)"
    SUDO="sudo"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v apt-get >/dev/null 2>&1; then
    FILE="virtci-linux-${ARCH}.deb"
    info "Downloading ${FILE}..."
    download "${BASE_URL}/${FILE}" "${TMP}/${FILE}"
    $SUDO apt-get install -y "${TMP}/${FILE}"

elif command -v dnf >/dev/null 2>&1; then
    FILE="virtci-linux-${ARCH}.rpm"
    info "Downloading ${FILE}..."
    download "${BASE_URL}/${FILE}" "${TMP}/${FILE}"
    $SUDO dnf install -y "${TMP}/${FILE}"

else
    FILE="virtci-linux-${ARCH}.tar.gz"
    info "Downloading ${FILE}..."
    download "${BASE_URL}/${FILE}" "${TMP}/${FILE}"
    tar -xzf "${TMP}/${FILE}" -C "${TMP}"
    $SUDO install -m 755 "${TMP}/virtci" /usr/local/bin/virtci
    info ""
    info "virtci installed to /usr/local/bin/virtci"
    info "Ensure qemu and swtpm are installed via your package manager, for example:"
    info "Arch: sudo pacman -S qemu-base qemu-img swtpm"
fi

info ""
info "Done. Run: virtci --help"
