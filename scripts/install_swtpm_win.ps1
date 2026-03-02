# Installs swtpm on Windows through WSL2.
#
# The swtpm library is linux/mac only and it's not really possible to compile
# it on windows, even using mingw64. swtpm instead can run inside WSL2
# with virtci connecting over TCP.
#
# Needs WSL2 with a default distro. I recommend Ubuntu or Arch.

$ErrorActionPreference = "Stop"

try { wsl --status 2>&1 | Out-Null } catch {
    Write-Error "[VirtCI] WSL is not installed. Enable it with: wsl --install"
    exit 1
}

$WslOutput = wsl --list --quiet 2>&1
if (-not $WslOutput) {
    Write-Error "[VirtCI] No WSL distro installed. Run: 'wsl --install'. Ubuntu recommended"
    exit 1
}

Write-Host "[VirtCI] WSL2 detected. Default distro: $($WslOutput | Select-Object -First 1)"

$AlreadyInstalled = wsl -- which swtpm 2>&1
if ($LASTEXITCODE -eq 0) {
    $Version = wsl -- swtpm --version 2>&1
    Write-Host "[VirtCI] swtpm is already installed: $Version"
    exit 0
}

# swtpm apt-get or pacman

Write-Host "[VirtCI] swtpm not found in WSL, installing"

$HasApt = wsl -- which apt-get 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[VirtCI] Using apt-get"
    wsl -- sudo apt-get update -qq
    if ($LASTEXITCODE -ne 0) { Write-Error "[VirtCI] apt-get update failed"; exit 1 }
    wsl -- sudo apt-get install -y swtpm
    if ($LASTEXITCODE -ne 0) { Write-Error "[VirtCI] apt-get install swtpm failed"; exit 1 }
} else {
    $HasPacman = wsl -- which pacman 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[VirtCI]  Using pacman"
        wsl -- sudo pacman -Sy --noconfirm swtpm
        if ($LASTEXITCODE -ne 0) { Write-Error "[VirtCI] pacman install swtpm failed"; exit 1 }
    } else {
        Write-Error @"
[VirtCI] Could not find apt-get or pacman in the default WSL distro.
Please install swtpm manually inside WSL:
  wsl -- sudo <your-package-manager> install swtpm
"@
        exit 1
    }
}

# Verify

Write-Host "[VirtCI] Verifying:"
wsl -- swtpm --version
if ($LASTEXITCODE -ne 0) {
    Write-Error "[VirtCI] swtpm installed but could not run --version"
    exit 1
}

Write-Host ""
Write-Host "[VirtCI] swtpm installed successfully in WSL2."
Write-Host "[VirtCI] virtci will launch it automatically doing 'wsl -- swtpm ...' when a VM needs TPM."
