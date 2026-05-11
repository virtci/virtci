# VirtCI installer for Windows.
# Usage: irm https://virtci.com/install.ps1 | iex

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BaseUrl = "https://github.com/virtci/virtci/releases/latest/download"

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x64" }
    "ARM64" { "arm64" }
    default {
        Write-Error "[VirtCI] unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
        exit 1
    }
}

$File = "virtci-windows-$Arch.tar.gz"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\virtci"
$Tmp = Join-Path $env:TEMP "virtci-install-$(New-Guid)"

try {
    New-Item -ItemType Directory -Force -Path $Tmp, $InstallDir | Out-Null

    Write-Host "[VirtCI] Downloading $File..."
    Invoke-WebRequest -Uri "$BaseUrl/$File" -OutFile (Join-Path $Tmp $File) -UseBasicParsing

    Write-Host "[VirtCI] Extracting to $InstallDir..."
    & tar.exe -xzf "$(Join-Path $Tmp $File)" -C "$InstallDir"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[VirtCI] tar extraction failed"
        exit 1
    }

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $UserPath -or $UserPath -notlike "*$InstallDir*") {
        $NewPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
        Write-Host "[VirtCI] Added $InstallDir to user PATH"
    }

    $QemuExe = if ($Arch -eq "arm64") { "qemu-system-aarch64.exe" } else { "qemu-system-x86_64.exe" }
    $QemuOnPath = [bool](Get-Command $QemuExe -ErrorAction SilentlyContinue)
    $QemuDefault = Test-Path "$env:ProgramFiles\qemu\$QemuExe"

    if (-not $QemuOnPath -and -not $QemuDefault) {
        Write-Host ""
        Write-Host "[VirtCI] QEMU is not installed. VirtCI requires QEMU."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            # https://winstall.app/apps/SoftwareFreedomConservancy.QEMU
            $Reply = Read-Host "[VirtCI] Install QEMU via winget? [Y/n]"
            if ($Reply -eq "" -or $Reply -match "^[Yy]") {
                winget install --id SoftwareFreedomConservancy.QEMU --accept-source-agreements --accept-package-agreements
            } else {
                Write-Host "[VirtCI] Skipped. Install later: winget install SoftwareFreedomConservancy.QEMU"
            }
        } else {
            Write-Host "[VirtCI] winget not found. Install QEMU from https://www.qemu.org/download/#windows"
        }
    } elseif ($QemuDefault -and -not $QemuOnPath) {
        Write-Host ""
        Write-Host "[VirtCI] QEMU found at $env:ProgramFiles\qemu but not on PATH."
        Write-Host "[VirtCI] Add 'C:\Program Files\qemu' to your PATH for VirtCI to find it."
    }

    Write-Host ""
    Write-Host "[VirtCI] Done. Open a new terminal and run: virtci --help"
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
