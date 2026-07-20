# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260716
#
# Canonical ships them compressed, gonna try decompressing them? Maybe helps Windows?

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$BaseUrl = "https://cloud-images.ubuntu.com/resolute/20260716"

$Images = @(
    @{ Name = "resolute-server-cloudimg-amd64.img";  Sha = "1733ea0c2aec6705192d54f60a4cc8a526d734f18170f42a4026521b623fc8a2"; Label = "x86_64" }
    @{ Name = "resolute-server-cloudimg-arm64.img";  Sha = "beb95f1c5ea8c64684af5eed992ac2fa9779416b482bdb068cef9978397900bc"; Label = "aarch64" }
    @{ Name = "resolute-server-cloudimg-riscv64.img"; Sha = "519e6a3ee02ab492deac4fcf6bc9f781b015a383ef44cdaa95ef326bf114ff3b"; Label = "riscv64" }
)

$QemuImg = Get-Command qemu-img -ErrorAction SilentlyContinue
if (-not $QemuImg) {
    $Fallback = "C:\Program Files\qemu\qemu-img.exe"
    if (Test-Path $Fallback) {
        $QemuImg = $Fallback
    } else {
        throw "qemu-img not found. It is needed to decompress the cloud images, so this must run after QEMU is installed."
    }
} else {
    $QemuImg = $QemuImg.Source
}

foreach ($img in $Images) {
    $dest = Join-Path $PSScriptRoot $img.Name
    $stamp = "$dest.sha256"
    $download = "$dest.download"

    if ((Test-Path $dest) -and (Test-Path $stamp) -and ((Get-Content $stamp -Raw).Trim() -eq $img.Sha)) {
        Write-Host "[VirtCI] Ubuntu 26.04 Server $($img.Label) already present and decompressed, skipping."
        continue
    }
    Remove-Item $dest, $stamp, $download -Force -ErrorAction SilentlyContinue

    Write-Host "[VirtCI] Downloading Ubuntu 26.04 Server $($img.Label)..."
    # curl.exe ships with Windows 10/11 already, and streams to disk.
    # Way better than Invoke-WebRequest for this.
    & curl.exe -L --fail --retry 3 --retry-delay 2 -o $download "$BaseUrl/$($img.Name)"
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $download -Force -ErrorAction SilentlyContinue
        throw "Failed to download Ubuntu 26.04 $($img.Label) (curl exit $LASTEXITCODE)."
    }

    if ((Get-FileHash $download -Algorithm SHA256).Hash -ne $img.Sha) {
        Remove-Item $download -Force -ErrorAction SilentlyContinue
        throw "Ubuntu 26.04 $($img.Label) SHA256 hash did not match the downloaded file."
    }
    Write-Host "[VirtCI] Ubuntu 26.04 Server $($img.Label) SHA256 verified."

    # No -c
    Write-Host "[VirtCI] Decompressing Ubuntu 26.04 Server $($img.Label)..."
    & $QemuImg convert -O qcow2 $download $dest
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $download, $dest -Force -ErrorAction SilentlyContinue
        throw "Failed to decompress Ubuntu 26.04 $($img.Label) (qemu-img exit $LASTEXITCODE)."
    }

    Remove-Item $download -Force -ErrorAction SilentlyContinue
    Set-Content -Path $stamp -Value $img.Sha -NoNewline
    Write-Host "[VirtCI] Ubuntu 26.04 Server $($img.Label) ready."
}
