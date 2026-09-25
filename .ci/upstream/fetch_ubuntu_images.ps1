# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260921

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$BaseUrl = "https://cloud-images.ubuntu.com/resolute/20260921"

$Images = @(
    @{ Name = "resolute-server-cloudimg-amd64.img";  Sha = "2d3b9b1f76fc204f684a2313113b1d7c2b35eabba19cfcbcec5eae2aed3cc853"; Label = "x86_64" }
    @{ Name = "resolute-server-cloudimg-arm64.img";  Sha = "3a3c4cd06716edd9e896b20b814227b051c42778c7693cb72eedbdd70642f8f7"; Label = "aarch64" }
    @{ Name = "resolute-server-cloudimg-riscv64.img"; Sha = "7a4402209b9c56e42c6c7824d5a15c97ca849ca78b4b1b37d9fbf4cf8e87d8a2"; Label = "riscv64" }
)

foreach ($img in $Images) {
    $dest = Join-Path $PSScriptRoot $img.Name

    if (Test-Path $dest) {
        if ((Get-FileHash $dest -Algorithm SHA256).Hash -eq $img.Sha) {
            Write-Host "[VirtCI] Ubuntu 26.04 Server $($img.Label) already present and verified, skipping."
            continue
        }
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[VirtCI] Downloading Ubuntu 26.04 Server $($img.Label)..."
    # curl.exe ships with Windows 10/11 already, and streams to disk.
    # Way better than Invoke-WebRequest for this.
    & curl.exe -L --fail --retry 3 --retry-delay 2 -o $dest "$BaseUrl/$($img.Name)"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to download Ubuntu 26.04 $($img.Label) (curl exit $LASTEXITCODE)."
    }

    if ((Get-FileHash $dest -Algorithm SHA256).Hash -ne $img.Sha) {
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        throw "Ubuntu 26.04 $($img.Label) SHA256 hash did not match the downloaded file."
    }
    Write-Host "[VirtCI] Ubuntu 26.04 Server $($img.Label) SHA256 verified."
}
