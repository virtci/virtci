# Fetch Ubuntu x86_64, aarch64, and riscv64 ubuntu QEMU images
# Using Ubuntu 26.04 Server Images from 20260520

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$BaseUrl = "https://cloud-images.ubuntu.com/resolute/20260520"

$Images = @(
    @{ Name = "resolute-server-cloudimg-amd64.img";  Sha = "dced94c031cc1f23dee14419a3723a5b110df9938de0ac31913a2bfd07c755b4"; Label = "x86_64" }
    @{ Name = "resolute-server-cloudimg-arm64.img";  Sha = "5e091e27d60116efbb0c743b8dd5cb2d15618e414ef04db0817ed43c8e2d7c7b"; Label = "aarch64" }
    @{ Name = "resolute-server-cloudimg-riscv64.img"; Sha = "353d24f14c0b48c55b67877fb5cdd0684ad79d38ed2b72161ddce50f2dfb08a4"; Label = "riscv64" }
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
