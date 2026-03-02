# Upstream Images for Testing

Debian has `.qcow2` files at `https://cloud.debian.org/images/cloud/bookworm/latest/` which can be fetched as a baseline functional image.

Run the script to fetch the x64 and arm64 qcow2 files.

```sh
./test/upstream_image/fetch_debian_genericcloud.sh
```

## Boot VMs

Boot the VMs with the following commands using the cloud-init seed iso.

This step isn't necessary, but may be good just to check.

### Linux x64 Host

```sh
qemu-system-x86_64 \
-accel kvm \
-cpu host \
-m 512 \
-drive file=debian-12-genericcloud-amd64.qcow2,if=virtio \
-cdrom seed.iso \
-netdev user,id=net0,hostfwd=tcp::2222-:22 \
-device virtio-net-pci,netdev=net0 \
-nographic

qemu-system-aarch64 \
-M virt \
-cpu cortex-a72 \
-m 512 \
-bios /usr/share/AAVMF/AAVMF_CODE.fd \
-drive file=debian-12-genericcloud-arm64.qcow2,if=virtio \
-cdrom seed.iso \
-netdev user,id=net0,hostfwd=tcp::2223-:22 \
-device virtio-net-pci,netdev=net0 \
-nographic
```

### Mac arm64 Host

Assuming you are using homebrew qemu

```sh
qemu-system-x86_64 \
-m 512 \
-drive file=test/upstream_image/debian-12-genericcloud-amd64.qcow2,if=virtio \
-cdrom test/upstream_image/seed.iso \
-netdev user,id=net0,hostfwd=tcp::2222-:22 \
-device virtio-net-pci,netdev=net0 \
-nographic

qemu-system-aarch64 \
-M virt \
-accel hvf \
-cpu host \
-m 512 \
-bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
-drive file=test/upstream_image/debian-12-genericcloud-arm64.qcow2,if=virtio \
-cdrom test/upstream_image/seed.iso \
-netdev user,id=net0,hostfwd=tcp::2223-:22 \
-device virtio-net-pci,netdev=net0 \
-nographic
```

### Windows x64 Host

Run in powershell, and assuming that is your qemu executable install location.

```sh
& 'C:\Program Files\qemu\qemu-system-x86_64.exe' `
-machine q35,kernel-irqchip=off `
-cpu qemu64 `
-name debian `
-m 1024M `
-smp 2 `
-drive file=test/upstream_image/debian-12-genericcloud-amd64.qcow2,format=qcow2,if=virtio `
-drive file=test/upstream_image/seed.iso,format=raw,if=virtio,readonly=on `
-rtc base=utc `
-accel whpx -accel tcg `
-netdev user,id=net0,hostfwd=tcp::2222-:22 `
-device virtio-net-pci,netdev=net0,disable-modern=on `
-serial stdio

& 'C:\Program Files\qemu\qemu-system-aarch64.exe' `
-machine virt `
-cpu cortex-a72 `
-name debian-arm64 `
-m 1024M `
-smp 2 `
-bios 'C:\Program Files\qemu\share\edk2-aarch64-code.fd' `
-drive file=test/upstream_image/debian-12-genericcloud-arm64.qcow2,format=qcow2,if=virtio `
-drive file=test/upstream_image/seed.iso,format=raw,if=virtio,readonly=on `
-rtc base=utc `
-accel tcg `
-netdev user,id=net0,hostfwd=tcp::2223-:22 `
-device virtio-net-pci,netdev=net0,disable-modern=on `
-serial stdio
```

## SSH Into VM to Validate it Works

This step isn't necessary.

```sh
# x64 VM using port 2222
ssh debian@127.0.0.1 -p 2222
# Password 'virtci'

# arm64 VM using port 2223
ssh debian@127.0.0.1 -p 2223
# Password 'virtci'
```
