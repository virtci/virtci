# RISC-V64 Linux Setup Guide

This guide assumes you are NOT running on RISC-V64 natively.

This guide will outline everything for a Ubuntu host system, but everything should nearly identically translate for other Linux hosts, and roughly translate for MacOS and Windows hosts.

This guide will also only walk through how to setup a Ubuntu 26.04 RISC-V64 VM.

Acquire an ISO at [Ubuntu 26.04 ISO Mirror](https://cdimage.ubuntu.com/releases/26.04/release/).

**NOTE**, the VM we will create here will run **extremely slow** sometimes, as it emulates RISC-V64 fully.

Run all steps inside a dedicated VM directory for convenience.

## 1. Ensure Compatible QEMU Version

```sh
qemu-system-riscv64 -version
```

Should print at least 10.x.x. QEMU 9.x.x added RVA22 profiles but Ubuntu 26.04 RISC-V is built against RVA23. 10.x.x is known to work from my testing.

If it does not, build from source:

```sh
git clone --depth 1 --branch v11.0.0 https://gitlab.com/qemu-project/qemu.git
cd qemu
./configure --prefix=/usr/local --enable-slirp --enable-kvm --enable-virtfs --enable-tools --enable-docs
make -j"$(nproc)"
sudo make install
```

That will install the qemu-system-* binaries into `/usr/local/bin`, which should take precedence over `/usr/bin` if you have an outdated version.

If you encounter issues you MAY need to install some dependencies. I didn't need to but who knows.

```sh
sudo sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
sudo apt update && sudo apt build-dep qemu
```

## 2. Install Required UEFI Files

```sh
sudo apt install qemu-efi-riscv64
cp /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd ./ubuntu-riscv64-vars.fd
```

## 3. Boot VM From ISO

```sh
qemu-img create -f qcow2 ubuntu-riscv64.qcow2 64G

qemu-system-riscv64 \
-machine virt \
-cpu max \
-smp 4 \
-m 8G \
-drive if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
-drive if=pflash,unit=1,format=raw,file=./ubuntu-riscv64-vars.fd \
-drive file=ubuntu-riscv64.qcow2,format=qcow2,if=virtio \
-device virtio-scsi-pci,id=scsi0 \
-drive file=ubuntu-26.04-live-server-riscv64.iso,format=raw,if=none,id=cdrom,readonly=on \
-device scsi-cd,bus=scsi0.0,drive=cdrom \
-netdev user,id=net0 \
-device virtio-net-pci,netdev=net0 \
-nographic
```

*scsi is necessary to get the cdrom, as virt has no IDE controller and it won't work otherwise seemingly.*

Inside here, you may get into the UEFI shell. I did. If so, I was able to actually boot by doing the following:

```uefi
FS0:
ls EFI\BOOT
EFI\BOOT\bootriscv64.efi
```

Note the backslash.

From here, follow the normal Ubuntu Live Server setup.

## 4. Boot VM Without ISO

```sh
qemu-system-riscv64 \
-machine virt \
-cpu max \
-smp 4 \
-m 8G \
-drive if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
-drive if=pflash,unit=1,format=raw,file=./ubuntu-riscv64-vars.fd \
-drive file=ubuntu-riscv64.qcow2,format=qcow2,if=virtio \
-netdev user,id=net0,hostfwd=tcp::2222-:22 \
-device virtio-net-pci,netdev=net0 \
-nographic
```

## 5. Prepare VM for VirtCI Usage

```sh
sudo systemctl status ssh

# If ssh.service could not be found
sudo apt update
sudo apt install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# Setup passwordless sudo, replacing USERNAME with the user
echo "USERNAME ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/USERNAME
sudo chmod 440 /etc/sudoers.d/USERNAME

sudo sysctl vm.mmap_rnd_bits
# If you see a value of 32, it should be adjusted to 28 for thread sanitizer usage
sudo nano /etc/sysctl.conf
# Add the following to the file
# vm.mmap_rnd_bits=28
```

Now you should be able to SSH into it if OpenSSH wasn't setup as part of the OS install.

```sh
ssh -p 2222 USERNAME@127.0.0.1
```
