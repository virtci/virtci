# Ubuntu Server Setup

[Ubuntu Server Download](https://ubuntu.com/download/server)

This will assume you are using an x64 virtual machine. For ARM64, rather than launching with `qemu-system-x86_64`, use `qemu-system-aarch64`. For RISCV64, use `qemu-system-riscv64`.

```sh
# Make the actual disk image
# After we'll use the ISO we downloaded :)
# Replace STORAGE_HERE with the amount of storage for the VM
# https://documentation.ubuntu.com/server/reference/installation/system-requirements/
# 25G is the suggested minimum value
qemu-img create -f qcow2 ubuntu-24.04-server.qcow2 STORAGE_HERE

# Install from the ISO you got
# Replace PATH_SO_ISO_YOU_DOWNLOADED with the actual ISO path
qemu-system-x86_64 \
-machine type=q35,accel=kvm \
-cpu host \
-smp 4 \
-m 4G \
-drive file=ubuntu-24.04-server.qcow2,format=qcow2,if=virtio \
-cdrom PATH_SO_ISO_YOU_DOWNLOADED \
-boot d \
-netdev user,id=net0 \
-device virtio-net-pci,netdev=net0 \
-display gtk

# Boot it
# Replace PORT with your desired port. 2222 is a typical option.
qemu-system-x86_64 \
-machine type=q35,accel=kvm \
-cpu host \
-smp 4 \
-m 4G \
-drive file=ubuntu-24.04-server.qcow2,format=qcow2,if=virtio \
-netdev user,id=net0,hostfwd=tcp::PORT-:22 \
-device virtio-net-pci,netdev=net0 \
-display gtk \
-serial stdio
```

Next, within the VM:

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

Connect to the VM with SSH:

```sh
# PORT is the port you booted with
# USERNAME is the user to ssh into
ssh -p PORT USERNAME@localhost
```
