# Windows Setup

It is recommend to use Windows Server for x64. For arm64, Windows 11 Home is acceptable. You may get Windows Server arm64 ISOs from Windows. You may use Windows 11 Home for x64 as well.

Running unlicensed Windows is not recommended.

[Windows Server 2022 x64 ISO](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022)

[Windows 11 ISO](https://www.microsoft.com/en-us/software-download/windows11)

[Windows Server ARM64 Insider Preview](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewarm64)

This will assume you are using an x64 virtual machine. For ARM64, rather than launching with `qemu-system-x86_64`, use `qemu-system-aarch64`.

## Windows Server Setup

```sh
# Make the actual disk image
# After we'll use the ISO we downloaded :)
# Replace STORAGE_HERE with the amount of storage for the VM
# https://learn.microsoft.com/en-us/windows-server/get-started/hardware-requirements?tabs=storage&pivots=windows-server-2022
# 32G is the suggested minimum value
qemu-img create -f qcow2 windows-server.qcow2 STORAGE_HERE
```

Download VirtIO Windows Drivers [virtio-win.iso](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso)

```sh
# Install from the ISO you got
# Replace PATH_SO_ISO_YOU_DOWNLOADED with the actual ISO path
# Replace PATH_TO_VIRTIO_DRIVERS with the virtio-win.iso path
# For the PATH_TO_VIRTIO_DRIVERS, you may need the absolute path
qemu-system-x86_64 \
-machine type=q35,accel=kvm \
-cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time \
-smp 4 \
-m 8G \
-drive if=pflash,format=raw,readonly=on,file=/usr/share/ovmf/OVMF.fd \
-drive file=windows-server.qcow2,format=qcow2,if=virtio \
-cdrom PATH_SO_ISO_YOU_DOWNLOADED \
-drive file=PATH_TO_VIRTIO_DRIVERS,media=cdrom \
-boot d \
-netdev user,id=net0 \
-device virtio-net-pci,netdev=net0 \
-device qemu-xhci,id=xhci \
-device usb-tablet \
-display gtk \
-vga virtio
```

When selecting the drive to isntall, you may see no option. Press `Load Driver` to load the virtio driver. I used `Red Hat VirtIO SCSI controller (D:\amd64\sk25\viostor.inf)`.

You also may be annoyed by the password requirements. I set my password to `DevWin2022` which got through.

Boot into the VM, and `Exit to command line (PowerShell)`.

Enable Networking and SSH

```sh
Get-Volume # Look for the DriveLetter for virtio-win...

# Replace with your drive letter, and 2k22 is for windows server 2022
pnputil /add-driver D:\NetKVM\2k22\amd64\*.inf /install
pnputil /scan-devices

# This may take a while
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
# Set powershell for SSH
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

```sh
# NOW you can boot without the virtio driver iso
qemu-system-x86_64 \
-machine type=q35,accel=kvm \
-cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time \
-smp 4 \
-m 8G \
-drive if=pflash,format=raw,readonly=on,file=/usr/share/ovmf/OVMF.fd \
-drive file=windows-server.qcow2,format=qcow2,if=virtio \
-netdev user,id=net0,hostfwd=tcp::2222-:22 \
-device virtio-net-pci,netdev=net0 \
-device qemu-xhci,id=xhci \
-device usb-tablet \
-display gtk,grab-on-hover=on \
-vga virtio
```

```sh
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -Value 1
Set-SConfig -AutoLaunch $false
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DisableCAD -Value 1
Restart-Computer
```
