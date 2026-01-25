# Windows Setup

It is recommend to use Windows Home, rather than Windows Server Core. This is because some applications will depend on graphics libraries. There is the Windows Server Desktop Experience, which you may prefer, but I personally find the normal desktop experience to be sufficient for all of my own use cases for CI/CD.

Running unlicensed Windows is not recommended.

[Windows 11 ISO](https://www.microsoft.com/en-us/software-download/windows11)

This will assume you are using an x64 virtual machine. For ARM64, rather than launching with `qemu-system-x86_64`, use `qemu-system-aarch64`.

## Windows Home Setup

```sh
# Make the actual disk image
# After we'll use the ISO we downloaded :)
# Replace STORAGE_HERE with the amount of storage for the VM
# 64G is the suggested minimum value
qemu-img create -f qcow2 windows-x64.qcow2 STORAGE_HERE
```

Download VirtIO Windows Drivers [virtio-win.iso](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso)

```sh
cp /usr/share/OVMF/OVMF_VARS_4M.fd ./OVMF_VARS_4M.fd
cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd ./OVMF_VARS_4M.ms.fd

mkdir -p /tmp/emulated_tpm
swtpm socket --tpmstate dir=/tmp/emulated_tpm --ctrl type=unixio,path=/tmp/emulated_tpm/swtpm-sock --tpm2 --daemon
```

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
-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.ms.fd \
-drive if=pflash,format=raw,file=./OVMF_VARS_4M.ms.fd \
-drive file=windows-x64.qcow2,format=qcow2,if=ide \
-cdrom $HOME/vm/iso/Win11_25H2_English_x64.iso \
-drive file=$HOME/vm/iso/virtio-win-0.1.285.iso,media=cdrom,index=1 \
-boot d \
-netdev user,id=net0 \
-device virtio-net-pci,netdev=net0 \
-device qemu-xhci,id=xhci \
-device usb-tablet \
-chardev socket,id=chrtpm,path=/tmp/emulated_tpm/swtpm-sock \
-tpmdev emulator,id=tpm0,chardev=chrtpm \
-device tpm-tis,tpmdev=tpm0 \
-display gtk \
-vga virtio
```

When you see "Press any key to boot from CD or DVD", do so.

1. Open Device Manager (right-click Start → Device Manager)
2. Look for "Ethernet Controller" or similar under "Other devices" with a yellow warning icon
3. Right-click it → "Update driver"
4. Choose "Browse my computer for drivers"
5. Browse to D:\NetKVM\w11\amd64\ (or try D:\NetKVM\2k22\amd64\ if w11 doesn't work)
6. Click "Next" and let it install

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

qemu-system-x86_64 
-machine q35 
-cpu max 
-name win-x64 
-m 8192M 
-smp 4
-drive if=pflash,format=raw,readonly=on,file=/usr/share/qemu/OVMF.fd -drive file=/home/user/vm/windows-server.qcow2,format=qcow2 
-accel kvm 
-accel tcg 
-netdev user,id=net0,hostfwd=tcp::PORT-:22 
-device virtio-net-pci,netdev=net0
```

```sh
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name DisableCAD -Value 1
Set-SConfig -AutoLaunch $false
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DisableCAD -Value 1
Restart-Computer
```

Install Visual Studio Tools and MinGW

```sh
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile "$env:TEMP\vs_buildtools.exe"

& "$env:TEMP\vs_buildtools.exe" --quiet --wait --norestart --nocache --installPath C:\BuildTools --add Microsoft.VisualStudio.Workload.VCTools  --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621

Set-ExecutionPolicy Bypass -Scope Process -Force

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

Invoke-WebRequest -Uri "https://github.com/niXman/mingw-builds-binaries/releases/download/13.2.0-rt_v11-rev1/x86_64-13.2.0-release-posix-seh-ucrt-rt_v11-rev1.7z" -OutFile "$env:TEMP\mingw.7z"

choco install 7zip -y

& "C:\Program Files\7-Zip\7z.exe" x "$env:TEMP\mingw.7z" -o"C:\"

[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\mingw64\bin", [System.EnvironmentVariableTarget]::Machine)
```

```sh
# You may need to refresh the PATH for mingw
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
```

Install CMake

```sh
choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System' -y
```
