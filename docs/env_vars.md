# Environment Variables

| Variable Name | Description | Use |
|---------------|-------------|-----|
| VIRTCI_BACKEND_PORT | The port that the `virtci serve` command uses.<br><br>If `virtci serve --port N` is supplied, that takes precedence.<br>`VIRTCI_BACKEND_PORT` takes precedence over default port of 6399. | export VIRTCI_BACKEND_PORT=8080 |
| VIRTCI_S3_URLS | The s3 url(s) that the `virtci serve` backend can use.<br>Multiple can be supplied, using the space `' '` as separators. The first one is always prioritized for read operations, but write operations are done to all. If the first is unavailable, the new primary becomes the second, and continuing round-robin. | export VIRTCI_S3_URLS="localhost:3900"<br>export VIRTCI_S3_URLS="localhost:3900 localhost:4900" |
| VIRTCI_USER_HOME | The user-local directory to store VMs and other persistent VirtCI data. | export VIRTCI_USER_HOME="~/.vciuser" |
| VIRTCI_SYSTEM_HOME | The system-wde directory to store VMs and other persistent VirtCI, read-accessible by all users. | export VIRTCI_SYSTEM_HOME="/home/other_user/.vcisystem" |
| VIRTCI_QEMU_BINARY | Override the `qemu-system-<arch>` binary VirtCI launches. If unset, VirtCI resolves it from `PATH` (and known install locations on Windows). | export VIRTCI_QEMU_BINARY="/usr/bin/qemu-system-x86_64" |
| VIRTCI_QEMU_IMG_BINARY | Override the `qemu-img` binary VirtCI uses to create overlays. If unset, VirtCI resolves it from `PATH` (and known install locations on Windows). | export VIRTCI_QEMU_IMG_BINARY="/usr/bin/qemu-img" |
| VIRTCI_WSL_DISTRO | Windows host only. The WSL2 distribution used to run and store TPM-backed VMs.<br>If unset, VirtCI uses the default distro reported by `wsl -l -v`, which must be WSL version 2. | export VIRTCI_WSL_DISTRO="Ubuntu" |
| VIRTCI_WSL_USER_HOME | Windows host only. WSL-namespace (inside-the-distro) user-local directory for VMs and persistent VirtCI data when driving WSL2 from a Windows host.<br>Defaults to `$HOME/.local/share/vci` inside the distro. | export VIRTCI_WSL_USER_HOME="/home/user/.local/share/vci" |
| VIRTCI_WSL_SYSTEM_HOME | Windows host only. WSL-namespace (inside-the-distro) system-wide directory for VMs and persistent VirtCI data.<br>Defaults to `/var/lib/vci`. | export VIRTCI_WSL_SYSTEM_HOME="/var/lib/vci" |
| VIRTCI_WSL_TEMP | Windows host only. WSL-namespace (inside-the-distro) per-run temporary directory for Windows-host-driven runs.<br>Defaults to `/tmp/vci_wsl`, and is deliberately distinct from a native-in-WSL2 VirtCI's own temp directory. | export VIRTCI_WSL_TEMP="/tmp/vci_wsl" |
| VIRTCI_VM_START_IDLE_TIMEOUT | Number of seconds a `virtci run` or `virtci boot` will wait for serial progress if present. After that amount of seconds elapses, the VM is considered hanging.<br>Defaults to 120. | export VIRTCI_VM_START_MAX_TIMEOUT=240 |
| VIRTCI_VM_START_MAX_TIMEOUT | Maximum number of seconds a `virtci run` VM can take to boot, as a hard cutoff.<br>Defaults to 1800. | export VIRTCI_VM_START_MAX_TIMEOUT=3600 |
