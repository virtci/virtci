# VCI Virtual Machine CI Runner

I don't want to pay hosting fees for projects with a vast amount of CI. I wanted a way to easily run CI scripts for testing or deployment using VMs, so I made this to do my CI/CD on my own hardware.

This allows running CI/CD real OS images, as well as cross-architecture without having to go buy a bunch of machines myself. For most use cases, this is sufficient. If virtualization / emulation is not sufficient, you probably know what you are doing.

Disabling networking for part of the workflow is also possible, and is incredibly useful when testing untrusted PRs or otherwise.

Currently just supports QEMU.

## Example CI Script

```yaml
# test_windows.yml
windows-11-x64:
    image: ~/Documents/windows-11-x64.qcow2
    arch: amd64
    cpus: 2
    memory: 8G
    user: dev
    pass: dev
    steps:
        - name: Install Test Script
          copy:
            from: ./test/test.ps1
            to: vm:/test/test.ps1

        - name: Run Subsequent Steps Offline
          offline: true

        - name: Run Test Script on VM
          run: ./test/test.ps1

windows-11-arm64:
    image: ~/Documents/windows-11-arm64.qcow2
    arch: arm64
    cpus: 2
    memory: 8G
    user: dev
    pass: dev
    steps:
        - name: Install Test Script
          copy:
            from: ./test/test.ps1
            to: vm:/test/test.ps1
            
        - name: Run Test Script on VM
          run: ./test/test.ps1
```

```sh
# Runs both windows-11-x64 and windows-11-arm64 QEMU Vms
vci run test_windows.yml

# Override, using 4 threads instead of 2 that is specified by default
vci run test_windows.yml --cpus windows-11-arm64=4
```

## Install

Make sure you have [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

```sh
# Install from source
git clone https://github.com/gabkhanfig/vci.git
cd vci
cargo install --path .
```

## All Options

| Environment Variable | Description |
|----------------------|-------------|
| VCI_QEMU_BINARY | Full path to the QEMU binary / executable |
| VCI_UEFI_FIRMWARE_DIR | Path to UEFI firmware that may be needed for QEMU |

### All CLI Options

#### `vci run`

```sh
vci run path/to/workflow.yaml [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--image <path>` | VM disk image (global) |
| `--image <job>=<path>` | VM disk image (per-job) |
| `--cpus <n>` | CPU count (global, default: half system threads) |
| `--cpus <job>=<n>` | CPU count (per-job) |
| `--mem <size>` | Memory e.g. `2G`, `512M` (global, default: 8G) |
| `--mem <job>=<size>` | Memory (per-job) |
| `--ssh-user <user>` | SSH username (global) |
| `--ssh-user <job>=<user>` | SSH username (per-job) |
| `--ssh-password <pass>` | SSH password (global) |
| `--ssh-password <job>=<pass>` | SSH password (per-job) |
| `--ssh-key <path>` | SSH private key (global) |
| `--ssh-key <job>=<path>` | SSH private key (per-job) |
| `--ssh-port <port>` | SSH port (global, default: 22) |
| `--ssh-port <job>=<port>` | SSH port (per-job) |
| `--arch <arch>` | VM architecture (global, default: host arch) `x86_64`, `x64`, `amd64`, `aarch64`, `arm64`, `riscv64` |
| `--arch <job>=<arch>` | VM architecture (per-job) `x86_64`, `x64`, `amd64`, `aarch64`, `arm64`, `riscv64` |

#### `vci cleanup`

VCI does its best to cleanup in any possible failure, but hardware failure is also possible, and not something that can reasonably be accounted for in this case. `vci cleanup` is to be used to delete ANY `vci` VM file in the temporary directories.

```sh
vci cleanup
```

| Option | Description |
|--------|-------------|
| `--list` | List any file flagged for deletion |
| `--force` | Forcibly delete all flagged file, rather than manually confirming |

### All YAML Options

#### Job Configuration

Each top-level key is a job name. Jobs run sequentially (for now).

```yaml
job-name:
  image: ~/path/to/image.qcow2      # VM disk image
  arch: x86_64                      # optional: architecture (default: host arch)
  cpus: 2                           # optional: CPU count
  memory: 8G                        # optional: Memory (e.g., 2G, 512M) (default: 8G)
  user: root                        # SSH username
  pass: secret                      # optional: SSH password (alternative to key)
  key: ~/.ssh/id_ed25519            # optional: SSH private key (alternative to pass)
  port: 22                          # optional: SSH port
  uefi: true                        # optional: UEFI firmware (see UEFI section below)
  tpm: true                         # optional: Enable TPM 2.0 emulation (requires swtpm)
  steps:                            # List of steps to execute
    - ...
```

`arch` may be one of: `x86_64`, `x64`, `amd64`, `aarch64`, `arm64`, `riscv64`

##### UEFI Firmware Configuration

The `uefi` field supports three modes:

**Auto-detect system UEFI:**

```yaml
uefi: true    # finds system OVMF.md
uefi: false   # no firmware
```

**Monolithic UEFI file:**

```yaml
uefi: /usr/share/ovmf/OVMF.fd    # monolithic file used by some stuff
```

**Split code/vars (recommended for macOS, Windows, Secure Boot):**

```yaml
uefi:
  code: ~/path/to/OVMF_CODE.fd    # readonly firmware code
  vars: ~/path/to/OVMF_VARS.fd    # writeable NVRAM variables (gets copied)
```

The split mode adheres to [UEFI pflash conventions](https://github.com/tianocore/tianocore.github.io/wiki/How-to-run-OVMF), creating a temporary copy of the vars file for each VM instance.

##### TPM 2.0 Emulation

Enables TPM 2.0 emulation for VMs that need it like Windows 11

```yaml
tpm: true    # Enables TPM 2.0 via swtpm
```

`swtpm` must be installed on the host system

- Linux: `apt install swtpm` or `dnf install swtpm` or whatever else
- macOS: `brew install swtpm`

```yaml
windows-11-x64:
  image: ~/path/to/windows-11.qcow2
  uefi:
    code: /usr/share/OVMF/OVMF_CODE_4M.ms.fd
    vars: /usr/share/OVMF/OVMF_VARS_4M.ms.fd
  tpm: true
  cpus: 4
  memory: 8G
  user: dev
  pass: dev
  steps:
    - ...
```

##### Advanced QEMU Configuration

For advanced use cases like [macOS virtualization in QEMU](docs/mac_x64_setup.md), more fields are available:

```yaml
job-name:
  # other config

  # set the CPU model
  cpu_model: "Haswell-v2,vendor=GenuineIntel,vmware-cpuid-freq=on"

  # additional QEMU drive arguments, such as OpenCore for the again mac stuff. Adds more -drive
  additional_drives:
    - "id=BootLoader,if=none,format=qcow2,file=~/path/to/OpenCore.qcow2"

  # extra devices. Adds more -device
  additional_devices:
    - "isa-applesmc,osk=ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"
    - "ahci,id=ahci"
    - "ide-hd,bus=ahci.0,drive=BootLoader,bootindex=0"
    - "virtio-blk-pci,drive=SystemDisk"

  # raw QEMU arguments for edge cases
  qemu_args:
    - "-k"
    - "en-us"
```

**macOS Example:**

See [`docs/mac_x64_setup.md`](docs/mac_x64_setup.md) for a complete macOS CI/CD setup example.

```yaml
macos-monterey:
  image: ~/vm/macos/disk.qcow2
  uefi:
    code: ~/vm/macos/OVMF_CODE.fd
    vars: ~/vm/macos/OVMF_VARS-1920x1080.fd
  cpu_model: "Haswell-v2,vendor=GenuineIntel,vmware-cpuid-freq=on"
  additional_drives:
    - "id=BootLoader,if=none,format=qcow2,file=~/vm/macos/OpenCore.qcow2"
  additional_devices:
    - "isa-applesmc,osk=ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"
    - "ahci,id=ahci"
    - "ide-hd,bus=ahci.0,drive=BootLoader,bootindex=0"
    - "virtio-blk-pci,drive=SystemDisk"
  cpus: 4
  memory: 16G
  user: dev
  pass: devmac
  steps:
    - run: clang
```

#### Step Types

##### `run` - Execute command via SSH

```yaml
- name: Build project          # optional: display name
  run: make build              # required: command to execute
  workdir: /app/src            # optional: working directory
  timeout: 10m                 # optional: step timeout
  env:                         # optional: environment variables
    CC: clang
    DEBUG: "1"
  continue_on_error: false     # optional: continue if step fails (default: false)
```

##### `copy` - Transfer files via SFTP

```yaml
# Host to VM
- name: Upload source          # optional: display name
  copy:
    from: ./src/               # required: source path
    to: vm:/app/src/           # required: destination (vm: prefix for VM paths)
    exclude:                   # optional: exclude patterns
      - "*.o"
      - "*.a"
      - "build/"
  timeout: 5m                  # optional: step timeout
  continue_on_error: false     # optional: continue if step fails (default: false)

# VM to Host
- name: Download artifacts
  copy:
    from: vm:/app/build/output
    to: ./artifacts/binary
```

##### `offline` - Toggle network isolation

Restarts the VM with network restricted (SSH still works for access but outbound blocked), OR restored.

```yaml
- offline: true    # network isolation
- offline: false   # normal network access
```
