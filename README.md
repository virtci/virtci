# VCI Virtual Machine CI Runner

I don't want to pay hosting fees for projects with a vast amount of CI. I wanted a way to easily run CI scripts for testing or deployment using VMs, so I made this to do my CI/CD on my own hardware.

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

### All CLI Options

```sh
vci run <workflow.yaml> [OPTIONS]
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
  steps:                            # List of steps to execute
    - ...
```

`arch` may be one of: `x86_64`, `x64`, `amd64`, `aarch64`, `arm64`, `riscv64`

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
