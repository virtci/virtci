<div align="center">
  <img src="res/VirtCI-wordmark.png"/>
</div>

*VirtCI* is a CI/CD tool for running real OS images across multiple CPU architectures on self-hosted hardware.

- Configure CPU core count and Memory availability to emulate production environments.
- Toggle networking on the fly for true sandboxing.
- Runs on VM clones, so the base image is untouched, and many parallel VMs can be ran.
- Export VirtCI configurations with VM files to deploy across your servers.

Currently supports [QEMU](https://www.qemu.org/) and [Tart](https://tart.run/) as backends (*for tart, please read its [license conditions](https://github.com/cirruslabs/tart/blob/main/LICENSE)*).

## Getting Started

### Install

Install all necessary tooling for your OS:

#### Linux

**Debian / Ubuntu / Mint / Debian-based:**

```sh
sudo apt update
# For x64
curl -LO https://github.com/virtci/virtci/releases/latest/download/virtci-linux-x64.deb
sudo apt install ./virtci-linux-x64.deb
# For arm64
curl -LO https://github.com/virtci/virtci/releases/latest/download/virtci-linux-arm64.deb
sudo apt install ./virtci-linux-arm64.deb
```

**Other:**

[Build from source](/docs/build_from_source.md).

VirtCI depends on qemu and swtpm on linux.

*Useful:*

You may also choose to use [quickemu](https://github.com/quickemu-project/quickemu) to easily get started with pre-setup QEMU VM images.

#### MacOS

Install QEMU and Tart.

```sh
brew install virtci/virtci/virtci # Yes it's actually that command
```

*Useful:*

You may also choose to install [UTM](https://mac.getutm.app/) to easily get started with QEMU VMs.

#### Windows

Install QEMU

```sh
choco install qemu
```

Add chocolatey qemu to your PATH. The location is `C:\Program Files\qemu`

[Build from source](/docs/build_from_source.md), then run the `install_swtpm_win.ps1` powershell script. WSL2 is required, along with a linux distro within.

```sh
./scripts/install_swtpm_win.ps1
```

### Setup VM

Setup a QEMU or Tart VM through your method of choice. See [docs](/docs) for more details information on setting up from a platform specific ISO.

### Add VM to VirtCI

#### Add QEMU VM

```sh
virtci setup --qemu
# Follow the interactive setup.
# VirtCI will, by default, use the settings that are validated on common
# VM configurations across multiple operating systems and cpu architectures.
# VirtCI automatically scans your system files to find relevant UEFI files if necessary.
```

#### Add Tart VM

```sh
virtci setup --tart
# Follow the interactive setup.
# Since tart manages VMs itself, this is a lot simpler than the QEMU setup.
```

#### Create your Workflow

Since these are VMs, you're free to install whatever build tools you want on them.

```yml
# test-ubuntu-x64.yml
ubuntu-x64:
    image: ubuntu-server-x64
    cpus: 2
    memory: 6G
    # Not required, but get opt-in secrets from GitHub Actions, or whatever else
    host_env:
        - GITHUB_TOKEN
        - APP_P12_FILE_BASE64
        - APP_P12_PASSWORD
    steps:
        # Copy files from the relative directory to the VM's home directory
        - name: Copy Files
          copy:
            from: ./
            to: vm:~/
            exclude:
              - .git
              - .github
              - docs

        # Networking is enabled currently, so this will install CMake into the VM
        - name: Install CMake
          run: sudo apt install cmake

        # Any steps after this one will be run without networking
        # Networking can be reenabled by doing `offline: false`.
        - name: Run Subsequent Steps Offline
          offline: true

        - name: Configure CMake
          run: cmake -S . -B build

        # Build for 3600 seconds maximum (1 hour)
        - name: Build CMake
          run: cmake --build build
          timeout: 3600

        - name: Run CTest
          run: ctest --test-dir build --output-on-failure
```

#### Run Your Workflow

```sh
virtci run test-ubuntu-x64.yml
```

#### Add to Self-Hosted Git CI/CD

For example, with GitHub Actions:

```yml
# .github/workflows/ci.yml
name: "CI"

on:
    workflow_dispatch:
    pull_request_target:
        branches:
            - main
    push:
        branches:
            - main

test-ubuntu-x64:
    # Here, the runs-on target is just whatever you have your runner set to
    # In this case, it's an x64 windows server, but anything works.
    runs-on:
        - self-hosted
        - Windows
        - X64
    env:
        # VirtCI can get opt-in secrets, such as for code signing
        APP_ID: ${{ secrets.APP_ID }}
        APP_PK: ${{ secrets.APP_PK }}
        APP_P12_FILE_BASE64: ${{ secrets.APP_P12_FILE_BASE64 }}
        APP_P12_PASSWORD: ${{ secrets.APP_P12_PASSWORD }}
        WORK_DIR: ${{ github.workspace }}/runs/${{ github.run_id }}

    steps:
        - name: Setup workspace
          run: |
            mkdir -p ${{ env.WORK_DIR }}
            cd ${{ env.WORK_DIR }}

        - name: Checkout code
          uses: actions/checkout@v4
          with:
            ref: ${{ github.event.pull_request.head.sha || github.sha }}
            path: ${{ env.WORK_DIR }}/repo
            clean: true

        - name: Run Ubuntu Tests
          working-directory: ${{ env.WORK_DIR }}/repo
          run: virtci run test-ubuntu-x64.yml
```

## QEMU vs Tart

Tart is only available on MacOS hosts, and right now is the simplest option for setting up MacOS Arm64 virtual machines. QEMU MacOS Arm64 support is not yet reliable.

For everything other than MacOS Arm64, QEMU works extremely well. If you would rather use Tart for Linux VMs, do so, but using QEMU VMs gives the best portability in the event you want to transfer Linux VMs to a Linux or Windows server host, leveraging `virtci export`.

## Why

I don't want to pay hosting fees for projects with a vast amount of CI. I wanted a way to easily run CI scripts for testing or deployment across as many architectures (notably riscv64) and operating systems as possible, so I made this to do my CI/CD on my own hardware.

This allows running CI/CD real OS images, as well as cross-architecture without having to go buy a bunch of machines myself. For most use cases, this is sufficient. If virtualization / emulation is not sufficient, you probably know what you are doing.

Obviously, if your only target is Linux and you're making a SaaS product, emphemeral docker containers or something would also work very well. This provides a solution to a niche problem.
