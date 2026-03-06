# Contributing

Thank you for wanting to contribute to VirtCI!

VirtCI is licensed under the [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html). For any source code file you modify, please add your username / full name to the copyright holder's list.

If this is your first time contributing, you may want to look at the [VirtCI GitHub Good First Issue List](https://github.com/virtci/virtci/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22) for issues that can get you more familiar with the code base.

Feel free to tackle any [VirtCI GitHub Issue](https://github.com/virtci/virtci/issues), or create a new issue for something you feel is relevant.

## Environment Setup

### 1. Clone the Repo

```sh
git clone https://github.com/virtci/virtci.git
```

### 2. Install Rust

[Rust Getting Started](https://rust-lang.org/learn/get-started/).

### 3. Install a C compiler

**Mac**:

XCode build tools will install apple clang.

**Linux**:

Install gcc.

**Windows**:

Install MSVC through the Visual Studio build tools, or use mingw64 and install gcc. MSVC is preferred.

### 4. Install Node.js and NPM

Bun is not currently supported. If you would like to fix that, see the relevant [Issue](https://github.com/virtci/virtci/issues/15).

[Download Node.js and npm](https://nodejs.org/en/download).

### 5. Install QEMU and SWTPM

**Mac**:

```sh
brew install qemu swtpm
```

**Linux**:

*Debian / Ubuntu / Mint / Debian-based:*

```sh
sudo apt install qemu-kvm qemu-utils swtpm
```

*Other:*

VirtCI depends on qemu and swtpm on linux.

**Windows**:

[Download QEMU](https://www.qemu.org/download/#windows).

[Setup WSL2](https://learn.microsoft.com/en-us/windows/wsl/install)

Run the WSL SWTPM installer scripts. SWTPM cannot be built for windows natively at all, only working in WSL.

```powershell
.\scripts\install_swtpm_win.ps1
```

## Building and Testing

```sh
# Build
cargo build

# See all CLI commands
cargo run -- help

# Run Unit Tests
cargo test

# Run Integration Tests
./tests/upstream_image/fetch_debian_genericcloud.sh
cargo test -- --ignored
```

## LLM Policy

**Human in the loop always. An automated PR without any human to explain it in the PR comments, or oversee it, will be rejected.**

Use whatever tools work best for you, whether LLMs, Stack Overflow, Linux man pages, or anything else. You are responsible for every commit you submit regardless of how it was produced, including ensuring it adheres to licensing restrictions.

With that said, before implementing anything, it's important to weigh and discuss significant architectural or design decisions in the relevant issue. A quick patch is easy to merge, but a poor long-term approach is difficult to undo.

## Branch and Commit Conventions

Commits should have a short but clear summary, and ideally have a word describing what kind of commit it is. These can include "fix", "add", etc.

Branches similarly should have short names, and should be relevant to the issue they are addressing.

## Pull Request

Before opening a PR, ensure your code is linted and formatted correctly.

```sh
cargo clippy
cd web
npm run lint
```

In VSCode, cargo fmt and clang-format are automatically ran. To manually run cargo format, do the following.

```sh
cargo fmt
```

Also run clang-format.

```sh
# Mac / Linux
find src -name "*.c" -exec clang-format -i {} +
```

```powershell
# Windows Powershell
Get-ChildItem -Path src -Recurse -Filter *.c | ForEach-Object { clang-format -i $_.FullName }
```

Pull requests targeting main must be approved, but notably CI will only run with admin approval. This is for a few reasons.

All PRs are run on self-hosted hardware, making them much more vulnerable than GitHub's runners. In exchange they are way faster and can easily run VirtCI VMs. There have historically been many vulnerabilities surrounding pull requests.

| Vulnerability | Link | Description |
|---------------|------|-------------|
| Pwn Request | [Pwn Request StepSecurity.io](https://www.stepsecurity.io/blog/github-actions-pwn-request-vulnerability) | 1. Open a pull request<br>2. Checkout untrusted code,<br>3. Run it with elevated permissions, with access to SECRETS / TOKENS.<br><br>Notably this could impact the test runners / VM fetchers. |
| hackerbot-claw | [hackerbot-claw StepSecurity.io](https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation) | Used OpenClaw to automate the Pwn Request vulnerability. |
