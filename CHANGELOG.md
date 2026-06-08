# Changelog

VirtCI adheres to [Semantic Versioning](https://semver.org/).

## Version 0.3.1 - 2026-06-07

### Added

- More useful logs for if a VM failed to boot, rather than just reporting it being unable to be SSH'd into.
- Added warning when emualting arm64 VMs using older QEMU versions.
  - QEMU versions before 9.2 can fail when TCG emulating newer arm64 kernels.
- Added check for if using a QEMU binary built for a different host architecture.
  - It can fail for seemingly no reason under emulators like Prism, Rosetta 2, or FEX, but `qemu-system-* --version` works, leading to very confusing situations.
  - As of June 7th 2026, winget installs x86_64 built QEMU binaries (intended to run on x86_64 host) even on a Windows arm64 host.
- `VIRTCI_VM_START_IDLE_TIMEOUT` environment variable to control the time required for a VM start to be considered hanging if no boot progress is being made. Defaults to 120.
- `VIRTCI_VM_START_MAX_TIMEOUT` environment variable to control the maximum time a `virtci run` workflow can take to start a VM, aborting the run past that time. Defaults to 1800.

### Changed

- MacOS default temp path moved to `/tmp/vci-<user_id>`.
  - Necessary due to swtpm socket path exceeding the maximum allowed on MacOS.
- Running a QEMU binary built for a different host architecture, running under translation layers is a fatal error and stops `virtci run` and `virtci boot` execution.
- The 600 second fixed VM boot to SSH detection has been replaced by a sliding window with maximum cutoff.
  - Now reads the serial log to determine if boot progress is being made, aborting after `VIRTCI_VM_START_IDLE_TIMEOUT` seconds if no progress has been made.
  - Has an absolute maximum cutoff seconds, configurable by the user of `VIRTCI_VM_START_MAX_TIMEOUT` only for `virtci run`, not for `virtci boot`.

### Fixed

- Fixed unconditional HVF acceleration on MacOS hosts, even if HVF acceleration isn't available.
- Fixed arm64 TCG emulation CPU selection unconditionally using `max`, which has issues on some host environments emulating newer kernels.
  - Default to `neoverse-n1` if the `qemu-system-aarch64` is version 7.0.0 or newer, otherwise fallback to `max` and warn.

## Version 0.3.0 - 2026-06-06

### Added

- Validate YAML run workflow without actually running it with `virtci run <workflow_yaml> --validate`.
- Do a full VM clone with `virtci clone <image> <new_image>`.
  - Useful for persisting modifications in a VM without having to change the base.
- Rename a VM image locally with `virtci edit <image> --rename <new_name>`.
  - Crash safe, even for SIGKILL.
- Support running UEFI VMs directly on Windows hosts, not just inside WSL2.
  - Only used if WSL2 KVM acceleration isn't available, and disables WHPX acceleration, so uses much slower TCG emulation.
  - Useful for running VMs inside of windows VMs.

### Fixed

- Fixed issue where Windows Host couldn't access VM-inside-WSL2 over SSH with various WSL2 configurations.
- Fixed stdout/stderr formatting in some terminals during workflow runs.
- Fixed `virtci active` not correctly tracking active workflows on Windows.
- Fixed Windows not finding system RISC-V64 UEFI files.
- Fixed issue where VirtCI would take a while to find a valid QEMU TCP port due to WinNAT/Hyper-V reservation table.
- Fixed issue where workflow run setting the VM offline did not work when running on a Windows host through WSL2.

## Version 0.2.0 - 2026-05-30

### Added

- Provide setup guide for a RISC-V64 Linux VM in [riscv64_linux_setup.md](/docs/riscv64_linux_setup.md).
- Detect if a user is using UEFI firmware with secure boot, which does not work on Windows or WSL2 hosts.
  - Warns that it will be substituted on run / boot.

### Fixed

- RISC-V64 QEMU Setup has more accurate defaults.
- Fixed Windows `crlf` copy flag not working on Windows host's correctly.
- Fixed occasional QEMU port binding failure.
- Fixed Windows being unable to run TPM or UEFI enabled VMs.
  - Now, TPM or UEFI VMs are ran through WSL2, being invoked on the Windows host.
  - Secure Boot VMs are strictly not supported, and likely will never be as Windows Hosts and WSL2 lack SMM.
- Longer timeout for emulated VMs to give them time to connect and boot.

## Version 0.1.0 - 2026-05-11

### Added

- System-wide VM storage.
  - Accessible by all users for workflow usage and clone boot.
  - Import new VMs with `virtci import some_file.tar --system`
  - Workflow runs will check the user-local directory first, then check the system-wide one.
  - Does not work for Tart backends.
- Run `copy` step will create the necessary directory hiearchy on the target by default.
  - Set the `no_mkdir` boolean option to `true` to disable this functionality, causing a failure if the directories do not exist on the target.
- Run `copy` step supports file globbing.
  - If the glob returns zero files, this is a step error.
  - Set the `allow_empty` boolean option to `true` to not fail on empty glob.
- CLI sub-command `boot` now supports `--clone` to boot a clone of the VM.
  - Ran with `virtci boot <name> --clone`.
  - Compatible with `--cpus`, `--mem`, and `--offline`.
- CLI sub-command `boot` now supports `--cpus`, `--mem`, and `--offline` for resource constraining.
  - Ran with `virtci boot <name> --cpus 10 --mem 16G --offline`.
  - `--cpus` has the same requirements as the top-level job `cpus` field.
  - `--mem` has the same requirements as the top-level job `memory` field.
  - `--offline` if present, disabled networking for the boot.
  - Compatible with `--clone`.

### Changed

- Run `offline` step changed to `restart` step, supporting custom resource modifications.
  - Use the `offline` boolean option within the `restart` step to set networking capabilities like before.
  - Use the `cpus` field to set the new amount of cpu cores for the VM, persisting across restarts until modified.
  - Use the `memory` field to set the new memory capacity for the VM, persisting across restarts until modified.

### Fixed

- Incorrect description in `virtci remove`.
- Edge-case for incorrect SSH detection with a slow enough VM (emulated).
- Send SIGTERM to QEMU properly to prevent qcow2 file corruption.

### Known Issues

- Windows hosts does not support VMs that use TPM ([see #30](https://github.com/virtci/virtci/issues/30)).
  - Use WSL instead, and enable nested virtualization (only works in Windows 11).

## Version 0.0.0 - 2026-03-03

Initial public release of VirtCI. Tested and ran in production environments.

### Added

- `version` Get the VirtCI version.
- `run` Run a workflow file.
- `setup` Interactive setup for a new VM image description.
- `cleanup` Clean up leftover temporary VM images.
- `list` List all configured VM images.
- `export` Export a VM image and its files to a .tar archive.
- `import` Import a VM image from a .tar archive.
- `active` List all currently running VirtCI jobs.
- `remove` Remove a VirtCI VM image.
- `boot` Boot a base VM image to modify it, found using `virtci list`.
- `shell` SSH into a running VM by job name.
