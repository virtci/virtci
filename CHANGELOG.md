# Changelog

VirtCI adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

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
