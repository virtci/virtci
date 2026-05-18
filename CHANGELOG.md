# Changelog

VirtCI adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- Provide setup guide for a RISC-V64 Linux VM in [riscv64_linux_setup.md](/docs/riscv64_linux_setup.md).

### Fixed

- RISC-V64 QEMU Setup has more accurate defaults.

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
