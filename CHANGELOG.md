# Changelog

VirtCI adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `virtci copy` to copy files to and from actively running VMs. Supports all of the same functionality as the `virtci run` YAML `copy` step.
- Added workflow run caching for QEMU VMs only for `virtci run`, which writes opt-in workflow runs to LRU storage, allowing them to be used by subsequent runs to massively speed up runs.
  - Added `cache` field to the top level `job` YAML scheme for workflow files (same area where you define `image` and related fields). `cache` has the following sub-fields to determine whether a workflow can use the cache or not:
    - `files_modified` to check if a list of files have had their contents changed. Note, only the hash of the contents is stored.
    - `files_list` check if the actual list of files in a directory has changed. Supports globbing.
    - `env` check if any environment variables in a list have changed. Note, only hash of the variable is stored.
    - `max_age` Set the TTL of this cache. Postfix with `S`/`s` for seconds, `M`/`m` for minutes, `H`/`h` for hours, and `D`/`d` for days.
  - The cache can also become invalidated for a run with a few more conditions:
    - If the YAML file itself changes.
    - If the base image was modified.
    - If the TTL `max_age` has expired.
    - Storage limits reached, evicting least-recently-used caches (see the `VIRTCI_CACHE_BUDGET_GB` and `VIRTCI_CACHE_RETAIN_GB` environment variables below).
  - If a workflow was ran from a cache, it won't write a new one. In most cases it is unnecessary, and makes it easier to parallelize cache usage.
  - Integrate with git providers (GitHub, GitLab, Forgejo/Codeberg, Gitea, Bitbucket), reading each provider's CI environment variables.
  - Support cache namespaces, in which different workflows can produce independent caches, and the same workflow can write to different caches. A job's cache lives at `<namespace>/<job>/<image>`, so different namespaces never share cache slots.
  - If you are running through a git provider's CI, use the repo owner, repo name, and branch to determine the namespace (`{owner}/{repo}/{ref}`), so a PR can cache workflow steps.
  - If you are using git provider's CI, fork PRs are rejected from using workflow caches as a security precaution, detected from the git providers defined environment variables. This prevents an untrusted contributor from reading or poisoning a trusted cache.
  - Added `skip_if_cached` field to a run step to skip the execution of that step if running from a cache.
  - Added `--no-cache` flag to `virtci run` to run a workflow without using or producing any cache.
  - Added `--cache-namespace` flag to `virtci run` to set the cache namespace explicitly. Supports `{owner}`, `{repo}`, and `{ref}` tokens that are auto-filled from the detected git provider and sanitized (`--cache-namespace "thing/{repo}/{ref}"`). Defaults to `{owner}/{repo}/{ref}` when a git provider is detected.
  - If a cache can be produced, and would overwrite a previous cache, if another run is using the previous cache, do not write the cache. This is usually not necessary and avoids massive concurrency issues.
  - See [workflow_yaml_syntax.md](/docs/workflow_yaml_syntax.md#cache) for full details.
- `VIRTCI_CACHE_HOME` environment variable to specify where cache files (and staged ones) can be written to. This is within the VirtCI home directory by default. This is relevant as there are other environment variables to control cache disk usage, so they can live on a separate drive entirely.
- `VIRTCI_WSL_CACHE_HOME` environment variable to specify where WSL2 cache files (and staged ones) can be written to. This is within the VirtCI home directory by default.
- `VIRTCI_CACHE_SHUTDOWN_TIMEOUT` environment variable to control the maximum time a cacheable VM run can take to shutdown before the VM is killed and the cache write is skipped to avoid disk corruption. A run that can produce a cache needs the disk to not be corrupted, so that will try to gracefully shutdown the VM (flushing the disk) rather than SIGKILLing it.
- `VIRTCI_CACHE_BUDGET_GB` environment variable to control the maximum amount of storage the usable cache can actually take up. Does LRU eviction. By default, this is unset and VirtCI will use as much as it needs until it hits the low disk detection. Set to `0` to not check.
- `VIRTCI_CACHE_RETAIN_GB` environment variable to prevent writing usable cache storage if there is only that much space left on the disk that owns the cache directory (either `VIRTCI_CACHE_HOME`/`VIRTCI_WSL_CACHE_HOME` or within `VIRTCI_USER_HOME`/`VIRTCI_WSL_USER_HOME`/default location). If unset does low disk detection:
  - If the disk where the VirtCI run cache lives has less than 1,800 GB, ensure the user still has 1/8th of their disk available.
    - Disk = 512GB (about 477GB usable), retain about 60GB.
    - Disk = 1TB (about 931GB usable), retain about 116GB.
  - If the disk where the VirtCI run cache lives has greater than or equal to 1,800 GB, ensure the user still has 1/16th of their disk available.
    - Disk = 2TB (about 1862GB usable), retain about 116GB.
    - Disk = 4TB (about 3725GB usable), retain about 223GB.
- `virtci run` by default will now get environment variables from your `.env` file if it exists in the current working directory.
  - Environment variables local to the shell / process are prioritized over any in the `.env`.
- Added `--env-file` to `virtci run` to specify a file other than the current working directory `.env`.
- Added `--no-env-file` to `virtci run` which will prevent loading of any `.env` or `--env-file` files.
- Added growing the VM's disk parition in a `virtci run` with a `disk` field in both the top-level job description, and the VM `restart` step.

### Changed

- A `virtci run` step without a timeout no longer defaults to 2 hours. It will now run with no timeout.
- Will now retry while trying to boot a macOS VM with the Tart backend as it respects Apple's EULA outlined max macOS VMs on a single host of 2.
  - After about 2 hours, it will give up retrying.

### Fixed

- Fixed a `virtci run` step reaching a timeout not actually stopping the execution of the step inside the VM sometimes.
- Fixed YAML workflow `timeout` in a step not accepting integers.
- Fixed empty strings in a YAML workflow `timeout` setting the timeout to 2 hours silently.
- Fixed Windows `virtci run` boot progress detection being too strict and checking values that may not always get updated, leading to flakiness when booting some VMs, notably TCG emulated ones (those were the only occurrences observed).

### Known Issues

#### Maybe Not Issue

- Windows hosts may (or may not) experience disk corruption with overlays. We are unable to deterministically reproduce this, and are unsure if this impacts any observed flakiness using Windows hosts.
  - [QEMU Issue #813](https://gitlab.com/qemu-project/qemu/-/work_items/813). On windows, preallocation=full qcow2 not creatable, qcow2 not resizable.
  - [QEMU Issue #814](https://gitlab.com/qemu-project/qemu/-/work_items/814). On Windows, qcow2 is corrupted on expansion.
  - In VirtCI's own CI, we were encountering a lot of flakiness with our Windows runners, resulting in the VM booting into emergency mode, with NIC failure. This has stopped with [e443809](https://github.com/virtci/virtci/commit/e443809141d71c6f0f3a216bc4435eeed0b9cd11). It is possible this was just a mistake in our cloud init seed.iso.

## Version 0.3.1 - 2026-06-11

### Added

- More useful logs for if a VM failed to boot, rather than just reporting it being unable to be SSH'd into.
- Added warning when emualting arm64 VMs using older QEMU versions.
  - QEMU versions before 9.2 can fail when TCG emulating newer arm64 kernels.
- Added check for if using a QEMU binary built for a different host architecture.
  - It can fail for seemingly no reason under emulators like Prism, Rosetta 2, or FEX, but `qemu-system-* --version` works, leading to very confusing situations.
  - As of June 7th 2026, winget installs x86_64 built QEMU binaries (intended to run on x86_64 host) even on a Windows arm64 host.
- `VIRTCI_VM_START_IDLE_TIMEOUT` environment variable to control the time required for a VM start to be considered hanging if no boot progress is being made in seconds. Defaults to 120.
- `VIRTCI_VM_START_MAX_TIMEOUT` environment variable to control the maximum time a `virtci run` workflow can take to start a VM, aborting the run past that time in seconds. Defaults to 1800.
- `VIRTCI_SSH_CONNECT_TIMEOUT` environment variable to control the maximum time a VirtCI will wait to establish connection to the VM over SSH seconds. Defaults to 60 per SSH attempt.

### Changed

- MacOS default temp path moved to `/tmp/vci-<user_id>`.
  - Necessary due to swtpm socket path exceeding the maximum allowed on MacOS.
- Running a QEMU binary built for a different host architecture, running under translation layers is a fatal error and stops `virtci run` and `virtci boot` execution.
- The 600 second fixed VM boot to SSH detection has been replaced by a sliding window with maximum cutoff.
  - Now reads the serial log to determine if boot progress is being made, aborting after `VIRTCI_VM_START_IDLE_TIMEOUT` seconds if no progress has been made.
  - Has an absolute maximum cutoff seconds, configurable by the user of `VIRTCI_VM_START_MAX_TIMEOUT` only for `virtci run`, not for `virtci boot`.
  - SSH detection itself uses a real attempt for SSH connection, configurable by the user of `VIRTCI_SSH_CONNECT_TIMEOUT` to determine if a VM is ready for use.
  - Checks CPU time of the QEMU process to also determine if boot progress is happening.
  - Checks growth of the qcow2 disk overlay to also determine if boot progress is happening.
- `.vci` file `managed: bool` field deprecated. Ignored now.

### Fixed

- Fixed unconditional HVF acceleration on MacOS hosts, even if HVF acceleration isn't available.
- Fixed arm64 TCG emulation CPU selection unconditionally using `max`, which has issues on some host environments emulating newer kernels.
  - Default to `neoverse-n1` if the `qemu-system-aarch64` is version 7.0.0 or newer, otherwise fallback to `max` and warn.
- Creating a new VM that uses system UEFI vars will now make a copy in the managed VM directory.
  - Fixes an issue where creating a VM would have boot attempt to use the system UEFI vars, and fail for lack of permissions. It also shouldn't do that so that other VMs can have their own UEFI vars.

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
