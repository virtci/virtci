# Changelog

VirtCI adheres to [Semantic Versioning](https://semver.org/).

## Version 0.1.0

### Added

#### System-wide VM Storage

Support importing a VM into system-wide storage, accessible by all users using `virtci import some_file.tar --system`. Runs will check the user-local directory first, then check the system-wide one.

Does not work for Tart backends.

#### Run Copy Step Make Directories

The `copy` step in the yaml workflows will, by default, create the directories on the target that is necessary in order to copy the files / directories. The `no_mkdir` boolean option can be set to `true` to disable this functionality, causing a failure if the directories do not exist, in which the copy would fail.

#### Run Copy Step Globbing

The `copy` step in the yaml workflows now supports file globbing. If the glob returns zero files, this is a hard error, unless `allow_empty` boolean option is set to `true`.

## Version 0.0.0 - 2026-03-03

Initial public release of VirtCI. Tested and ran in production environments.

### Added

- `version` Get the VirtCI version
- `run` Run a workflow file
- `setup` Interactive setup for a new VM image description
- `cleanup` Clean up leftover temporary VM images
- `list` List all configured VM images
- `export` Export a VM image and its files to a .tar archive
- `import` Import a VM image from a .tar archive
- `active` List all currently running VirtCI jobs
- `remove` Remove a VirtCI VM image
- `boot` Boot a base VM image to modify it, found using `virtci list`
- `shell` SSH into a running VM by job name
