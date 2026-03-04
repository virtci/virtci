# Changelog

VirtCI adheres to [Semantic Versioning](https://semver.org/).

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
