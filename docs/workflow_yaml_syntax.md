# Workflow YAML Syntax

VirtCI YAML Syntax is very similar to GitHub Actions YAML syntax.

## `job`

The name of a job. This is the highest level field in the YAML file, and is used to identify and SSH into a workflow run. Multiple jobs are allowed in a single workflow YAML file, in which each one will be ran in order.

```yaml
# Complete reference (every field optional unless noted)
# test.yml
ubuntu-x64:                 # job name (required, top-level key)
  image: ubuntu-server-x64  # required. from `virtci list`
  cpus: 2                   # default cores/2 or 1
  memory: 6G                # default 8G; suffix G/g or M/m
  host_env: [GITHUB_TOKEN]  # env vars to forward into the VM
  steps:                    # required. runs in order
    - run: echo Hi

windows-x64:                # Many jobs in one file is permitted
  image: windows-11-x64
  cpus: 4
  memory: 16G
  host_env:
    - AZURE_CODE_SIGNING_ACCOUNT_NAME
    - AZURE_CERTIFICATE_PROFILE_NAME
    - AZURE_CLIENT_ID
    - AZURE_CLIENT_SECRET
    - AZURE_TENANT_ID
  steps:
    - run: Write-Output "Hi"
```

## `image`

The actual VM image that will be used. Must exist on disk, and can be found by running `virtci list`.

```sh
# Get the VirtCI images available on this system.
$ virtci list
ubuntu-server-x64
windows-11-x64
mac-x64
```

```yaml
ubuntu-x64:
  image: ubuntu-server-x64
  # Rest of workflow ...
```

## `cpus`

Defaults to half the available system cores, or 1, whichever is greater.

The number of cores that the VM will get on initial startup. Must be a positive non-zero integer.

```yaml
ubuntu-x64:
  image: ubuntu-server-x64
  cpus: 2
  # Rest of workflow ...
```

## `memory`

Defaults to 8GB.

The amount of RAM in megabytes the VM will get on initial startup. If post-fixed with a 'G' or 'g', will be as gigabytes instead. If post-fixed with an 'M' or 'm', will be as megabytes, just with explicitness. The numerical part of the string must be a positive non-zero integer.

```yaml
ubuntu-x64:
  image: ubuntu-server-x64
  cpus: 4
  memory: 6G # or '6144M' or just '6144'
  # Rest of workflow ...
```

## `host_env`

Array of environment variables to copy from the host into the VM.

```yaml
windows-x64:
  image: windows-11-x64
  cpus: 4
  memory: 12G
  host_env:
    - GITHUB_TOKEN
    - SOME_OTHER_HOST_ENVIRONMENT_VARIABLE
  # Rest of workflow ...
```

## `cache`

Defaults to empty (produces no cache, and cannot use a cache).

Opt this job into workflow run caching. When enabled, a successful run writes its VM state (the QEMU disk overlay, UEFI vars, and any additional drives) into long-term LRU storage. A later run of the same job, against the same image, in the same [namespace](#cache-namespaces), can skip straight to that cached VM state instead of executing the workflow again from scratch, which can massively speed up runs.

A cache is only usable if none of its inputs have changed since it was written. Some inputs are checked implicitly and are not configurable:

- The workflow YAML file's contents changed.
- The base VM image (its backing qcow2 / backend identity) was modified.
- The cache's TTL (see [`max_age`](#cachemax_age)) has expired.
- The [namespace](#cache-namespaces) differs.
- Storage limits evicted it (see [cache storage](#cache-storage)).

The `cache` block adds your own invalidation inputs on top of those. If you set none of the sub-fields, the job still caches, keyed only on the implicit inputs above.

```yaml
ubuntu-x64:
  image: ubuntu-server-x64
  cache:
    files_modified:
      - Cargo.lock
      - rust-toolchain.toml
    files_list:
      - "src/**/*.rs"
    env:
      - RUSTFLAGS
    max_age: 7D
  steps:
    - name: Fetch and build dependencies
      run: cargo build --release
      # Skip this expensive step entirely on a cache hit
      skip_if_cached: true
```

A run that was served from a cache will never write a new cache. This is almost always unnecessary, and it makes parallel jobs reading the same cache simpler and safer.

### `cache.files_modified`

Defaults to empty.

An array of files whose contents are tracked on the host system. If the hash of any listed file's contents changes, the cache is invalidated. A file that is missing at capture time is recorded as missing (and matches only if still missing later). Paths are resolved relative to the working directory the run was invoked from.

Only the hash of the contents is stored, never the contents themselves.

```yaml
cache:
  files_modified:
    - Cargo.lock
    - package-lock.json
```

### `cache.files_list`

Defaults to empty.

An array of glob patterns whose set of matching file names is tracked (not their contents) on the host system. Adding or removing a matching file invalidates the cache, whereas editing the contents of an already-matched file does not (use [`files_modified`](#cachefiles_modified) for that). Useful for catching a newly added source file that should trigger a rebuild.

```yaml
cache:
  files_list:
    # Invalidate when a C++ source is added or removed
    - "src/**/*.cpp"
    - "src/**/*.hpp"
```

### `cache.env`

Defaults to empty.

An array of environment variable names. If the hash of any listed variable's value changes, the cache is invalidated. An unset variable is recorded as unset (and matches only if still unset later).

Only the hash of the value is stored, never the value itself, so this is safe to use with secrets.

```yaml
cache:
  env:
    - RUSTFLAGS
    - NODE_ENV
```

### `cache.max_age`

Defaults to no expiry.

A string setting the TTL (time-to-live) of a cache this job writes. Once a cache is older than this, it is treated as a miss. A bare integer is interpreted as days. A post-fix overrides the unit:

- `S`/`s` = seconds
- `M`/`m` = minutes
- `H`/`h` = hours
- `D`/`d` = days

```yaml
cache:
  # Rebuild from scratch at least weekly
  max_age: 7D
```

```yaml
cache:
  # 90 minutes
  max_age: 90M
```

### Cache Namespaces

A namespace isolates caches. Different namespaces never share cache slots. A job's cache slot lives at `<namespace>/<job>/<image>`.

The namespace is resolved in this order:

1. `--no-cache` on the command line disables caching entirely even if the workflow supports it.
2. If the run is detected as a fork / external pull request, caching is disabled unconditionally. Caches are never shared with forks, so an untrusted contributor can neither read a trusted cache nor set one maliciously.
3. `--cache-namespace <template>` on the command line, if given. The template may contain `{owner}`, `{repo}`, and `{ref}` tokens, which are auto-filled from the detected git provider and sanitized. For example `--cache-namespace "hi/{repo}/{ref}"`. A template that uses a token with no git provider to fill it disables caching rather than collapsing distinct refs together.
4. Otherwise, if a git provider CI environment is detected, the namespace defaults to `{owner}/{repo}/{ref}`. This lets each branch (and each PR) accumulate and reuse its own cache.
5. If none of the above yields a namespace, such as a local run with no `--cache-namespace`, caching is disabled.

Detected git providers are GitHub Actions, GitLab CI, Forgejo/Codeberg Actions, Gitea Actions, and Bitbucket Pipelines, read from each provider's CI environment variables.

### Cache Storage

Caches are written under `VIRTCI_CACHE_HOME` (or `VIRTCI_WSL_CACHE_HOME` for WSL2-hosted VMs), defaulting to a directory inside the VirtCI user / wsl2 user home. Storage is bounded and least-recently-used entries are evicted first:

- `VIRTCI_CACHE_BUDGET_GB` caps the total usable cache size. Unset uses as much as available (subject to the retention floor below); `0` disables the cap.
- `VIRTCI_CACHE_RETAIN_GB` refuses to write new cache entries once the disk holding the cache has less than this much free space. Unset applies an automatic low-disk floor (1/8 of the disk under 1,800 GB, 1/16 at or above) and `0` disables the check.

See [env_vars.md](/docs/env_vars.md) for the full list, including `VIRTCI_CACHE_SHUTDOWN_TIMEOUT`.

## `steps`

Array of steps to execute in top-to-bottom order.

A step must have exactly one of [run](#stepsrun), [copy](#stepscopy), or [restart](#stepsrestart).

```yaml
windows-x64:
  image: windows-11-x64
  cpus: 2
  memory: 8G
  steps:
    # The actual steps to execute, must have at least one
```

### `steps.name`

The optional string name of the step.

```yaml
steps:
  - name: Say Hi
    run: echo Hi
```

### `steps.run`

A string containing the shell command to run inside the VM, or the YAML standard pipe `|` character for multi-line strings, which the VM shell executes as multiple statements.

```yaml
steps:
  - run: echo hi
```

```yaml
steps:
  - name: APT
    run: |
      sudo apt update
      sudo apt install build-essential
```

### `steps.copy`

Copy files from the host to the VM, or from the VM to the host, using tar-over-ssh.

```yaml
steps:
  - name: Copy Files
    copy:
      from: ./
      to: vm:~/
```

#### `steps.copy.from`

Required string field.

Specifies the directory or files or file glob pattern to copy from the host to the VM, or from the VM to the host.

If you want to copy from the **VM to the host**, prefix the entire string with `vm:`, otherwise omit that.

Exactly one of the [from](#stepscopyfrom) and [to](#stepscopyto) must be prefixed with `vm:`. If neither have it, or both have it, this is a fatal condition, terminating the workflow.

```yaml
steps:
  - name: Copy Files to VM
    copy:
      from: ./ # From the host's current working directory
      to: vm:~/
```

```yaml
steps:
  - name: Copy Files to Host
    copy:
      from: vm:~/ # From the VM's home directory
      to: ./
```

#### `steps.copy.to`

Required string field.

Specifies the directory or files or file glob pattern to write the files into from the host to the VM, or from the VM to the host.

If you want to copy from the **host to the VM**, prefix the entire string with `vm:`, otherwise omit that.

Exactly one of the [from](#stepscopyfrom) and [to](#stepscopyto) must be prefixed with `vm:`. If neither have it, or both have it, this is a fatal condition, terminating the workflow.

```yaml
steps:
  - name: Copy Files to VM
    copy:
      from: ./
      to: vm:~/ # To the VM's home directory
```

```yaml
steps:
  - name: Copy Files to Host
    copy:
      from: vm:~/
      to: ./ # To the host's current working directory
```

#### `steps.copy.exclude`

Defaults to empty.

An array of directories or files to exclude from the file copies.

```yaml
steps:
  - name: Copy Files to VM Exclude Unnecessary
    copy:
      from: ./
      to: vm:~/
      exclude:
        - .git
        - .github
        - docs
```

#### `steps.copy.crlf`

Defaults to `false`.

If `false`, no line-ending conversion happens. If `true`, text files are normalized to the destination's convention. Conversion only runs when host and guest disagree:

Host to VM:

- **Windows VM copied from non-Windows host**: CRLF, converted in-guest after the files are extracted.
- **Unix VM (Linux/macOS/etc) copied from a Windows host**: LF, converted by rewriting the transfer archive in memory before sending. Keeps shell scripts from arriving with `\r` that breaks `/bin/sh`.

VM to Host:

- **Windows VM copied to a non-Windows host**: LF, converted by rewriting the received archive in memory before local extraction.
- **Unix VM copied to a Windows host**: CRLF, converted by rewriting the received archive in memory before local extraction.

Binary files (detected by a null-byte scan) and the source files on disk are never modified so only the in-flight tar is converted.

```yaml
steps:
  - name: Copy Files to VM with CRLF conversion
    copy:
      from: ./
      to: vm:~/
      crlf: true
```

#### `steps.copy.no_mkdir`

Defaults to `false`

If `false`, the copy step will create the necessary directory tree for the copy's `to` target. If this boolean is set to `true`, will not make the necessary directory tree, failing if a file cannot be copied to the corresponding directory.

```yaml
steps:
  - name: Copy Only Web Source Files
    copy:
      from: ./web/src
      to: vm:~/ # Will create ~/web/src
```

```yaml
steps:
  - name: Copy Only Web Source Files
    copy:
      from: ./web/src
      to: vm:~/
      # Will fail, as it cannot create ~/web/src
      no_mkdir: true
```

#### `steps.copy.allow_empty`

Defaults to `false`.

If `false` and a glob pattern is used, it will cause a step failure if the glob returns 0 entries. If `true`, allows the glob to return 0.

```yaml
steps:
  - name: Copy Executables to Host
    copy:
      # Will fail if there are no .exe files
      from: vm:~/build/**/*.exe
      to: ./
```

```yaml
steps:
  - name: Copy Executables to Host
    copy:
      # Won't copy anything if there are no .exe files, but will continue to next step.
      from: vm:~/build/**/*.exe
      to: ./
      allow_empty: true
```

### `steps.restart`

Restarts the VM.

```yaml
steps:
  - restart: {}
```

#### `steps.restart.offline`

Defaults to null.

Can contain either `null`, or a boolean value. If `null`, retains the current networking capabilities of the VM prior to restarting. If `false`, enables networking if it was disabled. If `true`, disables networking if it was enabled.

If `offline` is set to `true`, as the first workflow step, the VM will be initially booted without networking.

```yaml
steps:
  # Since this `offline` is the first step, boots without networking
  - restart:
      offline: true
  # Restarts again, and re-enables networking
  - restart:
      offline: false
```

#### `steps.restart.cpus`

Defaults to null.

Can contain either `null` or a positive non-zero integer value. If `null`, retains the current cpu cores of the VM prior to restarting, otherwise sets the VM to boot with the new number of cores.

If `cpus` is set to some value as the first workflow step, the VM will be initially booted with that amount of cores. This is kind of silly but it works.

```yaml
steps:
  - name: Install CMake
    run: sudo apt update && sudo apt install cmake

  - name: Restart With More Cores for Parallel Compile
    restart:
      cpus: 4

  - name: Compile
    run: cmake -B build && cmake --build build --parallel

  - name: Restart With More Memory for Tests
    restart:
      # Note that cpu cores stays at 4 from the previous step
      memory: 12G
```

#### `steps.restart.memory`

Defaults to null.

Can contain either `null` or a string containing a positive non-zero integer value, and an optional post-fix. If `null`, retains the current memory capacity of the VM prior to restarting, otherwise sets the VM to boot with the new memory capacity as megabytes. If post-fixed with a 'G' or 'g', will be as gigabytes instead. If post-fixed with an 'M' or 'm', will be as megabytes, just with explicitness.

If `memory` is set to some value as the first workflow step, the VM will be initially booted with that amount of memory capacity. This is kind of silly but it works.

```yaml
steps:
  - name: Install CMake
    run: sudo apt update && sudo apt install cmake

  - name: Restart With More Resources for Parallel Compile
    restart:
      cpus: 4
      memory: 12G

  - name: Compile
    run: cmake -B build && cmake --build build --parallel

  - name: Decrease Cores for Tests
    restart:
      cpus: 2
      # Note that memory stays at 12GB from the previous step

  - name: Test
    run: ctest --test-dir build
```

```yaml
steps:
  - name: Install CMake
    run: sudo apt update && sudo apt install cmake

  - name: Restart With More Memory for Parallel Compile
    restart:
      memory: 10G

  - name: Compile
    run: cmake -B build && cmake --build build --parallel

  - name: Increase Cores for Tests
    restart:
      cpus: 3
      # Note that memory stays at 10 Gigabytes from the previous step

  - name: Test
    run: ctest --test-dir build
```

### `steps.workdir`

Defaults to null.

Sets the working directory within the VM for the step to execute.

```yaml
steps:
  - name: Working Directory
    workdir: ~/build
    # Assuming VM image SSH is setup for user dev
    run: pwd # /home/dev/build
```

### `steps.timeout`

Defaults to 2 hours.

A string representing the maximum amount of time a step can last. By default, is measured in seconds. If post-fixed with 'M' or 'm', is measured in minutes. If post-fixed with 'H' or 'h', is measured in hours. If post-fixed with 'S' or 's', is measured in seconds, just with explicitness. If the string provided fails to parse into a valid timeout, silently uses the 2 hour default.

```yaml
steps:
  - name: Test
    run: ctest --test-dir build
    # Tests should not take longer than 5 minutes
    timeout: 5M
```

### `steps.env`

Defaults to empty.

A map containing environment variables as string identifiers, and their values as strings, for the specific step.

```yaml
steps:
  - name: Test
    run: ctest --test-dir build
    env:
      # One of the test cases reads `TEST_PORT`
      TEST_PORT: 8080
```

### `steps.continue_on_error`

Defaults to `false`.

If `false`, a step failure is considered a workflow failure. If `true`, a step failure will continue on to the next step.

```yaml
steps:
  - name: Test
    run: ctest --test-dir build
    # Continue to the rest of the workflow if the tests fail
    continue_on_error: true
```

### `steps.skip_if_cached`

Defaults to `false`.

If `true`, this step is skipped when the run is served from a workflow cache (see [`cache`](#cache)), since the cached VM already reflects the result of having run it. On a normal (non-cached) run the step executes as usual. If `false`, the step always runs.

This is meant for steps whose only effect is already baked into the cached VM state, like as fetching and building dependencies. Do not use it for steps that must run every time (copying in the latest source, running tests, compiling probably).

```yaml
steps:
  - name: Fetch and build dependencies
    # Already present in the cached VM, no need to redo it on a hit
    run: cargo fetch
    skip_if_cached: true

  - name: Copy in latest source
    # Should always copy since the cache doesn't have this run's code
    copy:
      from: ./src
      to: vm:~/src

  - name: Fetch and build dependencies
    # Should recompile
    run: cargo build

  - name: Test
    # Should always test
    run: cargo test
```
