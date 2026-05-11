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

If `false`, CRLF conversion will not happen automatically. If `true`, and the copy is from host to VM, and the VM is a Windows VM, will perform CRLF conversion.

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
