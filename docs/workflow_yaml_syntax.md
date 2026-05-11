# Workflow YAML Syntax

VirtCI YAML Syntax is very similar to GitHub Actions YAML syntax.

## `job`

The name of a job. This is the highest level field in the YAML file, and is used to identify and SSH into a workflow run. Multiple jobs are allowed in a single workflow YAML file.

## `image`

The actual VM image that will be used. Must exist on disk, and can be found by running `virtci list`.

## `cpus`

Defaults to half the available system cores, or 1, whichever is greater.

The number of cores that the VM will get on initial startup. Must be a positive non-zero integer.

## `memory`

Defaults to 8GB.

The amount of RAM in megabytes the VM will get on initial startup. If post-fixed with a 'G' or 'g', will be as gigabytes instead. If post-fixed with an 'M' or 'm', will be as megabytes, just with explicitness. The numerical part of the string must be a positive non-zero integer.

## `host_env`

Array of environment variables to copy from the host into the VM.

## `steps`

Array of steps to execute in top-to-bottom order.

A step must have exactly one of [run](#stepsrun), [copy](#stepscopy), or [restart](#stepsrestart).

### `steps.name`

The optional string name of the step.

### `steps.run`

A string containing the shell command to run inside the VM, or the YAML standard pipe `|` character for multi-line strings, which the VM shell executes as multiple statements.

### `steps.copy`

Copy files from the host to the VM, or from the VM to the host, using tar-over-ssh.

#### `steps.copy.from`

Required string field.

Specifies the directory or files or file glob pattern to copy from the host to the VM, or from the VM to the host.

If you want to copy from the **VM to the host**, prefix the entire string with `vm:`, otherwise omit that.

Exactly one of the [from](#stepscopyfrom) and [to](#stepscopyto) must be prefixed with `vm:`. If neither have it, or both have it, this is a fatal condition, terminating the workflow.

#### `steps.copy.to`

Required string field.

Specifies the directory or files or file glob pattern to write the files into from the host to the VM, or from the VM to the host.

If you want to copy from the **host to the VM**, prefix the entire string with `vm:`, otherwise omit that.

Exactly one of the [from](#stepscopyfrom) and [to](#stepscopyto) must be prefixed with `vm:`. If neither have it, or both have it, this is a fatal condition, terminating the workflow.

#### `steps.copy.exclude`

Defaults to empty.

An array of directories or files to exclude from the file copies.

#### `steps.copy.crlf`

Defaults to `false`.

If `false`, CRLF conversion will not happen automatically. If `true`, and the copy is from host to VM, and the VM is a Windows VM, will perform CRLF conversion.

#### `steps.copy.no_mkdir`

Defaults to `false`

If `false`, the copy step will create the necessary directory tree for the copy's `to` target. If this boolean is set to `true`, will not make the necessary directory tree, failing if a file cannot be copied to the corresponding directory.

#### `steps.copy.allow_empty`

Defaults to `false`.

If `false` and a glob pattern is used, it will cause a step failure if the glob returns 0 entries. If `true`, allows the glob to return 0.

### `steps.restart`

Restarts the VM.

#### `steps.restart.offline`

Defaults to null.

Can contain either `null`, or a boolean value. If `null`, retains the current networking capabilities of the VM prior to restarting. If `false`, enables networking if it was disabled. If `true`, disables networking if it was enabled.

#### `steps.restart.cpus`

Defaults to null.

Can contain either `null` or a positive non-zero integer value. If `null`, retains the current cpu cores of the VM prior to restarting, otherwise sets the VM to boot with the new number of cores.

#### `steps.restart.memory`

Defaults to null.

Can contain either `null` or a string containing a positive non-zero integer value, and an optional post-fix. If `null`, retains the current memory capacity of the VM prior to restarting, otherwise sets the VM to boot with the new memory capacity as megabytes. If post-fixed with a 'G' or 'g', will be as gigabytes instead. If post-fixed with an 'M' or 'm', will be as megabytes, just with explicitness.

### `steps.workdir`

Defaults to null.

Sets the working directory within the VM for the step to execute.

### `steps.timeout`

Defaults to 2 hours.

A string representing the maximum amount of time a step can last. By default, is measured in seconds. If post-fixed with 'M' or 'm', is measured in minutes. If post-fixed with 'H' or 'h', is measured in hours. If post-fixed with 'S' or 's', is measured in seconds, just with explicitness. If the string provided fails to parse into a valid timeout, silently uses the 2 hour default.

### `steps.env`

Defaults to empty.

A map containing environment variables as string identifiers, and their values as strings, for the specific step.

### `steps.continue_on_error`

Defaults to `false`.

If `false`, a step failure is considered a workflow failure. If `true`, a step failure will continue on to the next step.
