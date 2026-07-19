// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use argh::FromArgs;
use std::path::PathBuf;

/// VCI: Virtual Machine CI Runner
#[derive(FromArgs, Debug)]
pub struct Args {
    #[argh(subcommand)]
    pub command: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Command {
    Version(VersionCommand),
    Run(RunArgs),
    Setup(SetupArgs),
    Cleanup(CleanupArgs),
    List(ListArgs),
    Export(ExportArgs),
    Import(ImportArgs),
    Active(ActiveArgs),
    Remove(RemoveArgs),
    Clone(CloneArgs),
    Edit(EditArgs),
    Boot(BootArgs),
    Shell(ShellArgs),
    Copy(CopyArgs),
    Serve(ServeArgs),
}

/// Get the VirtCI version
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "version")]
pub struct VersionCommand {}

/// Run a workflow file
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "run")]
#[allow(clippy::struct_excessive_bools)] // CLI flags, not a state machine
pub struct RunArgs {
    /// path to workflow YAML file
    #[argh(positional)]
    pub workflow: PathBuf,
    /// validate the workflow syntax and exit without running the workflow
    #[argh(switch)]
    pub validate: bool,
    /// VM image: --image <name>
    #[argh(option)]
    pub image: Option<String>,
    /// run this workflow without using or producing any VM cache.
    #[argh(switch)]
    pub no_cache: bool,
    /// user specified cache namespace.
    /// There are 3 variables that VirtCI can auto-fill from git providers when possible.
    /// These are the following:
    ///
    /// - `owner` The organization that owns the git repo. (GITHUB_REPOSITORY_OWNER).
    /// - `repo` The git repository. (repo part of GITHUB_REPOSITORY).
    /// - `ref` Ref name / branch name. (GITHUB_REF_NAME).
    ///
    /// You can use these, which will get auto-filled, replaced when using {} braces, and sanitized.
    /// For example: `--cache-namespace "hello/{repo}/{ref}"` or
    /// `--cache-namespace "example/{repo}"`. If not provided, will default to
    /// `{owner}/{repo}/{ref}`.
    ///
    /// NOTE: Must be cautious about forks and PRs who have access
    /// to the VirtCI VM cache on the CI machine.
    #[argh(option)]
    pub cache_namespace: Option<String>,
    /// explicitly set an environment variable file to use.
    #[argh(option)]
    pub env_file: Option<PathBuf>,
    /// do not read the `.env` file even if it is there.
    #[argh(switch)]
    pub no_env_file: bool,
    /// do not use any ignore files, even if specified in a `copy:` step.
    #[argh(switch)]
    pub no_ignore: bool,
}

/// Interactive setup for a new VM image description
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "setup")]
pub struct SetupArgs {
    /// set up a QEMU-backed VM image
    #[argh(switch)]
    pub qemu: bool,

    /// set up a Tart-backed VM image (macOS only)
    #[argh(switch)]
    pub tart: bool,

    /// non-interactive: register from an existing JSON config file
    #[argh(option)]
    pub from: Option<PathBuf>,

    /// image name to use when registering with --from (defaults to the filename stem)
    #[argh(option)]
    pub name: Option<String>,

    /// register into the system-wide image directory (requires elevated privileges)
    #[argh(switch)]
    pub system: bool,
}

/// Clean up leftover temporary VM images
#[derive(FromArgs, Debug, Copy, Clone)]
#[argh(subcommand, name = "cleanup")]
pub struct CleanupArgs {
    /// delete all without confirmation
    #[argh(switch)]
    pub force: bool,

    /// list files that would be deleted without deleting
    #[argh(switch)]
    pub list: bool,
}

/// List all configured VM images
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
pub struct ListArgs {
    /// show detailed metadata for each image
    #[argh(switch)]
    pub verbose: bool,
}

/// Export a VM image and its files to a .tar archive
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "export")]
pub struct ExportArgs {
    /// name of the VM image to export
    #[argh(positional)]
    pub name: String,

    /// output file path (defaults to ./<name>.tar)
    #[argh(option, short = 'o')]
    pub output: Option<PathBuf>,
}

/// Import a VM image from a .tar archive
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "import")]
pub struct ImportArgs {
    /// path to the .tar archive to import
    #[argh(positional)]
    pub archive: PathBuf,

    /// import into the system-wide image directory (requires elevated privileges)
    #[argh(switch)]
    pub system: bool,
}

/// List all currently running VirtCI jobs
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "active")]
pub struct ActiveArgs {}

/// Remove a VirtCI VM image
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "remove")]
pub struct RemoveArgs {
    /// name of the VM image to remove
    #[argh(positional)]
    pub name: String,

    /// delete without confirmation
    #[argh(switch)]
    pub force: bool,
}

/// Make a full, persistent copy of a VM image under a new name
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "clone")]
pub struct CloneArgs {
    /// name of the existing VM image to clone
    #[argh(positional)]
    pub name: String,

    /// name for the new cloned VM image
    #[argh(positional)]
    pub new_name: String,

    /// register the clone into the system-wide image directory (requires elevated privileges)
    #[argh(switch)]
    pub system: bool,
}

/// Edit an existing VM image. Currently supports renaming; more fields will be editable later.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "edit")]
pub struct EditArgs {
    /// name of the existing VM image to edit
    #[argh(positional)]
    pub image: String,

    /// rename the image to this new name
    #[argh(option)]
    pub rename: Option<String>,
}

/// Boot a base VM image to modify it, found using `virtci list`
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "boot")]
pub struct BootArgs {
    /// name of the VM to modify
    #[argh(positional)]
    pub name: String,
    /// disable graphics
    #[argh(switch)]
    pub nographics: bool,
    /// boot a throwaway clone instead of the base image so changes are discarded on exit
    #[argh(switch)]
    pub clone: bool,
    /// amount of cpu cores to allocate to the booted VM
    #[argh(option)]
    pub cpus: Option<u32>,
    /// amount of memory to allocate to the booted VM, measured in megabytes by default,
    /// unless you specify a 'G' or 'g' postfix, then measured in gigabytes
    #[argh(option)]
    pub mem: Option<String>,
    #[argh(switch)]
    /// disable networking in the booted VM
    pub offline: bool,
}

/// SSH into a running VM by job name
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "shell")]
pub struct ShellArgs {
    /// name of the running job to connect to
    #[argh(positional)]
    pub name: String,
}

/// Copy files to or from a running VM (find it with `virtci active`).
///
/// Exactly one of `source` / `dest` must be prefixed with `vm:` to mark the VM side. This works
/// identically to the YAML `copy:` step in workflows.
/// `~` is expanded correctly on both the `source` and `dest` sides for the VM and host.
///
/// Example:
///   virtci copy vci-win-11-arm64-00001 ./dist vm:~/app --exclude build
///   virtci copy vci-win-11-arm64-00001 vm:/home/ci/logs ./logs --crlf
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "copy")]
#[allow(clippy::struct_excessive_bools)] // CLI flags, not a state machine
pub struct CopyArgs {
    /// name of the running VM (from `virtci active`)
    #[argh(positional)]
    pub vm: String,
    /// source path. Prefix with `vm:` to read from the VM
    #[argh(positional)]
    pub source: String,
    /// destination path. Prefix with `vm:` to write to the VM
    #[argh(positional)]
    pub dest: String,
    /// glob pattern to exclude from the copy; may be given more than once
    #[argh(option)]
    pub exclude: Vec<String>,
    /// convert line endings (CRLF <-> LF) based on host and guest OS
    #[argh(switch)]
    pub crlf: bool,
    /// do not create the destination directory before copying
    #[argh(switch)]
    pub no_mkdir: bool,
    /// allow a glob `source` that matches zero files instead of erroring
    #[argh(switch)]
    pub allow_empty: bool,
    /// file to use for which files / directories to ignore when copying from host to vm, such a
    /// `.gitignore`. Uses gitignore semantics. If omitted, uses the current working directory
    /// `.virtciignore` file if present.
    #[argh(option)]
    pub ignore_file: Option<String>,
    /// do not use any ignore files, even if `--ignore-file` is present.
    #[argh(switch)]
    pub no_ignore: bool,
}

/// (TODO) Start the web UI server
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "serve")]
pub struct ServeArgs {
    /// port to listen on (default: VIRTCI_BACKEND_PORT env var, or 6399)
    #[argh(option)]
    pub port: Option<u16>,
    /// S3 storage URL to use.
    /// Multiple are supported, prioritizing the first for read operations,
    /// but writing to both.
    #[argh(option)]
    pub s3_url: Vec<String>,
}

// #[derive(Debug, Clone)]
// pub enum Override {
//     Global(String),
//     Job { name: String, value: String },
// }

// impl Override {
//     /// "value" as Global, "job=value" as Job
//     pub fn parse(s: &str) -> Self {
//         match s.split_once('=') {
//             Some((job, value)) if !job.contains('/') && !job.contains('\\') => Override::Job {
//                 // in case there is an = in a path
//                 name: job.to_string(),
//                 value: value.to_string(),
//             },
//             _ => Override::Global(s.to_string()),
//         }
//     }
// }

// pub fn parse_overrides(values: &[String]) -> Vec<Override> {
//     let mut overrides = Vec::<Override>::default();
//     for value in values {
//         overrides.push(Override::parse(value));
//     }
//     return overrides;
// }

// pub fn resolve_for_job<'a>(overrides: &'a [Override], job: &str) -> Option<&'a str> {
//     for ov in overrides {
//         if let Override::Job { name, value } = ov {
//             if name == job {
//                 return Some(value);
//             }
//         }
//     }

//     for ov in overrides {
//         if let Override::Global(value) = ov {
//             return Some(value);
//         }
//     }

//     return None;
// }

pub fn parse_mem_mb(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num, unit) = if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len() - 1], 1024u64)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 1u64)
    } else {
        // assume MB
        (s, 1u64)
    };

    num.parse::<u64>().ok().map(|n| n * unit)
}

pub fn parse_disk_gb(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num, unit) = if s.ends_with('T') || s.ends_with('t') {
        (&s[..s.len() - 1], 1024u64)
    } else if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len() - 1], 1u64)
    } else {
        // assume GB
        (s, 1u64)
    };

    num.parse::<u64>().ok().map(|n| n * unit)
}

pub fn default_cpus() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let cpus = std::thread::available_parallelism().map_or(2, |p| p.get() as u32);
    (cpus / 2).max(1)
}

pub const DEFAULT_MEM_MB: u64 = 8192;
