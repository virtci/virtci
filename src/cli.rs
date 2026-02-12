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
}

/// Get the VirtCI version
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "version")]
pub struct VersionCommand {}

/// Run a workflow file
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "run")]
pub struct RunArgs {
    /// path to workflow YAML file
    #[argh(positional)]
    pub workflow: PathBuf,
    // /// VM disk image: --image path OR --image job=path
    // #[argh(option)]
    // pub image: Vec<String>,

    // /// CPU count: --cpus 4 OR --cpus job=2 (default: half system threads)
    // #[argh(option)]
    // pub cpus: Vec<String>,

    // /// memory: --mem 2G OR --mem job=512M (default: 8G)
    // #[argh(option)]
    // pub mem: Vec<String>,

    // /// SSH username: --ssh-user root OR --ssh-user job=admin
    // #[argh(option)]
    // pub ssh_user: Vec<String>,

    // /// SSH password: --ssh-password secret OR --ssh-password job=secret
    // #[argh(option)]
    // pub ssh_password: Vec<String>,

    // /// SSH private key: --ssh-key path OR --ssh-key job=path
    // #[argh(option)]
    // pub ssh_key: Vec<String>,

    // /// SSH port: --ssh-port 22 OR --ssh-port job=2222
    // #[argh(option)]
    // pub ssh_port: Vec<String>,

    // /// VM architecture: --arch x86_64 OR --arch job=aarch64 (default: host arch)
    // #[argh(option)]
    // pub arch: Vec<String>,
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
}

/// Clean up leftover temporary VM images
#[derive(FromArgs, Debug)]
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

    return num.parse::<u64>().ok().map(|n| n * unit);
}

pub fn default_cpus() -> u32 {
    let cpus = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(2);
    return (cpus / 2).max(1);
}

pub const DEFAULT_MEM_MB: u64 = 8192;
