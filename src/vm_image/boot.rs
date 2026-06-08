// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use colored::Colorize;

use crate::{
    backend::VmBackend,
    cli::BootArgs,
    orphan::OrphanTracker,
    run::{wait_for_ssh, SSH_WAIT_TIMEOUT},
    vm_image::{BackendConfig, ImageDescription, SshTarget},
    VciGlobalPaths,
};

pub fn run_boot(args: &BootArgs, paths: &VciGlobalPaths, orphans: &OrphanTracker) {
    let image_desc = load_image(&args.name, paths).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to load image '{}': {e}", args.name).red()
        );
        std::process::exit(1);
    });

    std::fs::create_dir_all(&paths.temp).unwrap_or_else(|e| {
        eprintln!("{}", format!("Failed to create temp directory: {e}").red());
        std::process::exit(1);
    });

    if args.clone {
        println!(
            "{}",
            format!(
                "[VirtCI] Booting clone of '{}'. Changes will be discarded on exit",
                args.name
            )
            .cyan()
            .bold()
        );
    } else {
        println!(
            "{}",
            format!(
                "[VirtCI] Booting base image '{}'. Changes to the disk will persist",
                args.name
            )
            .cyan()
            .bold()
        );
    }

    match image_desc.backend {
        BackendConfig::Qemu(_) => boot_qemu(image_desc, args, paths, orphans),
        BackendConfig::Tart(_) => boot_tart(image_desc, args, paths),
    }
}

fn boot_qemu(
    image_desc: ImageDescription,
    args: &BootArgs,
    paths: &VciGlobalPaths,
    orphans: &OrphanTracker,
) {
    use crate::backend::{
        qemu::backend::{QemuBackend, SerialKind},
        VmStartConfig,
    };

    let (cpus, memory_mb) = resolve_cpus_and_memory(args);

    let serial = if args.nographics {
        SerialKind::Console
    } else {
        SerialKind::File
    };

    let mut backend = QemuBackend::new(
        args.name.clone(),
        image_desc,
        paths,
        args.clone,
        !args.nographics,
        serial,
        orphans.clone(),
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "{}",
            format!("Failed to initialize QEMU backend for boot: {e}").red()
        );
        std::process::exit(1);
    });

    backend
        .start_vm(VmStartConfig {
            offline: Some(args.offline),
            cpus: Some(cpus),
            memory_mb: Some(memory_mb),
        })
        .unwrap_or_else(|e| {
            eprintln!("{}", format!("Failed to start VM: {e:#}").red());
            std::process::exit(1);
        });

    if !args.clone {
        if let Some(pid) = backend.qemu_pid() {
            let _ = crate::QEMU_BOOT_GRACEFUL_PID.set(pid);
        }
    }

    spawn_ssh_announcer(
        backend.ssh_target(),
        backend.run_name(),
        backend.serial_log_path().map(std::path::Path::to_path_buf),
    );

    backend.wait_for_exit();
    println!("{}", "VM exited.".dimmed());
}

fn boot_tart(image_desc: ImageDescription, args: &BootArgs, paths: &VciGlobalPaths) {
    #[cfg(target_os = "macos")]
    {
        use crate::backend::{tart::TartBackend, VmStartConfig};

        let (cpus, memory_mb) = resolve_cpus_and_memory(args);

        let mut backend = if args.clone {
            let mut b = TartBackend::new(args.name.clone(), image_desc, cpus, memory_mb, paths)
                .unwrap_or_else(|e| {
                    eprintln!(
                        "{}",
                        format!("Failed to initialize Tart backend for boot: {e}").red()
                    );
                    std::process::exit(1);
                });
            b.graphics = !args.nographics;
            b
        } else {
            TartBackend::new_base(
                args.name.clone(),
                image_desc,
                cpus,
                memory_mb,
                args.nographics,
                paths,
            )
            .unwrap_or_else(|e| {
                eprintln!(
                    "{}",
                    format!("Failed to initialize Tart backend for boot: {e}").red()
                );
                std::process::exit(1);
            })
        };

        if args.offline {
            eprintln!(
                "{}",
                "Warning: --offline on Tart in boot mode does not auto-enforce. \
                After SSH'ing in, run: sudo route -n delete default"
                    .yellow()
            );
        }

        backend
            .start_vm(VmStartConfig {
                offline: Some(args.offline),
                cpus: None,
                memory_mb: None,
            })
            .unwrap_or_else(|e| {
                eprintln!("{}", format!("Failed to start VM: {e:#}").red());
                std::process::exit(1);
            });

        spawn_ssh_announcer(
            backend.ssh_target(),
            backend.run_name(),
            backend.serial_log_path().map(std::path::Path::to_path_buf),
        );

        backend.wait_for_exit();
        println!("{}", "VM exited.".dimmed());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (image_desc, args, paths);
        eprintln!("{}", "Tart backend is only supported on macOS".red());
        std::process::exit(1);
    }
}

fn resolve_cpus_and_memory(args: &BootArgs) -> (u32, u64) {
    let cpus = args.cpus.unwrap_or_else(crate::cli::default_cpus);
    let memory_mb = match args.mem.as_deref() {
        Some(s) => crate::cli::parse_mem_mb(s).unwrap_or_else(|| {
            eprintln!("{}", format!("Failed to parse memory: {s}").red());
            std::process::exit(1);
        }),
        None => crate::cli::DEFAULT_MEM_MB,
    };
    (cpus, memory_mb)
}

fn spawn_ssh_announcer(ssh: SshTarget, run_name: String, serial_log: Option<std::path::PathBuf>) {
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let Some(secs) = rt.block_on(wait_for_ssh(&ssh, SSH_WAIT_TIMEOUT)) else {
            return;
        };
        let cmd = if let Some(ref key) = ssh.cred.key {
            format!(
                "ssh -i {} {}@{} -p {}",
                key, ssh.cred.user, ssh.ip, ssh.port
            )
        } else {
            format!("ssh {}@{} -p {}", ssh.cred.user, ssh.ip, ssh.port)
        };
        println!(
            "{}",
            format!("[VirtCI] SSH ready after {secs}s. [{cmd}]").green()
        );
        println!(
            "{}",
            format!("[VirtCI] Connect to this VM while running: virtci shell {run_name}").magenta()
        );
        if let Some(log) = serial_log {
            println!(
                "{}",
                format!("[VirtCI] Serial log: {} (tail -f to follow)", log.display()).magenta()
            );
        }
    });
}

fn load_image(name: &str, paths: &VciGlobalPaths) -> Result<ImageDescription, String> {
    let home = paths.resolve_image_home(name).ok_or_else(|| {
        format!(
            "image '{}' not found (looked at {} and {})",
            name,
            paths.user_home.display(),
            paths.system_home.display()
        )
    })?;

    #[cfg(target_os = "windows")]
    let home_wsl_distro = home.wsl_distro.clone();

    let vci_path = home.path;
    let contents = std::fs::read_to_string(&vci_path)
        .map_err(|e| format!("Failed to read {}: {e}", vci_path.display()))?;
    let mut desc: ImageDescription = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse image description '{name}': {e}"))?;
    desc.name = name.to_string();

    #[cfg(target_os = "windows")]
    {
        desc.wsl_distro = home_wsl_distro;
    }

    Ok(desc)
}
