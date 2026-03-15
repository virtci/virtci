// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use colored::Colorize;

use crate::{
    backend::VmBackend,
    cli::BootArgs,
    vm_image::{BackendConfig, ImageDescription},
    VciGlobalPaths,
};

pub fn run_boot(args: &BootArgs, paths: &VciGlobalPaths) -> anyhow::Result<()> {
    let image_desc =
        ImageDescription::load_from_disk(&args.name, &paths.home).unwrap_or_else(|e| {
            eprintln!(
                "{}",
                format!("Failed to load image '{}': {e}", args.name).red()
            );
            std::process::exit(1);
        });

    paths.create_temp_dir()?;

    println!(
        "{}",
        format!(
            "[VirtCI] Booting base image '{}' — changes to the disk will persist",
            args.name
        )
        .cyan()
        .bold()
    );

    match image_desc.backend {
        BackendConfig::Qemu(_) => boot_qemu(image_desc, args, paths),
        BackendConfig::Tart(_) => boot_tart(image_desc, args, paths),
    }

    Ok(())
}

fn boot_qemu(image_desc: ImageDescription, args: &BootArgs, paths: &VciGlobalPaths) {
    use crate::{
        backend::qemu::QemuBackend,
        cli::{default_cpus, DEFAULT_MEM_MB},
    };

    let mut backend = QemuBackend::new_base(
        args.name.clone(),
        image_desc,
        default_cpus(),
        DEFAULT_MEM_MB,
        args.nographics,
        &paths.temp,
    )
    .unwrap_or_else(|()| {
        eprintln!("{}", "Failed to initialize QEMU backend for boot".red());
        std::process::exit(1);
    });

    backend.start_vm(false).unwrap_or_else(|()| {
        eprintln!("{}", "Failed to start VM".red());
        std::process::exit(1);
    });

    println!(
        "{}",
        format!(
            "Connect to this VM while running: virtci shell {}",
            backend.run_name()
        )
        .magenta()
    );

    backend.wait_for_exit();
    println!("{}", "VM exited.".dimmed());
}

fn boot_tart(image_desc: ImageDescription, args: &BootArgs, paths: &VciGlobalPaths) {
    #[cfg(target_os = "macos")]
    {
        use crate::{
            backend::tart::TartBackend,
            cli::{default_cpus, DEFAULT_MEM_MB},
        };

        let mut backend = TartBackend::new_base(
            args.name.clone(),
            image_desc,
            default_cpus(),
            DEFAULT_MEM_MB,
            args.nographics,
            &paths.temp,
        )
        .unwrap_or_else(|()| {
            eprintln!("{}", "Failed to initialize Tart backend for boot".red());
            std::process::exit(1);
        });

        backend.start_vm(false).unwrap_or_else(|()| {
            eprintln!("{}", "Failed to start VM".red());
            std::process::exit(1);
        });

        println!(
            "{}",
            format!(
                "Connect to this VM while running: virtci shell {}",
                backend.run_name()
            )
            .magenta()
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
