// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;

use colored::Colorize;

use crate::{
    backend::VmBackend,
    cli::BootArgs,
    vm_image::{BackendConfig, ImageDescription},
    VciGlobalPaths,
};

pub fn run_boot(args: &BootArgs, paths: &VciGlobalPaths) {
    let image_desc = load_image(&args.name, &paths.home).unwrap_or_else(|e| {
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

fn load_image(name: &str, home_path: &Path) -> Result<ImageDescription, String> {
    let vci_path = home_path.join(format!("{name}.vci"));
    let contents = std::fs::read_to_string(&vci_path).map_err(|_| {
        format!(
            "image '{}' not found (looked at {})",
            name,
            vci_path.display()
        )
    })?;
    let mut desc: ImageDescription = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse image description '{name}': {e}"))?;
    desc.name = name.to_string();
    Ok(desc)
}
