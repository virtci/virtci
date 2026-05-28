// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

pub mod backend;
pub mod cli;
pub mod file_lock;
pub mod global_paths;
pub mod orphan;
pub mod run;
pub mod run_state;
pub mod transfer_lock;
pub mod vm_image;
pub mod web;
pub mod yaml;

use global_paths::VciGlobalPaths;
use std::path::PathBuf;
use std::sync::OnceLock;

use argh::FromArgs;

/// PID of the QEMU process running the qcow2 for `virtci boot` (no --clone).
pub static QEMU_BOOT_GRACEFUL_PID: OnceLock<u32> = OnceLock::new();

/// `args` should not contain the command/executable name.
///
/// For instance, if you're testing `virtci import hello.tar`, the `args` should be
/// `["import", "hello.tar"]`.
pub fn run_virtci_with_args(paths: &VciGlobalPaths, args: &[&str]) {
    let cli_args = cli::Args::from_args(&["virtci"], args).expect("Failed to parse args");
    run_virtci(paths, cli_args);
}

pub fn run_virtci_cli(paths: &VciGlobalPaths) {
    run_virtci(paths, argh::from_env());
}

fn run_virtci(paths: &VciGlobalPaths, args: cli::Args) {
    let orphans = orphan::OrphanTracker::new();
    setup_signal_handlers(orphans.clone());

    backend::qemu::cleanup_stale_qemu_files(paths);
    backend::tart::cleanup_stale_tart_clones(&paths.temp);

    match args.command {
        cli::Command::Version(_) => {
            println!("VirtCI version: {}", env!("CARGO_PKG_VERSION"));
        }
        cli::Command::Run(run_args) => {
            std::fs::create_dir_all(&paths.temp).unwrap_or_else(|e| {
                panic!(
                    "Failed to create temp directory {}: {}",
                    paths.temp.display(),
                    e
                )
            });
            let jobs = extract_yaml_workflows(&run_args, paths);
            run_jobs(jobs, paths);
        }
        cli::Command::Setup(setup_args) => {
            run_setup(&setup_args, paths);
        }
        cli::Command::Cleanup(cleanup_args) => {
            run_cleanup(cleanup_args, paths);
        }
        cli::Command::List(list_args) => {
            vm_image::list::run_list(list_args.verbose, paths);
        }
        cli::Command::Export(export_args) => {
            if let Err(e) =
                vm_image::export::run_export(&export_args.name, export_args.output, paths)
            {
                eprintln!("Export failed: {e}");
                std::process::exit(1);
            }
        }
        cli::Command::Import(import_args) => {
            if let Err(e) =
                vm_image::import::run_import(&import_args.archive, paths, import_args.system)
            {
                eprintln!("Import failed: {e}");
                std::process::exit(1);
            }
        }
        cli::Command::Active(_) => {
            run_state::run_active(&paths.temp);
        }
        cli::Command::Remove(remove_args) => {
            vm_image::remove::run_remove(&remove_args, paths);
        }
        cli::Command::Boot(boot_args) => {
            vm_image::boot::run_boot(&boot_args, paths);
        }
        cli::Command::Shell(shell_args) => {
            run_state::run_shell(&shell_args, &paths.temp);
        }
        cli::Command::Serve(serve_args) => {
            let mut config = crate::web::ServerConfig::default();
            if let Some(port) = serve_args.port {
                config.port = port;
            }

            if !serve_args.s3_url.is_empty() {
                config.s3 = serve_args.s3_url;
            }

            web::serve(&config);
        }
    }
}

fn run_setup(args: &cli::SetupArgs, paths: &VciGlobalPaths) {
    if let Some(ref from_path) = args.from {
        if let Err(e) = vm_image::run_from_file(from_path, paths, args.name.as_deref(), args.system)
        {
            eprintln!("Setup failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    assert!(
        !(args.qemu && args.tart),
        "Error: specify either --qemu or --tart, not both."
    );

    assert!(
        !(!args.qemu && !args.tart),
        "Error: specify a backend with --qemu or --tart, and optionally provide --from <config.json>."
    );

    if args.tart && args.system {
        eprintln!(
            "Error: --system is not supported for Tart-backed images. Tart stores VM data in per-user storage (~/.tart/vms/), so a system-wide config would point at data that other users cannot access."
        );
        std::process::exit(1);
    }

    if args.qemu {
        if let Err(e) = vm_image::setup_qemu::run_interactive_setup(paths, args.system) {
            panic!("Setup failed: {e}");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if args.tart {
            if let Err(e) = vm_image::setup_tart::run_interactive_setup(paths, args.system) {
                panic!("Setup failed: {e}");
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        assert!(!args.tart, "Tart setup is only available on macOS.");
    }
}

fn run_jobs(jobs: Vec<run::Job>, paths: &VciGlobalPaths) {
    use colored::Colorize;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    let mut failed = false;

    for mut job in jobs {
        let job_name = job.name.clone();
        println!("{}", format!("=== Job {job_name} ===").cyan().bold());

        let result = rt.block_on(job.run(paths));

        match result {
            Ok(()) => println!(
                "{}\n",
                format!("=== Job {job_name} completed ===").green().bold()
            ),
            Err(e) => {
                eprintln!(
                    "{}",
                    format!("=== Job {job_name} failed: {e} ===").red().bold()
                );
                failed = true;
                break;
            }
        }
    }

    backend::qemu::cleanup_stale_qemu_files(paths);
    backend::tart::cleanup_stale_tart_clones(&paths.temp);

    if failed {
        std::process::exit(1);
    }

    println!("{}", "All jobs completed successfully".green().bold());
}

fn run_cleanup(args: cli::CleanupArgs, paths: &VciGlobalPaths) {
    use colored::Colorize;
    use std::io::{self, Write};

    // Mirrors `cleanup_stale_qemu_files()`
    #[cfg(target_os = "windows")]
    let temp_dirs: Vec<PathBuf> = {
        let mut dirs = vec![paths.temp.clone()];
        if let Some(wsl) = &paths.wsl {
            dirs.push(wsl.to_unc(&wsl.temp));
        }
        dirs
    };
    #[cfg(not(target_os = "windows"))]
    let temp_dirs: Vec<PathBuf> = vec![paths.temp.clone()];

    let files: Vec<PathBuf> = temp_dirs
        .iter()
        .flat_map(|dir| find_vci_temp_files(dir))
        .collect();

    if files.is_empty() {
        println!("{}", "No temporary VCI files found".dimmed());
        return;
    }

    if args.list {
        println!(
            "{}",
            format!("Found {} temporary VCI file(s):", files.len()).cyan()
        );
        for file in &files {
            println!("  {}", file.display());
        }
        return;
    }

    if args.force {
        for file in &files {
            match std::fs::remove_file(file) {
                Ok(()) => println!("{} {}", "Deleted:".green(), file.display()),
                Err(e) => eprintln!("{} {}: {}", "Failed to delete:".red(), file.display(), e),
            }
        }
        return;
    }

    // confirm each deletion, very important
    println!(
        "{}",
        format!("Found {} temporary VCI file(s)", files.len()).cyan()
    );
    for file in &files {
        print!("Delete {}? [y/N] ", file.display());
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let input = input.trim().to_lowercase();
            if input == "y" || input == "yes" {
                match std::fs::remove_file(file) {
                    Ok(()) => println!("{}", "  Deleted".green()),
                    Err(e) => eprintln!("{} {}", "  Failed:".red(), e),
                }
            } else {
                println!("{}", "  Skipped".dimmed());
            }
        }
    }
}

fn find_vci_temp_files(temp_dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let ext = std::path::Path::new(name)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();

                let is_vci_file = (name.starts_with("vci-") || name.starts_with("vci_"))
                    && matches!(ext.as_str(), "qcow2" | "lock" | "fd" | "log");

                if is_vci_file {
                    files.push(path);
                }
            }
        }
    }

    files
}

fn setup_signal_handlers(orphans: orphan::OrphanTracker) {
    // background thread handles signals (kinda silly but whatever, tokio you do you)
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create signal handler runtime");

        rt.block_on(async {
            signal_handler(orphans).await;
        });
    });
}

async fn signal_handler(orphans: orphan::OrphanTracker) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        const GRACEFUL_TIMEOUT_SECS: u64 = 30;

        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sighup = signal(SignalKind::hangup()).unwrap();
        let mut sigquit = signal(SignalKind::quit()).unwrap();

        let mut graceful_attempted = false;
        loop {
            let timed_out = tokio::select! {
                _ = sigint.recv() => false,
                _ = sigterm.recv() => false,
                _ = sighup.recv() => false,
                _ = sigquit.recv() => false,
                () = tokio::time::sleep(std::time::Duration::from_secs(GRACEFUL_TIMEOUT_SECS)),
                    if graceful_attempted => true,
            };

            if timed_out {
                if let Some(&pid) = QEMU_BOOT_GRACEFUL_PID.get() {
                    eprintln!(
                        "\n[VirtCI] QEMU did not exit within {GRACEFUL_TIMEOUT_SECS}s after SIGTERM. Sending SIGKILL so qcow2 may be left with the in-use bit set."
                    );
                    let _ = std::process::Command::new("kill")
                        .arg("-KILL")
                        .arg(pid.to_string())
                        .status();
                }
                orphans.kill_all();
                std::process::exit(1);
            }

            if !graceful_attempted {
                if let Some(&pid) = QEMU_BOOT_GRACEFUL_PID.get() {
                    let sent = std::process::Command::new("kill")
                        .arg("-TERM")
                        .arg(pid.to_string())
                        .status()
                        .is_ok_and(|s| s.success());
                    if sent {
                        eprintln!(
                            "\n[VirtCI] SIGTERM sent to QEMU; waiting for clean qcow2 close (up to {GRACEFUL_TIMEOUT_SECS}s). Press CTRL+C again to force-exit."
                        );
                        graceful_attempted = true;
                        continue;
                    }
                }
            }

            orphans.kill_all();
            std::process::exit(1);
        }
    }

    #[cfg(windows)]
    {
        // TODO Some WSL chicanery
        use tokio::signal::windows;

        let mut ctrl_c = windows::ctrl_c().unwrap();
        let mut ctrl_break = windows::ctrl_break().unwrap();
        let mut ctrl_close = windows::ctrl_close().unwrap();
        let mut ctrl_shutdown = windows::ctrl_shutdown().unwrap();

        tokio::select! {
            _ = ctrl_c.recv() => {},
            _ = ctrl_break.recv() => {},
            _ = ctrl_close.recv() => {},
            _ = ctrl_shutdown.recv() => {},
        }

        orphans.kill_all();
        std::process::exit(1);
    }
}

fn load_image_description(image_name: &str, paths: &VciGlobalPaths) -> vm_image::ImageDescription {
    let home = paths.resolve_image_home(image_name).unwrap_or_else(|| {
        panic!(
            "Failed to load image description '{}' (looked at {} and {})",
            image_name,
            paths.user_home.display(),
            paths.system_home.display()
        )
    });
    let vci_path = home.path;
    let contents = std::fs::read_to_string(&vci_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read image description at {}: {e}",
            vci_path.display()
        )
    });
    let mut desc: vm_image::ImageDescription = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("Failed to parse image description '{image_name}': {e}"));
    desc.name = image_name.to_string();
    desc
}

fn extract_yaml_workflows(args: &cli::RunArgs, paths: &VciGlobalPaths) -> Vec<run::Job> {
    let file_contents = std::fs::read_to_string(&args.workflow)
        .unwrap_or_else(|_| panic!("Failed to load workflow file: {}", args.workflow.display()));

    let workflow: yaml::Workflow = yaml::parse_workflow(&file_contents)
        .unwrap_or_else(|e| panic!("Failed to parse workflow YAML: {e}"));

    // let image_overrides = cli::parse_overrides(&args.image);
    // let cpus_overrides = cli::parse_overrides(&args.cpus);
    // let mem_overrides = cli::parse_overrides(&args.mem);

    let mut jobs = Vec::<run::Job>::new();
    for (name, yaml_job) in workflow {
        // let image_name = cli::resolve_for_job(&image_overrides, &name)
        //     .unwrap_or(&yaml_job.image)
        //     .to_string();
        let image_name = if let Some(img) = &args.image {
            img
        } else {
            &yaml_job.image
        };

        let image_desc = load_image_description(image_name, paths);

        // let cpus: u32 = match cli::resolve_for_job(&cpus_overrides, &name) {
        //     Some(s) => s.parse::<u32>().expect("Expected number for --cpus"),
        //     None => yaml_job.cpus.unwrap_or(cli::default_cpus()),
        // };
        let cpus: u32 = yaml_job.cpus.unwrap_or(cli::default_cpus());
        assert!(cpus > 0, "Expected positive, non-zero CPU count");

        // let memory_mb: u64 = match cli::resolve_for_job(&mem_overrides, &name) {
        //     Some(s) => {
        //         cli::parse_mem_mb(s).unwrap_or_else(|| panic!("Failed to parse memory: {}", s))
        //     }
        //     None => match yaml_job.memory.as_deref() {
        //         Some(s) => {
        //             cli::parse_mem_mb(s).unwrap_or_else(|| panic!("Failed to parse memory: {}", s))
        //         }
        //         None => cli::DEFAULT_MEM_MB,
        //     },
        // };
        let memory_mb = match yaml_job.memory.as_deref() {
            Some(s) => {
                cli::parse_mem_mb(s).unwrap_or_else(|| panic!("Failed to parse memory: {s}"))
            }
            None => cli::DEFAULT_MEM_MB,
        };
        assert!(memory_mb > 0, "Expected positive, non-zero memory amount");

        let steps: Vec<run::Step> = yaml_job
            .steps
            .iter()
            .map(|step| {
                let kind = match step.validate() {
                    Ok(sk) => match sk {
                        yaml::StepKind::Run(s) => run::StepKind::Run(s),
                        yaml::StepKind::Copy(c) => run::StepKind::Copy(c),
                        yaml::StepKind::Restart(r) => {
                            let memory_mb = r.memory.as_deref().map(|s| {
                                cli::parse_mem_mb(s).unwrap_or_else(|| {
                                    panic!("Failed to parse restart memory: {s}")
                                })
                            });
                            run::StepKind::Restart(yaml::ResolvedRestart {
                                offline: r.offline,
                                cpus: r.cpus,
                                memory_mb,
                            })
                        }
                    },
                    Err(e) => panic!("{}", e),
                };
                let timeout = match &step.timeout {
                    Some(s) => yaml::parse_timeout_seconds(s),
                    None => run::MAX_TIMEOUT,
                };
                run::Step {
                    name: step.name.clone(),
                    kind,
                    workdir: step.workdir.clone(),
                    timeout,
                    env: step.env.clone(),
                    continue_on_error: step.continue_on_error,
                }
            })
            .collect();

        assert!(!steps.is_empty(), "Expected at least 1 step");

        let backend: Box<dyn backend::VmBackend> = match &image_desc.backend {
            vm_image::BackendConfig::Qemu(_) => Box::new(
                backend::qemu_old::QemuBackend::new(
                    name.clone(),
                    image_desc,
                    cpus,
                    memory_mb,
                    &paths.temp,
                )
                .unwrap_or_else(|()| panic!("Failed to create QEMU backend for job '{}'", &name)),
            ),
            vm_image::BackendConfig::Tart(_) => Box::new(
                backend::tart::TartBackend::new(
                    name.clone(),
                    image_desc,
                    cpus,
                    memory_mb,
                    &paths.temp,
                )
                .unwrap_or_else(|()| panic!("Failed to create Tart backend for job '{}'", &name)),
            ),
        };

        jobs.push(run::Job {
            name,
            backend,
            host_env: yaml_job.host_env,
            steps,
        });
    }

    jobs
}
