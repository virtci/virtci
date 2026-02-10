mod backend;
mod cli;
mod file_lock;
mod run;
mod transfer_lock;
mod vm_image;
mod yaml;

use std::path::PathBuf;

pub(crate) static VCI_TEMP_PATH: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    return std::env::temp_dir().join("vci");
});

pub fn run_vci() {
    setup_signal_handlers();

    backend::qemu::cleanup_stale_qemu_files();
    backend::tart::cleanup_stale_tart_clones();

    let args: cli::Args = argh::from_env();

    match args.command {
        cli::Command::Run(run_args) => {
            std::fs::create_dir_all(&*VCI_TEMP_PATH).unwrap_or_else(|e| {
                panic!(
                    "Failed to create temp directory {}: {}",
                    VCI_TEMP_PATH.display(),
                    e
                )
            });
            let jobs = extract_yaml_workflows(run_args);
            run_jobs(jobs);
        }
        cli::Command::Setup(setup_args) => {
            run_setup(setup_args);
        }
        cli::Command::Cleanup(cleanup_args) => {
            run_cleanup(cleanup_args);
        }
        cli::Command::List(list_args) => {
            vm_image::list::run_list(list_args.verbose);
        }
        cli::Command::Export(export_args) => {
            if let Err(e) = vm_image::export::run_export(&export_args.name, export_args.output) {
                eprintln!("Export failed: {}", e);
                std::process::exit(1);
            }
        }
        cli::Command::Import(import_args) => {
            if let Err(e) = vm_image::import::run_import(&import_args.archive) {
                eprintln!("Import failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn run_setup(args: cli::SetupArgs) {
    if args.qemu && args.tart {
        panic!("Error: specify either --qemu or --tart, not both.");
    }

    if !args.qemu && !args.tart {
        panic!("Error: specify a backend with --qemu or --tart.");
    }

    if args.qemu {
        if let Err(e) = vm_image::setup_qemu::run_interactive_setup() {
            panic!("Setup failed: {}", e);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if args.tart {
            if let Err(e) = vm_image::setup_tart::run_interactive_setup() {
                panic!("Setup failed: {}", e);
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if args.tart {
            panic!("Tart setup is only available on macOS.");
        }
    }
}

fn run_jobs(jobs: Vec<run::Job>) {
    use colored::Colorize;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    for mut job in jobs {
        let job_name = job.name.clone();
        println!("{}", format!("=== Job {} ===", job_name).cyan().bold());

        let result = rt.block_on(job.run());

        match result {
            Ok(_) => println!(
                "{}\n",
                format!("=== Job {} completed ===", job_name).green().bold()
            ),
            Err(e) => {
                eprintln!(
                    "{}",
                    format!("=== Job {} failed: {} ===", job_name, e)
                        .red()
                        .bold()
                );
                std::process::exit(1);
            }
        }
    }

    println!("{}", "All jobs completed successfully".green().bold());

    backend::qemu::cleanup_stale_qemu_files();
    backend::tart::cleanup_stale_tart_clones();
}

fn run_cleanup(args: cli::CleanupArgs) {
    use colored::Colorize;
    use std::io::{self, Write};

    let files = find_vci_temp_files(&VCI_TEMP_PATH);

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
                Ok(_) => println!("{} {}", "Deleted:".green(), file.display()),
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
                    Ok(_) => println!("{}", "  Deleted".green()),
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
                if name.starts_with("vci-") && name.ends_with(".qcow2") {
                    files.push(path);
                }
            }
        }
    }

    files
}

fn setup_signal_handlers() {
    // background thread handles signals (kinda silly but whatever, tokio you do you)
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create signal handler runtime");

        rt.block_on(async {
            signal_handler().await;
        });
    });
}

async fn signal_handler() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sighup = signal(SignalKind::hangup()).unwrap();
        let mut sigquit = signal(SignalKind::quit()).unwrap();

        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
            _ = sighup.recv() => {},
            _ = sigquit.recv() => {},
        }

        std::process::exit(1);
    }

    #[cfg(windows)]
    {
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

        do_cleanup();
        std::process::exit(1);
    }
}

fn load_image_description(image_name: &str) -> vm_image::ImageDescription {
    let vci_path = vm_image::VCI_HOME_PATH.join(format!("{}.vci", image_name));
    let contents = std::fs::read_to_string(&vci_path).unwrap_or_else(|_| {
        panic!(
            "Failed to load image description '{}' (looked at {})",
            image_name,
            vci_path.display()
        )
    });
    let mut desc: vm_image::ImageDescription = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("Failed to parse image description '{}': {}", image_name, e));
    desc.name = image_name.to_string();
    return desc;
}

fn extract_yaml_workflows(args: cli::RunArgs) -> Vec<run::Job> {
    let file_contents = std::fs::read_to_string(&args.workflow)
        .unwrap_or_else(|_| panic!("Failed to load workflow file: {}", args.workflow.display()));

    let workflow: yaml::Workflow = yaml::parse_workflow(&file_contents)
        .unwrap_or_else(|e| panic!("Failed to parse workflow YAML: {}", e));

    // let image_overrides = cli::parse_overrides(&args.image);
    // let cpus_overrides = cli::parse_overrides(&args.cpus);
    // let mem_overrides = cli::parse_overrides(&args.mem);

    let mut jobs = Vec::<run::Job>::new();
    for (name, yaml_job) in workflow {
        // let image_name = cli::resolve_for_job(&image_overrides, &name)
        //     .unwrap_or(&yaml_job.image)
        //     .to_string();
        let image_name = yaml_job.image;

        let image_desc = load_image_description(&image_name);

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
                cli::parse_mem_mb(s).unwrap_or_else(|| panic!("Failed to parse memory: {}", s))
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
                        yaml::StepKind::Offline(b) => run::StepKind::Offline(b),
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
                backend::qemu::QemuBackend::new(name.clone(), image_desc, cpus, memory_mb)
                    .unwrap_or_else(|_| {
                        panic!("Failed to create QEMU backend for job '{}'", &name)
                    }),
            ),
            vm_image::BackendConfig::Tart(_) => Box::new(
                backend::tart::TartBackend::new(name.clone(), image_desc, cpus, memory_mb)
                    .unwrap_or_else(|_| {
                        panic!("Failed to create Tart backend for job '{}'", &name)
                    }),
            ),
        };

        jobs.push(run::Job {
            name,
            backend,
            host_env: yaml_job.host_env,
            steps,
        });
    }

    return jobs;
}
