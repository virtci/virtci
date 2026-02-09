mod backend;
mod cli;
mod file_lock;
mod job;
mod platform;
mod run;
mod ssh;
mod transfer_lock;
mod vm_image;
mod yaml;

use std::path::PathBuf;
use std::sync::Mutex;

pub(crate) static VCI_TEMP_PATH: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    return std::env::temp_dir().join("vci");
});

/// Right now, VMs are run synchronously. In the event of any error we can
/// handle (excluding total system failure),
/// we still want to not leave the user with non-cleaned up files.
static CLEANUP_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn set_cleanup_path(path: PathBuf) {
    if let Ok(mut guard) = CLEANUP_PATH.lock() {
        *guard = Some(path);
    }
}

pub fn clear_cleanup_path() {
    if let Ok(mut guard) = CLEANUP_PATH.lock() {
        *guard = None;
    }
}

fn do_cleanup() {
    if let Ok(guard) = CLEANUP_PATH.lock() {
        if let Some(ref path) = *guard {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn run_vci() {
    setup_signal_handlers();

    let args: cli::Args = argh::from_env();

    match args.command {
        cli::Command::Run(run_args) => {
            let jobs = extract_yaml_workflows(run_args);
            run_jobs(jobs);
        }
        cli::Command::Setup(setup_args) => {
            run_setup(setup_args);
        }
        cli::Command::Cleanup(cleanup_args) => {
            run_cleanup(cleanup_args);
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
            panic!("Tart setup is not yet implemented.");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if args.tart {
            panic!("Tart setup is only available on macOS.");
        }
    }
}

fn run_jobs(jobs: Vec<job::Job>) {
    use colored::Colorize;

    ssh::cleanup_stale_port_locks();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    for job in jobs {
        let job_name = job.name.clone();
        println!("{}", format!("=== Job {} ===", job_name).cyan().bold());

        let result = rt.block_on(job::run_job(job));

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
}

fn run_cleanup(args: cli::CleanupArgs) {
    use colored::Colorize;
    use std::io::{self, Write};

    let temp_dir = std::env::temp_dir();
    let files = find_vci_temp_files(&temp_dir);

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

        do_cleanup();
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

fn extract_yaml_workflows(args: cli::RunArgs) -> Vec<job::Job> {
    let file_contents = std::fs::read_to_string(&args.workflow).expect(&format!(
        "Failed to load workflow file: {}",
        args.workflow.to_str().unwrap()
    ));

    let workflow = {
        let res = yaml::parse_workflow(&file_contents);
        if res.is_err() {
            panic!("Failed to parse workflow YAML. {}", res.unwrap_err());
        }
        res.unwrap()
    };

    let image_overrides = cli::parse_overrides(&args.image);
    let arch_overrides = cli::parse_overrides(&args.arch);
    let cpus_overrides = cli::parse_overrides(&args.cpus);
    let mem_overrides = cli::parse_overrides(&args.mem);
    let user_overrides = cli::parse_overrides(&args.ssh_user);
    let pass_overrides = cli::parse_overrides(&args.ssh_password);
    let key_overrides = cli::parse_overrides(&args.ssh_key);
    let port_overrides = cli::parse_overrides(&args.ssh_port);

    let mut jobs = Vec::<job::Job>::default();
    for pair in workflow {
        let name = pair.0;

        let job_image = String::from(
            cli::resolve_for_job(&image_overrides, &name).unwrap_or(
                &pair
                    .1
                    .image
                    .expect("No override supplied, so expected image in YAML workflow"),
            ),
        );

        let job_arch: job::Arch = {
            let cli_arch = cli::resolve_for_job(&arch_overrides, &name);
            if let Some(arch_str) = cli_arch {
                job::Arch::parse(arch_str).expect(&format!("Invalid architecture: {}", arch_str))
            } else if let Some(ref yaml_arch) = pair.1.arch {
                job::Arch::parse(yaml_arch).expect(&format!("Invalid architecture: {}", yaml_arch))
            } else {
                job::Arch::default()
            }
        };

        let job_cpus: u32 = {
            let temp = cli::resolve_for_job(&cpus_overrides, &name);
            let mut num: u32 = 0;
            if temp.is_some() {
                num = temp.unwrap().parse::<u32>().expect("Expected number");
            } else {
                num = pair.1.cpus.unwrap_or(cli::default_cpus());
            }
            if num == 0 {
                panic!("Expected positive, non-zero CPU count");
            }
            num
        };

        let job_mem: u64 = {
            let temp = cli::resolve_for_job(&mem_overrides, &name);
            let mut num: u64;
            match temp {
                Some(s) => {
                    num = cli::parse_mem_mb(temp.unwrap())
                        .expect(&format!("Failed to parse job memory: {}", s))
                }
                None => match &pair.1.memory {
                    Some(mstr) => {
                        num = cli::parse_mem_mb(mstr)
                            .expect(&format!("Failed to parse job memory: {}", mstr))
                    }
                    None => num = cli::DEFAULT_MEM_MB,
                },
            }
            if num == 0 {
                panic!("Expected positive, non-zero memory amount");
            }
            num
        };

        let job_user = String::from(
            cli::resolve_for_job(&user_overrides, &name).unwrap_or(
                &pair
                    .1
                    .user
                    .expect("No override supplied, so expected user in YAML workflow"),
            ),
        );

        let job_pass: Option<String> = {
            let temp = cli::resolve_for_job(&pass_overrides, &name);
            let mut pass: Option<String> = None;
            if temp.is_some() {
                pass = Some(String::from(temp.unwrap()))
            } else {
                let yaml_temp = pair.1.pass;
                if yaml_temp.is_some() {
                    pass = Some(String::from(yaml_temp.unwrap()))
                }
            }

            pass
        };

        let job_key: Option<String> = {
            let temp = cli::resolve_for_job(&key_overrides, &name);
            let mut key: Option<String> = None;
            if temp.is_some() {
                key = Some(String::from(temp.unwrap()))
            } else {
                let yaml_temp = pair.1.key;
                if yaml_temp.is_some() {
                    key = Some(String::from(yaml_temp.unwrap()))
                }
            }

            key
        };

        if job_pass.is_none() && job_key.is_none() {
            panic!(
                "Job {} does not have either a password or SSH key specified",
                &name
            );
        }
        if job_pass.is_some() && job_key.is_some() {
            panic!(
                "Job {} may not have both a password or SSH key specified",
                &name
            );
        }

        let job_port: u16 = {
            let temp = cli::resolve_for_job(&port_overrides, &name);
            let mut num: u16;
            if temp.is_some() {
                num = temp.unwrap().parse::<u16>().expect("Expected number");
            } else {
                num = pair.1.port.unwrap_or(job::DEFAULT_VM_PORT);
            }
            num
        };

        let mut job_steps = Vec::<job::Step>::default();
        for step in pair.1.steps {
            match step.validate() {
                Ok(_) => (),
                Err(e) => panic!("{}", e),
            }

            let kind: job::StepKind = {
                if step.run.is_some() {
                    job::StepKind::Run(step.run.unwrap())
                } else if step.copy.is_some() {
                    job::StepKind::Copy(step.copy.unwrap())
                } else {
                    job::StepKind::Offline(step.offline.unwrap())
                }
            };

            let timeout = match step.timeout {
                Some(s) => yaml::parse_timeout_seconds(&s),
                None => job::MAX_TIMEOUT,
            };

            job_steps.push(job::Step {
                name: step.name,
                kind: kind,
                workdir: step.workdir,
                timeout: timeout,
                env: step.env,
                continue_on_error: step.continue_on_error,
            })
        }

        if job_steps.len() == 0 {
            panic!("Expected at least 1 step");
        }

        let job_uefi_firmware: Option<PathBuf> = match &pair.1.uefi {
            Some(yaml::UefiFirmware::Boolean(true)) => platform::find_uefi_firmware(job_arch),
            Some(yaml::UefiFirmware::Path(path)) => {
                let expanded = job::expand_path(path);
                if !expanded.exists() {
                    panic!(
                        "UEFI firmware file not found: {} (expanded to {})",
                        path,
                        expanded.display()
                    );
                }
                Some(expanded)
            }
            Some(yaml::UefiFirmware::Split(split)) => {
                let code_path = job::expand_path(&split.code);
                let vars_path = job::expand_path(&split.vars);
                if !code_path.exists() {
                    panic!(
                        "UEFI code file not found: {} (expanded to {})",
                        split.code,
                        code_path.display()
                    );
                }
                if !vars_path.exists() {
                    panic!(
                        "UEFI vars file not found: {} (expanded to {})",
                        split.vars,
                        vars_path.display()
                    );
                }
                None
            }
            Some(yaml::UefiFirmware::Boolean(false)) | None => None,
        };

        jobs.push(job::Job {
            name: name,
            image: job_image,
            arch: job_arch,
            cpus: job_cpus,
            memory: job_mem,
            user: job_user,
            pass: job_pass,
            key: job_key,
            port: job_port,
            uefi_firmware: job_uefi_firmware,
            uefi: pair.1.uefi.clone(),
            cpu_model: pair.1.cpu_model.clone(),
            additional_drives: pair.1.additional_drives.clone(),
            additional_devices: pair.1.additional_devices.clone(),
            qemu_args: pair.1.qemu_args.clone(),
            tpm: pair.1.tpm.clone(),
            nvme: pair.1.nvme,
            host_env: pair.1.host_env.clone(),
            steps: job_steps,
        });
    }

    return jobs;
}
