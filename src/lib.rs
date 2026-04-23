// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

pub mod backend;
pub mod cli;
pub mod client;
pub mod file_lock;
pub mod run;
pub mod run_state;
pub mod server;
pub mod transfer_lock;
pub mod vm_image;
pub mod yaml;

use std::path::PathBuf;

use argh::FromArgs;

use crate::vm_image::ImageDescription;

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
    setup_signal_handlers();

    backend::qemu::cleanup_stale_qemu_files(&paths.temp);
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
            run_setup(&setup_args, &paths.home);
        }
        cli::Command::Cleanup(cleanup_args) => {
            run_cleanup(cleanup_args, paths);
        }
        cli::Command::List(list_args) => {
            vm_image::list::run_list(list_args.verbose, &paths.home);
        }
        cli::Command::Export(export_args) => {
            if let Err(e) =
                vm_image::export::run_export(&export_args.name, export_args.output, &paths.home)
            {
                eprintln!("Export failed: {e}");
                std::process::exit(1);
            }
        }
        cli::Command::Import(import_args) => {
            if let Err(e) = vm_image::import::run_import(&import_args.archive, &paths.home) {
                eprintln!("Import failed: {e}");
                std::process::exit(1);
            }
        }
        cli::Command::Active(_) => {
            run_state::run_active(&paths.temp);
        }
        cli::Command::Remove(remove_args) => {
            vm_image::remove::run_remove(&remove_args, &paths.home);
        }
        cli::Command::Boot(boot_args) => {
            if let Err(e) = vm_image::boot::run_boot(&boot_args, paths) {
                eprintln!("Boot failed: {e:?}");
                std::process::exit(1);
            }
        }
        cli::Command::Shell(shell_args) => {
            run_state::run_shell(&shell_args, &paths.temp);
        }
        cli::Command::Serve(serve_args) => {
            let mut config = server::ServerConfig::default();
            if let Some(port) = serve_args.port {
                config.port = port;
            }

            if !serve_args.s3_url.is_empty() {
                config.s3 = serve_args.s3_url;
            }

            if !serve_args.db_path.is_empty() {
                config.db_path = Some(PathBuf::from(serve_args.db_path));
            } else {
                config.db_path = Some(paths.home.clone());
            }

            let server = server::Server::new(config, &paths).expect("Failed to start server");
            server.wait();
        }
        cli::Command::Push(push_args) => {
            if let Err(e) = client::push::run_push(&push_args, paths) {
                eprintln!("Import failed: {e:?}");
                std::process::exit(1);
            }
        }
    }
}

fn run_setup(args: &cli::SetupArgs, home_path: &PathBuf) {
    if let Some(ref from_path) = args.from {
        if let Err(e) = vm_image::run_from_file(from_path, home_path, args.name.as_deref()) {
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

    if args.qemu {
        if let Err(e) = vm_image::setup_qemu::run_interactive_setup(home_path) {
            panic!("Setup failed: {e}");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if args.tart {
            if let Err(e) = vm_image::setup_tart::run_interactive_setup(home_path) {
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

    backend::qemu::cleanup_stale_qemu_files(&paths.temp);
    backend::tart::cleanup_stale_tart_clones(&paths.temp);

    if failed {
        std::process::exit(1);
    }

    println!("{}", "All jobs completed successfully".green().bold());
}

fn run_cleanup(args: cli::CleanupArgs, paths: &VciGlobalPaths) {
    use colored::Colorize;
    use std::io::{self, Write};

    let files = find_vci_temp_files(&paths.temp);

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
                if name.starts_with("vci-")
                    && std::path::Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("qcow2"))
                {
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

        std::process::exit(1);
    }
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

        let image_desc = ImageDescription::load_from_disk(image_name, &paths.home)
            .expect("Failed to load image");

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
                backend::qemu::QemuBackend::new(
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

/// Tests need to be able to control where they're writing to. Using
/// `VciGlobalPaths::default()` works for normal use.
pub struct VciGlobalPaths {
    pub home: PathBuf,
    pub temp: PathBuf,
    /// Directory storing the cached remote VM images. Should be accessible by any user on the system for reading.
    pub cache: PathBuf,
}

impl VciGlobalPaths {
    fn default_home_path() -> PathBuf {
        if let Some(vci_home) = std::env::var_os("VIRTCI_HOME_DIR") {
            return PathBuf::from(vci_home);
        }

        #[cfg(target_os = "macos")]
        {
            // ~/.vci/ (kinda matches tart)
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(".vci");
            }
        }

        #[cfg(target_os = "linux")]
        {
            // $XDG_DATA_HOME/vci or ~/.local/share/vci/
            if let Some(xdg_data) = std::env::var_os("XDG_DATA_HOME") {
                return PathBuf::from(xdg_data).join("vci");
            }
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(".local/share/vci");
            }
        }

        #[cfg(target_os = "windows")]
        {
            // %LOCALAPPDATA%\vci\
            if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
                return PathBuf::from(local_app_data).join("vci");
            }
        }

        PathBuf::from(".vci")
    }

    pub fn create_temp_dir(&self) -> anyhow::Result<()> {
        return anyhow::Context::with_context(std::fs::create_dir_all(&self.temp), || {
            format!(
                "Failed to create temp directory at '{}'",
                self.temp.display()
            )
        });
    }

    fn default_cache_dir() -> PathBuf {
        if let Some(vci_cache) = std::env::var_os("VIRTCI_CACHE_DIR") {
            return PathBuf::from(vci_cache);
        }

        #[cfg(target_os = "macos")]
        {
            return PathBuf::from("/Users/Shared/virtci_cache");
        }

        #[cfg(target_os = "linux")]
        {
            // even if the cache is evicted, thats fine, cause it can be re-pulled.
            // furthermore, if a vm image is evicted mid run, the fd will stay valid while the process runs.
            return PathBuf::from("/var/tmp/virtci_cache");
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(public) = std::env::var_os("PUBLIC") {
                return PathBuf::from(public).join("virtci_cache");
            }
            return PathBuf::from("C:\\Users\\Public\\virtci_cache"); // default assuming C drive
        }
    }

    pub fn create_cache_dir(&self) -> anyhow::Result<()> {
        use anyhow::Context;

        std::fs::create_dir_all(&self.cache).with_context(|| {
            format!(
                "Failed to create cache directory at '{}'",
                self.cache.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            const DESIRED_MODE: u32 = 0o1777;

            let current_mode = std::fs::metadata(&self.cache)
                .with_context(|| {
                    format!(
                        "Failed to stat cache directory at '{}'",
                        self.cache.display()
                    )
                })?
                .permissions()
                .mode()
                & 0o7777;

            if current_mode != DESIRED_MODE {
                let perms = std::fs::Permissions::from_mode(DESIRED_MODE);
                if let Err(e) = std::fs::set_permissions(&self.cache, perms) {
                    if current_mode & 0o1777 != 0o1777 {
                        return Err(anyhow::Error::new(e).context(format!(
                            "Cache directory at '{}' has mode {:o}, expected 1777, and cannot be chmod'd",
                            self.cache.display(),
                            current_mode
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for VciGlobalPaths {
    fn default() -> Self {
        Self {
            home: Self::default_home_path(),
            temp: std::env::temp_dir().join("vci"),
            cache: Self::default_cache_dir(),
        }
    }
}
