// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::{
    backend::{
        exec::{self, TargetChildProcess},
        qemu::{create_backing_file, PortFlock},
        VmBackend, VmStartConfig,
    },
    file_lock::FileLock,
    global_paths::{TargetPath, VciGlobalPaths},
    orphan::OrphanTracker,
    run::run_id::ReservedRunId,
    vm_image::{expand_path, HostExecTarget, ImageDescription},
};

use anyhow::Context;

const DEFAULT_CPUS: u32 = 2;
const DEFAULT_MEMORY_MB: u64 = 8192;

pub struct QemuBackend {
    pub run_id: ReservedRunId,
    /// Workflow name.
    pub name: String,
    pub base_image: ImageDescription,
    pub start_config: VmStartConfig,
    /// Basically always 22.
    pub inside_vm_port: u16,
    pub graphics: bool,
    /// If None, there is no `-serial` at all. If Some, serial is captured,
    /// and routed to stdio when `!graphics`, or to this file when `graphics`.
    pub serial_log: Option<TargetPath>,
    pub exec_target: HostExecTarget,
    /// The host-reachable IP the forwarded SSH port lives on. `127.0.0.1` for native targets;
    /// for a WSL2 target it's the distro's NAT IP, since QEMU's `hostfwd` binds inside WSL2 and
    /// `127.0.0.1` only works there if WSL2 localhost forwarding is enabled.
    pub ssh_ip: String,
    pub host_temp_dir: PathBuf,
    pub exec_target_temp_dir: TargetPath,

    /// Shared or exclusive `vci_image_<name>.lock`
    pub image_lock: FileLock,
    pub host_port: Option<PortFlock>,
    pub disk: BackingFile,
    /// pflash unit=0 code firmware path, in the exec namespace. May differ from the image's
    /// `uefi.code` when Secure Boot is substituted.
    pub uefi_code: Option<String>,
    /// May differ from the image's `uefi.vars` when Secure Boot is substituted.
    pub uefi_vars: Option<BackingFile>,
    pub additional_drives: Vec<AdditionalDrive>,
    pub tpm_info: Option<TpmInfo>,

    pub orphans: OrphanTracker,
    pub qemu_process: Option<Arc<Mutex<TargetChildProcess>>>,
    /// Must be stored here, as it must restart when QEMU process restarts.
    pub tpm_process: Option<Arc<Mutex<TargetChildProcess>>>,
}

impl QemuBackend {
    /// # Arguments
    /// - `clone` Whether to create a throwaway clone of `base_image` (writes discarded), or boot
    ///   the base itself (writes persist).
    /// - `graphics` Whether to display graphics.
    /// - `serial` Whether to attach a guest serial (interactive `virtci boot`) routed to stdio
    ///   when `!graphics`, or to a log file when `graphics`. `false` for `virtci run`.
    pub fn new(
        name: String,
        base_image: ImageDescription,
        paths: &VciGlobalPaths,
        clone: bool,
        graphics: bool,
        serial: bool,
        orphans: OrphanTracker,
    ) -> anyhow::Result<Self> {
        let run_id = ReservedRunId::new(paths)?;

        let exec_target: HostExecTarget = {
            #[cfg(target_os = "windows")]
            {
                // Where an image is stored is where it should run.
                if let Some(distro) = &base_image.wsl_distro {
                    HostExecTarget::WSL2(distro.clone())
                } else {
                    let qemu = base_image.backend.as_qemu().expect("Expected QEMU config");
                    if qemu.tpm {
                        anyhow::bail!(
                            "Image '{}' needs a TPM, which on Windows requires WSL2, but it is \
                             stored on the Windows host. Re-import it with a WSL2 distro \
                             configured.",
                            base_image.name
                        )
                    }
                    HostExecTarget::WindowsNative
                }
            }
            #[cfg(target_os = "macos")]
            {
                HostExecTarget::MacOS
            }
            #[cfg(target_os = "linux")]
            {
                HostExecTarget::Linux
            }
        };

        #[cfg(target_os = "windows")]
        let ssh_ip: String = match &exec_target {
            HostExecTarget::WSL2(distro) => match crate::backend::qemu::wsl_distro_ip(distro) {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!(
                        "Warning: could not resolve the WSL2 distro IP ({e}); falling back to \
                         127.0.0.1. SSH from the Windows host will fail unless WSL2 localhost \
                         forwarding is enabled."
                    );
                    "127.0.0.1".to_string()
                }
            },
            _ => "127.0.0.1".to_string(),
        };
        #[cfg(not(target_os = "windows"))]
        let ssh_ip: String = "127.0.0.1".to_string();

        let setup = setup_run(
            &name,
            run_id.id,
            &base_image,
            paths,
            &exec_target,
            serial,
            clone,
        )?;

        let host_temp_dir = paths.temp.clone();
        let exec_target_temp_dir = temp_dir_target(paths, &exec_target);

        Ok(QemuBackend {
            run_id,
            name,
            base_image,
            start_config: VmStartConfig::default(),
            // Guest-side SSH port. The host-side forwarded port lives in `host_port`.
            inside_vm_port: 22,
            graphics,
            serial_log: setup.serial_log,
            exec_target,
            ssh_ip,
            host_temp_dir,
            exec_target_temp_dir,
            image_lock: setup.image_lock,
            host_port: None,
            disk: setup.disk,
            uefi_code: setup.uefi_code,
            uefi_vars: setup.uefi_vars,
            additional_drives: setup.additional_drives,
            tpm_info: setup.tpm_info,
            orphans,
            qemu_process: None,
            tpm_process: None,
        })
    }

    pub fn is_base_mode(&self) -> bool {
        matches!(self.disk, BackingFile::Base(_))
    }

    pub fn is_tpm(&self) -> bool {
        self.tpm_info.is_some()
    }

    /// Host PID of the running QEMU process, or `None` when it runs inside WSL2 (no host PID),
    /// OR has not been spawned. Used by `virtci boot` to register a graceful-SIGTERM target.
    pub fn qemu_pid(&self) -> Option<u32> {
        self.qemu_process
            .as_ref()
            .and_then(|p| p.lock().ok().and_then(|g| g.host_pid()))
    }

    /// The run marker `vci-<name>-<id:05>`: QEMU's `-name`, the substring the orphan reaper
    /// `pkill -f`s, the metadata `run_name`, and the stem of every temp artifact. Zero-padding
    /// the id keeps one run's marker from being a substring of another's. Single source of truth,
    /// so it must match the file stems built in `setup_run`.
    pub fn run_marker(&self) -> String {
        format!("vci-{}-{:05}", self.name, self.run_id.id)
    }

    fn write_run_metadata(&mut self) -> anyhow::Result<()> {
        let ssh = self.ssh_target();
        let wsl_distro = match &self.exec_target {
            HostExecTarget::WSL2(distro) => Some(distro.clone()),
            _ => None,
        };
        let meta =
            crate::file_lock::LockMetadata::with_run_info(self.run_marker(), ssh, wsl_distro);
        let json =
            serde_json::to_string_pretty(&meta).context("Failed to serialize run metadata")?;
        self.run_id
            .flock_mut()
            .write_content(json.as_bytes())
            .map_err(|()| anyhow::anyhow!("Failed to write run metadata to the active-run lock"))?;
        Ok(())
    }

    fn spawn_swtpm(&mut self) -> anyhow::Result<()> {
        let tpm = self
            .tpm_info
            .as_ref()
            .expect("spawn_swtpm called without tpm_info");

        let args = vec![
            "socket".to_string(),
            "--tpmstate".to_string(),
            format!("dir={}", tpm.state_dir.native_path()),
            "--ctrl".to_string(),
            format!("type=unixio,path={}", tpm.socket_path.native_path()),
            "--tpm2".to_string(),
        ];

        let process = TargetChildProcess::new(
            &self.exec_target,
            &self.run_marker(),
            "swtpm",
            &args,
            exec::ChildIo::Quiet,
        )
        .context("Failed to spawn swtpm")?;
        self.orphans.add_child_process(&process);
        self.tpm_process = Some(process);

        self.wait_for_tpm_socket()
    }

    fn wait_for_tpm_socket(&self) -> anyhow::Result<()> {
        let socket = self
            .tpm_info
            .as_ref()
            .expect("wait_for_tpm_socket called without tpm_info")
            .socket_path
            .native_path();

        for _ in 0..50 {
            let ready = super::binaries::target_command(&self.exec_target, "test")
                .args(["-S", &socket])
                .status()
                .is_ok_and(|s| s.success());
            if ready {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        anyhow::bail!("swtpm control socket {socket} did not appear within 5s")
    }
}

impl VmBackend for QemuBackend {
    fn start_vm(&mut self, cfg: VmStartConfig) -> anyhow::Result<()> {
        if let Some(o) = cfg.offline {
            self.start_config.offline = Some(o);
        }
        if let Some(c) = cfg.cpus {
            self.start_config.cpus = Some(c);
        }
        if let Some(m) = cfg.memory_mb {
            self.start_config.memory_mb = Some(m);
        }

        let _ = self.start_config.cpus.get_or_insert(DEFAULT_CPUS);
        let _ = self.start_config.memory_mb.get_or_insert(DEFAULT_MEMORY_MB);

        self.host_port = Some(PortFlock::get_available(&self.host_temp_dir, 0)?);
        self.write_run_metadata()?;

        if self.is_tpm() {
            self.spawn_swtpm()?;
        }

        let stderr_log = self
            .host_temp_dir
            .join(format!("{}-qemu.stderr", self.run_marker()));

        let qemu_io = if self.serial_log.is_some() && !self.graphics {
            exec::ChildIo::Interactive(&stderr_log)
        } else {
            exec::ChildIo::StderrToFile(&stderr_log)
        };

        let qemu = loop {
            let cmd = super::binaries::build_qemu_args(self)?;

            eprintln!(
                "QEMU launch command... Attempting to bind QEMU to TCP port [{}]:",
                self.host_port.as_ref().expect("what").port
            );
            eprintln!(
                "{}",
                super::binaries::format_launch_command(&self.exec_target, &cmd)
            );

            let qemu = TargetChildProcess::new(
                &self.exec_target,
                &self.run_marker(),
                &cmd.program,
                &cmd.arguments,
                qemu_io,
            )
            .context("Failed to spawn QEMU")?;
            self.orphans.add_child_process(&qemu);

            match super::binaries::qemu_launch_outcome(&qemu, &stderr_log)? {
                super::binaries::QemuLaunchOutcome::Running => break qemu,
                super::binaries::QemuLaunchOutcome::PortTaken => {
                    // QEMU already exited, so drop it, release the reserved port, and try again.
                    drop(qemu);
                    let taken = self.host_port.as_ref().expect("port reserved").port;
                    self.host_port =
                        Some(PortFlock::get_available(&self.host_temp_dir, taken + 1)?);
                    self.write_run_metadata()?;
                }
            }
        };

        self.qemu_process = Some(qemu);

        Ok(())
    }

    fn stop_vm(&mut self) {
        if let Some(qemu) = self.qemu_process.take() {
            if let Ok(mut guard) = qemu.lock() {
                guard.kill();
            }
        }
        if let Some(tpm) = self.tpm_process.take() {
            if let Ok(mut guard) = tpm.lock() {
                guard.kill();
            }
        }

        // Directly remove swtpm's control socket, cause SIGKILL may not unlink it.
        // This allows a restarted swtpm to be able to recreate it.
        if let Some(info) = &self.tpm_info {
            let _ = super::binaries::target_command(&self.exec_target, "rm")
                .args(["-f", &info.socket_path.native_path()])
                .status();
        }

        self.host_port = None;
    }

    fn ssh_target(&self) -> crate::vm_image::SshTarget {
        crate::vm_image::SshTarget {
            ip: self.ssh_ip.clone(),
            port: self
                .host_port
                .as_ref()
                .expect("Need booted VM to get the host port")
                .port,
            cred: self.base_image.ssh.clone(),
        }
    }

    fn os(&self) -> crate::vm_image::GuestOs {
        self.base_image.os
    }

    fn is_offline(&self) -> bool {
        self.start_config.offline.unwrap_or(false)
    }

    fn offline_enforce_cmd(&self) -> Option<&'static str> {
        // slirp's `restrict=yes` breaks host->guest SSH on WSL2 (see `build_qemu_args`),
        // so offline is enforced in-guest by deleting the default route.
        // The tart backend does this. The subnet route remains, so SSH via the slirp gateway keeps
        // working. Route tables are in-memory and reset on VM restart, so toggling works.
        // Absolutely not as good as the restrict.
        if !matches!(self.exec_target, HostExecTarget::WSL2(_)) {
            return None;
        }
        match self.base_image.os {
            crate::vm_image::GuestOs::Windows => Some(
                "$peer = ($env:SSH_CONNECTION -split ' ')[0]; \
                 route add $peer mask 255.255.255.255 10.0.2.2 2>&1 | Out-Null; \
                 route delete 0.0.0.0 | Out-Null; \
                 if ($LASTEXITCODE -ne 0) { exit 1 }; \
                 route delete ::/0 2>&1 | Out-Null; exit 0",
            ),
            _ => Some(
                "peer=\"${SSH_CONNECTION%% *}\" && \
                 { sudo ip route add \"$peer/32\" via 10.0.2.2 2>/dev/null || true; } && \
                 sudo ip route del default && (sudo ip -6 route del default || true)",
            ),
        }
    }

    fn run_name(&self) -> String {
        self.run_marker()
    }

    fn vm_exit_error(&mut self) -> Option<String> {
        let qemu = self.qemu_process.as_ref()?;
        let exited = qemu.lock().ok()?.try_wait();
        if !exited {
            return None;
        }
        let stderr_log = self
            .host_temp_dir
            .join(format!("{}-qemu.stderr", self.run_marker()));
        let stderr = std::fs::read_to_string(stderr_log).unwrap_or_default();
        let stderr = stderr.trim();
        if stderr.is_empty() {
            Some("QEMU exited with no stderr output".to_string())
        } else {
            Some(format!("QEMU exited:\n{stderr}"))
        }
    }

    fn wait_for_exit(&mut self) {
        if let Some(qemu) = self.qemu_process.clone() {
            loop {
                let exited = qemu.lock().map_or(true, |mut guard| guard.try_wait());
                if exited {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }

        self.qemu_process = None;
        if let Some(tpm) = self.tpm_process.take() {
            if let Ok(mut guard) = tpm.lock() {
                guard.kill();
            }
        }

        // Directly remove swtpm's control socket, cause SIGKILL may not unlink it.
        // This allows a restarted swtpm to be able to recreate it.
        if let Some(info) = &self.tpm_info {
            let _ = super::binaries::target_command(&self.exec_target, "rm")
                .args(["-f", &info.socket_path.native_path()])
                .status();
        }
    }

    fn serial_log_path(&self) -> Option<&Path> {
        if let Some(serial_log) = &self.serial_log {
            return Some(serial_log.path.as_path());
        }
        None
    }
}

impl Drop for QemuBackend {
    fn drop(&mut self) {
        if let Some(qemu) = self.qemu_process.take() {
            if let Ok(mut guard) = qemu.lock() {
                guard.kill();
            }
        }
        if let Some(tpm) = self.tpm_process.take() {
            if let Ok(mut guard) = tpm.lock() {
                guard.kill();
            }
        }

        // [`BackingFile::temp()`] returns a path only for `Temp`.
        let mut files: Vec<PathBuf> = Vec::new();
        if let Some(p) = self.disk.temp() {
            files.push(p.path.clone());
        }
        if let Some(p) = self.uefi_vars.as_ref().and_then(|v| v.temp()) {
            files.push(p.path.clone());
        }
        for drive in &self.additional_drives {
            if let Some(p) = drive.file.temp() {
                files.push(p.path.clone());
            }
        }
        if let Some(serial) = &self.serial_log {
            files.push(serial.path.clone());
        }
        files.push(
            self.host_temp_dir
                .join(format!("{}-qemu.stderr", self.run_marker())),
        );

        for path in files {
            let _ = std::fs::remove_file(&path);
        }

        if let Some(info) = &self.tpm_info {
            let _ = std::fs::remove_dir_all(&info.state_dir.path);
        }
    }
}

/// A file the VM boots from, resolved to the `exec_target`'s namespace fully. The variant is the
/// source of truth for whether cleanup should delete it or not.
/// - [`BackingFile::Base`] is the image's own file, used in place so writes persist and it is
///   NEVER deleted. This is `virtci boot`.
/// - [`BackingFile::Temp`] is a per-run throwaway in the temp dir (a qcow2 overlay for disks, a
///   plain copy for UEFI vars) so writes are discarded and it is deleted on cleanup.
///   Always for `virtci run`.
pub enum BackingFile {
    Base(TargetPath),
    Temp(TargetPath),
}

impl BackingFile {
    /// The path QEMU should use, in either mode.
    pub fn target(&self) -> &TargetPath {
        match self {
            BackingFile::Base(p) | BackingFile::Temp(p) => p,
        }
    }

    /// `Some` only for a throwaway file that cleanup is responsible for deleting.
    pub fn temp(&self) -> Option<&TargetPath> {
        match self {
            BackingFile::Temp(p) => Some(p),
            BackingFile::Base(_) => None,
        }
    }
}

/// One extra `-drive`, such as the macOS OpenCore bootloader. `spec` is the full `-drive` arg
/// with its `file=` already pointing at `file`'s in-namespace path.
pub struct AdditionalDrive {
    pub spec: String,
    pub file: BackingFile,
}

pub struct TpmInfo {
    pub state_dir: TargetPath,
    /// swtpm's control socket inside of `state_dir`. swtpm and QEMU share it.
    pub socket_path: TargetPath,
}

struct RunSetup {
    image_lock: FileLock,
    disk: BackingFile,
    uefi_code: Option<String>,
    uefi_vars: Option<BackingFile>,
    additional_drives: Vec<AdditionalDrive>,
    tpm_info: Option<TpmInfo>,
    serial_log: Option<TargetPath>,
}

/// Acquire a flock on the image. Shared lock if `clone`, otherwise Exclusive.
fn acquire_image_lock(
    paths: &VciGlobalPaths,
    image_name: &str,
    clone: bool,
) -> anyhow::Result<FileLock> {
    let lock_path = paths.temp.join(format!("vci_image_{image_name}.lock"));
    if clone {
        FileLock::try_new_shared(&lock_path).map_err(|e| {
            let msg = match e {
                crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                    "Image '{image_name}' is currently being modified by `virtci boot`. \
                     Wait for it to finish before starting a new run."
                ),
                crate::file_lock::FileLockError::Other => format!(
                    "Failed to acquire shared lock for image '{image_name}'. \
                     If `virtci boot` is not running, try `virtci cleanup --force`."
                ),
            };
            anyhow::anyhow!(msg)
        })
    } else {
        FileLock::try_new(&lock_path).map_err(|e| {
            let msg = match e {
                crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                    "Image '{image_name}' is currently in use by another virtci process — \
                     cannot boot it for modification while it is running."
                ),
                crate::file_lock::FileLockError::Other => format!(
                    "Failed to acquire exclusive lock for image '{image_name}'. \
                     Try `virtci cleanup --force` if no other run is active."
                ),
            };
            anyhow::anyhow!(msg)
        })
    }
}

/// Set up everything a run needs in `exec_target`'s temp dir, short of acquiring the SSH port
/// (that waits until launch). `clone` selects throwaway overlays/copies (`virtci run`) vs the
/// image's own files in place (`virtci boot`), decided per artifact via [`BackingFile`].
fn setup_run(
    name: &str,
    id: u16,
    base_image: &ImageDescription,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    serial: bool,
    clone: bool,
) -> anyhow::Result<RunSetup> {
    let qemu_config = base_image.backend.as_qemu().expect("Expected QEMU config");

    let image_lock = acquire_image_lock(paths, &base_image.name, clone)?;

    // May be inside WSL2.
    let temp_dir = temp_dir_target(paths, exec_target);
    std::fs::create_dir_all(&temp_dir.path).with_context(|| {
        format!(
            "Failed to create temp directory {}",
            temp_dir.path.display()
        )
    })?;

    let disk = setup_disk(name, id, qemu_config, paths, exec_target, &temp_dir, clone)?;
    let (uefi_code, uefi_vars) = setup_uefi(
        name,
        id,
        qemu_config,
        paths,
        exec_target,
        &temp_dir,
        clone,
        base_image.arch,
    )?;
    let additional_drives =
        setup_additional_drives(name, id, qemu_config, paths, exec_target, &temp_dir, clone)?;

    // swtpm state is always a fresh per-run scratch dir, even in base mode: the `.vci` does not
    // store vTPM state yet, so persisting it across boots is a separate, future feature.
    let tpm_info = if qemu_config.tpm {
        let state_dir = temp_dir.join(&format!("vci-{name}-{id:05}-tpm"));
        std::fs::create_dir_all(&state_dir.path).with_context(|| {
            format!(
                "Failed to create TPM state dir {}",
                state_dir.path.display()
            )
        })?;
        let socket_path = state_dir.join("swtpm-sock");
        Some(TpmInfo {
            state_dir,
            socket_path,
        })
    } else {
        None
    };

    let serial_log = serial.then(|| temp_dir.join(&format!("vci-{name}-{id:05}-serial.log")));

    Ok(RunSetup {
        image_lock,
        disk,
        uefi_code,
        uefi_vars,
        additional_drives,
        tpm_info,
        serial_log,
    })
}

/// Main disk: a throwaway qcow2 overlay backed by the base (clone), or the base disk itself used
/// in place so writes persist (base).
fn setup_disk(
    name: &str,
    id: u16,
    qemu_config: &crate::vm_image::QemuConfig,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    temp_dir: &TargetPath,
    clone: bool,
) -> anyhow::Result<BackingFile> {
    if !clone {
        return Ok(BackingFile::Base(config_path_target_with_unc(
            &qemu_config.image,
            exec_target,
            paths,
        )));
    }

    // Non-UNC path, but may be a path to be done inside WSL2.
    let source_exec = expand_exec_path_no_unc(&qemu_config.image, exec_target, paths);
    let overlay = temp_dir.join(&format!("vci-{name}-{id:05}.qcow2"));
    create_backing_file(&source_exec, &overlay.native_path(), exec_target)
        .context("Failed to create the thin qcow2 overlay backing the clone")?;
    Ok(BackingFile::Temp(overlay))
}

#[allow(clippy::too_many_arguments)]
fn setup_uefi(
    name: &str,
    id: u16,
    qemu_config: &crate::vm_image::QemuConfig,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    temp_dir: &TargetPath,
    clone: bool,
    arch: crate::vm_image::Arch,
) -> anyhow::Result<(Option<String>, Option<BackingFile>)> {
    let Some(uefi) = &qemu_config.uefi else {
        return Ok((None, None));
    };

    let wants_substitute = crate::vm_image::host_lacks_smm(exec_target)
        && crate::vm_image::is_maybe_secure_boot_firmware(uefi);

    let substitute = if wants_substitute {
        super::binaries::find_non_secboot_firmware(arch, exec_target)
    } else {
        None
    };

    if wants_substitute {
        let configured = crate::vm_image::export::filename_of(&uefi.code);
        match &substitute {
            Some((sub_code, _)) => eprintln!(
                "Note: '{name}' uses Secure Boot firmware ({configured}), which cannot run on this \
                 host (no SMM). Substituting non-secboot firmware: {sub_code}"
            ),
            None => eprintln!(
                "Warning: '{name}' uses Secure Boot firmware ({configured}), which cannot run on \
                 this host (no SMM), and no non-secboot OVMF was found to substitute it. Boot will \
                 likely fail — install the 'ovmf' package in the exec environment."
            ),
        }
    }

    let (code, vars_src) = match &substitute {
        Some((sub_code, sub_vars)) => (
            sub_code.clone(),
            config_path_target_with_unc(sub_vars, exec_target, paths),
        ),
        None => (
            uefi.code.clone(),
            config_path_target_with_unc(&uefi.vars, exec_target, paths),
        ),
    };

    let vars_backing = if substitute.is_some() || clone {
        let dest = temp_dir.join(&format!("vci-{name}-{id:05}-VARS.fd"));
        let contents = std::fs::read(&vars_src.path)
            .with_context(|| format!("Failed to read UEFI vars {}", vars_src.path.display()))?;
        std::fs::write(&dest.path, &contents)
            .with_context(|| format!("Failed to write UEFI vars to {}", dest.path.display()))?;
        BackingFile::Temp(dest)
    } else {
        BackingFile::Base(vars_src)
    };

    Ok((Some(code), Some(vars_backing)))
}

fn setup_additional_drives(
    name: &str,
    id: u16,
    qemu_config: &crate::vm_image::QemuConfig,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    temp_dir: &TargetPath,
    clone: bool,
) -> anyhow::Result<Vec<AdditionalDrive>> {
    let Some(specs) = &qemu_config.additional_drives else {
        return Ok(Vec::new());
    };

    let mut drives = Vec::new();
    for (idx, spec) in specs.iter().enumerate() {
        let Some(file_start) = spec.find("file=") else {
            continue;
        };
        let after_file = &spec[file_start + 5..];
        let file_path = match after_file.find(',') {
            Some(comma) => &after_file[..comma],
            None => after_file,
        };

        let file = if clone {
            let source = expand_exec_path_no_unc(file_path, exec_target, paths);
            let overlay = temp_dir.join(&format!("vci-{name}-drive{idx}-{id:05}.qcow2"));
            create_backing_file(&source, &overlay.native_path(), exec_target)
                .with_context(|| format!("Failed to create overlay for additional drive {idx}"))?;
            BackingFile::Temp(overlay)
        } else {
            BackingFile::Base(config_path_target_with_unc(file_path, exec_target, paths))
        };

        let updated_spec = spec.replace(
            &format!("file={file_path}"),
            &format!("file={}", file.target().native_path()),
        );
        drives.push(AdditionalDrive {
            spec: updated_spec,
            file,
        });
    }
    Ok(drives)
}

/// Expands an image-config path string into `exec_target`'s namespace, without UNC prefixing.
/// Host-native targets call [`expand_path`], such as host `~/` become the host's user home.
/// For [`HostExecTarget::WSL2`], the path becomes the WSL distro's `$HOME`, and separators
/// stay as `/` NOT `\`.
fn expand_exec_path_no_unc(
    path: &str,
    exec_target: &HostExecTarget,
    paths: &VciGlobalPaths,
) -> String {
    #[cfg(target_os = "windows")]
    if let HostExecTarget::WSL2(_) = exec_target {
        let wsl = paths
            .wsl
            .as_ref()
            .expect("WSL2 exec target implies WSL paths");
        return match path.strip_prefix("~/") {
            Some(rest) => format!("{}/{rest}", wsl.wsl_home.trim_end_matches('/')),
            None => path.to_string(),
        };
    }

    let _ = (exec_target, paths);
    expand_path(path).to_string_lossy().into_owned()
}

/// Like [`expand_exec_path_no_unc`], but returns a full [`TargetPath`] whose `path` is reachable
/// from the Windows host, like a `\\wsl.localhost\<distro>` UNC share for WSL2, or a plain host path
/// otherwise. Use this when the host's own `std::fs` must touch the file (e.g. copying UEFI
/// vars). Use [`expand_exec_path_no_unc`] when the path is consumed by a process running inside
/// the namespace. The returned `TargetPath` still yields the in-namespace `/`-path by calling
/// `native_path()`.
fn config_path_target_with_unc(
    path: &str,
    exec_target: &HostExecTarget,
    paths: &VciGlobalPaths,
) -> TargetPath {
    let exec_str = expand_exec_path_no_unc(path, exec_target, paths);

    #[cfg(target_os = "windows")]
    {
        if let HostExecTarget::WSL2(distro) = exec_target {
            let wsl = paths
                .wsl
                .as_ref()
                .expect("WSL2 exec target implies WSL paths");
            return TargetPath {
                path: wsl.to_unc(&exec_str),
                wsl_distro: Some(distro.clone()),
            };
        }
        TargetPath {
            path: PathBuf::from(exec_str),
            wsl_distro: None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        TargetPath {
            path: PathBuf::from(exec_str),
        }
    }
}

fn temp_dir_target(paths: &VciGlobalPaths, exec_target: &HostExecTarget) -> TargetPath {
    #[cfg(target_os = "windows")]
    {
        if let HostExecTarget::WSL2(distro) = exec_target {
            let wsl = paths
                .wsl
                .as_ref()
                .expect("WSL2 exec target implies WSL paths");
            return TargetPath {
                path: wsl.to_unc(&wsl.temp),
                wsl_distro: Some(distro.clone()),
            };
        }
        TargetPath {
            path: paths.temp.clone(),
            wsl_distro: None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = exec_target;
        TargetPath {
            path: paths.temp.clone(),
        }
    }
}
