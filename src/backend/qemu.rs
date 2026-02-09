use std::{io::Write, path::PathBuf, process::Child};

use colored::Colorize;

use crate::{
    backend::{qemu, VmBackend},
    file_lock::{FileLock, FileLockError},
    job::{expand_path, expand_path_in_string},
    ssh::{self, SshTarget},
    vm_image::{Arch, GuestOs, ImageDescription, UefiSplit},
    VCI_TEMP_PATH,
};

pub struct QemuRunner {
    pub host_port: (FileLock, u16),
    temp_image: FileLock,
    temp_uefi_vars: Option<FileLock>,
    temp_additional_drives: Vec<(String, FileLock)>, // (original_spec, temp_path)
    tpm_state_dir: Option<PathBuf>,
    tpm_socket_path: Option<PathBuf>,
    tpm_flock: Option<FileLock>,
    qemu_process: Option<Child>,
    tpm_process: Option<Child>,
}

pub struct QemuBackend {
    pub name: String,
    pub base_image: ImageDescription,
    pub cpus: u32,
    /// Megabytes
    pub memory_mb: u64,
    /// Port within the VM that SSH accesses.
    pub inside_vm_port: u16,
    pub runner: Option<QemuRunner>,
}

impl QemuBackend {
    fn new(
        name: String,
        base_image: ImageDescription,
        cpus: u32,
        memory_mb: u64,
    ) -> Result<Self, ()> {
        let mut backend = QemuBackend {
            name: name,
            base_image: base_image,
            cpus: cpus,
            memory_mb: memory_mb,
            inside_vm_port: 22,
            runner: None,
        };

        backend.setup_clone()?;

        return Ok(backend);
    }

    fn build_qemu_cmd(&self, offline: bool) -> std::process::Command {
        let qemu_config = self.base_image.backend.as_qemu().unwrap();
        let mut cmd = std::process::Command::new(qemu_system_binary(self.base_image.arch));

        cmd.arg("-machine").arg(qemu_machine(self.base_image.arch));

        if let Some(ref cpu_model) = qemu_config.cpu_model {
            cmd.arg("-cpu").arg(cpu_model);
        } else {
            cmd.arg("-cpu").arg(qemu_cpu(self.base_image.arch));
        }

        cmd.arg("-name").arg(&self.name);
        cmd.arg("-m").arg(format!("{}M", self.memory_mb));
        cmd.arg("-smp").arg(self.cpus.to_string());

        if let Some(ref uefi) = qemu_config.uefi {
            // Split UEFI: code (readonly) + vars (writable)
            let code_path = expand_path(&uefi.code);
            cmd.arg("-drive").arg(format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                code_path.display()
            ));
            if self.runner.as_ref().unwrap().temp_uefi_vars.is_some() {
                cmd.arg("-drive").arg(format!(
                    "if=pflash,format=raw,unit=1,file={}",
                    self.runner
                        .as_ref()
                        .unwrap()
                        .temp_uefi_vars
                        .as_ref()
                        .unwrap()
                        .get_path()
                        .display()
                ));
            }
        }

        // Some VMs need additional drives like OpenCore bootloader for macOS
        for (drive_spec, _) in &self.runner.as_ref().unwrap().temp_additional_drives {
            cmd.arg("-drive").arg(drive_spec);
        }

        // main disk
        // if=none only when additional_devices will attach it
        // windows arm64 requires nvme? At least when made with UTM? Idk
        if qemu_config.additional_devices.is_some() {
            cmd.arg("-drive").arg(format!(
                "id=SystemDisk,if=none,file={},format=qcow2",
                self.runner
                    .as_ref()
                    .unwrap()
                    .temp_image
                    .get_path()
                    .display()
            ));
        } else {
            match self.base_image.arch {
                Arch::ARM64 | Arch::RISCV64 => {
                    cmd.arg("-drive").arg(format!(
                        "id=SystemDisk,if=none,file={},format=qcow2",
                        self.runner
                            .as_ref()
                            .unwrap()
                            .temp_image
                            .get_path()
                            .display()
                    ));
                    if qemu_config.nvme {
                        cmd.arg("-device")
                            .arg("nvme,drive=SystemDisk,serial=SystemDisk,bootindex=0");
                    } else {
                        cmd.arg("-device")
                            .arg("virtio-blk-pci,drive=SystemDisk,bootindex=0");
                    }
                }
                Arch::X64 => {
                    cmd.arg("-drive").arg(format!(
                        "file={},format=qcow2",
                        self.runner
                            .as_ref()
                            .unwrap()
                            .temp_image
                            .get_path()
                            .display()
                    ));
                }
            };
        }

        cmd.arg("-display").arg("none");

        // hardware accel if possible
        #[cfg(target_os = "linux")]
        {
            if crate::platform::is_kvm_available() {
                cmd.arg("-accel").arg("kvm");
            }
        }
        #[cfg(target_os = "macos")]
        cmd.arg("-accel").arg("hvf");
        #[cfg(target_os = "windows")]
        cmd.arg("-accel").arg("whpx");
        cmd.arg("-accel").arg("tcg");

        let netdev = if offline {
            format!(
                "user,id=net0,restrict=yes,hostfwd=tcp::{}-:{}",
                self.runner.as_ref().unwrap().host_port.1,
                self.inside_vm_port
            )
        } else {
            format!(
                "user,id=net0,hostfwd=tcp::{}-:{}",
                self.runner.as_ref().unwrap().host_port.1,
                self.inside_vm_port
            )
        };
        cmd.arg("-netdev").arg(netdev);
        cmd.arg("-device").arg("virtio-net-pci,netdev=net0");

        // TPM stuff
        if let Some(ref socket_path) = self.runner.as_ref().unwrap().tpm_socket_path {
            cmd.arg("-chardev")
                .arg(format!("socket,id=chrtpm,path={}", socket_path.display()));
            cmd.arg("-tpmdev").arg("emulator,id=tpm0,chardev=chrtpm");
            let tpm_device = match self.base_image.arch {
                Arch::ARM64 | Arch::RISCV64 => "tpm-tis-device,tpmdev=tpm0".to_string(),
                Arch::X64 => "tpm-tis,tpmdev=tpm0".to_string(),
            };
            cmd.arg("-device").arg(tpm_device);
        }

        if let Some(ref additional_devices) = qemu_config.additional_devices {
            for device in additional_devices {
                let expanded_device = expand_path_in_string(device);
                cmd.arg("-device").arg(expanded_device);
            }
        }

        // TODO need raw args?
        // if let Some(ref qemu_args) = self.qemu_args {
        //     for arg in qemu_args {
        //         let expanded_arg = expand_path_in_string(arg);
        //         cmd.arg(expanded_arg);
        //     }
        // }

        return cmd;
    }
}

impl VmBackend for QemuBackend {
    /// BEFORE: self.runner.is_none()
    /// AFTER: self.runner.is_some()
    fn setup_clone(&mut self) -> Result<(), ()> {
        assert!(self.runner.is_none());

        let qemu_config = self.base_image.backend.as_qemu().unwrap();

        let host_port_flock = get_port_flock().expect("Failed to get any port for QEMU");

        let source_image = expand_path(&qemu_config.image);
        let temp_image =
            VCI_TEMP_PATH.join(format!("vci-{}-{}.qcow2", self.name, host_port_flock.1));
        let new_image_backed = create_backing_file(&source_image, &temp_image)?;

        let temp_vars = if let Some(ref split) = qemu_config.uefi {
            let temp_vars_path =
                VCI_TEMP_PATH.join(format!("vci-{}-{}-VARS.fd", self.name, host_port_flock.1));
            let mut vars_flock = FileLock::try_new(temp_vars_path).map_err(|_| ())?;
            let contents = std::fs::read(expand_path(&split.vars)).map_err(|_| ())?;
            vars_flock
                .get_file_mut()
                .write_all(&contents)
                .map_err(|_| ())?;
            Some(vars_flock)
        } else {
            None
        };

        let mut temp_additional_drives = Vec::<(String, FileLock)>::new();
        if let Some(ref drives) = qemu_config.additional_drives {
            for (idx, drive_spec) in drives.iter().enumerate() {
                if let Some(file_start) = drive_spec.find("file=") {
                    let after_file = &drive_spec[file_start + 5..];
                    let file_path = if let Some(comma_pos) = after_file.find(',') {
                        &after_file[..comma_pos]
                    } else {
                        after_file
                    };

                    let source_path = expand_path(file_path);
                    let temp_path = VCI_TEMP_PATH.join(format!(
                        "vci-{}-{}-drive-{}.qcow2",
                        &self.name, host_port_flock.1, idx
                    ));
                    let drive_flock = create_backing_file(&source_path, &temp_path)?;

                    let updated_spec = drive_spec.replace(
                        &format!("file={}", file_path),
                        &format!("file={}", temp_path.display()),
                    );
                    temp_additional_drives.push((updated_spec, drive_flock));
                } else {
                    // TODO is this necessary?
                    // temp_additional_drives.push((drive_spec.clone(), ??));
                }
            }
        }

        let (tpm_state_dir, tpm_socket_path, tpm_flock) = if qemu_config.tpm {
            let tpm_lock_file =
                VCI_TEMP_PATH.join(&format!("vci-{}-{}-tpm.lock", self.name, host_port_flock.1));
            let tpm_flock_file = FileLock::try_new(tpm_lock_file).map_err(|_| ())?;
            let state_dir =
                VCI_TEMP_PATH.join(&format!("vci-{}-{}-tpm", self.name, host_port_flock.1));
            std::fs::create_dir_all(&state_dir).map_err(|_| ())?;
            let socket_path = state_dir.join("swtpm-sock");
            (Some(state_dir), Some(socket_path), Some(tpm_flock_file))
        } else {
            (None, None, None)
        };

        let runner = QemuRunner {
            host_port: host_port_flock,
            temp_image: new_image_backed,
            temp_uefi_vars: temp_vars,
            temp_additional_drives: temp_additional_drives,
            tpm_state_dir: tpm_state_dir,
            tpm_socket_path: tpm_socket_path,
            tpm_flock: tpm_flock,
            qemu_process: None,
            tpm_process: None,
        };

        self.runner = Some(runner);
        return Ok(());
    }

    fn start_vm(&mut self, offline: bool) -> Result<(), ()> {
        {
            let runner = self.runner.as_mut().unwrap();
            if let (Some(ref state_dir), Some(ref socket_path)) =
                (&runner.tpm_state_dir, &runner.tpm_socket_path)
            {
                // Clean up any leftover socket from previous run
                if socket_path.exists() {
                    let _ = std::fs::remove_file(socket_path);
                }

                let mut tpm_cmd = std::process::Command::new("swtpm");
                tpm_cmd
                    .arg("socket")
                    .arg("--tpmstate")
                    .arg(format!("dir={}", state_dir.display()))
                    .arg("--ctrl")
                    .arg(format!("type=unixio,path={}", socket_path.display()))
                    .arg("--tpm2")
                    .arg("--daemon");

                runner.tpm_process = Some(tpm_cmd.spawn().map_err(|_| ())?);

                std::thread::sleep(std::time::Duration::from_millis(500));

                let mut retries = 0;
                while !socket_path.exists() && retries < 10 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    retries += 1;
                }

                if !socket_path.exists() {
                    return Err(());
                }
            }
        }

        let mut cmd = self.build_qemu_cmd(offline);
        let fancy_cmd = format!("{:?}", cmd).replace("\"", "");
        println!("{}", (&fancy_cmd as &str).dimmed());
        self.runner.as_mut().unwrap().qemu_process = Some(cmd.spawn().map_err(|_| ())?);
        return Ok(());
    }

    fn stop_vm(&mut self) {
        let runner = self.runner.as_mut().unwrap();
        if let Some(ref mut process) = runner.qemu_process {
            let _ = process.kill();
            let _ = process.wait();
        }
        runner.qemu_process = None;

        // Stop swtpm daemon if it's running
        if let Some(ref mut process) = runner.tpm_process {
            let _ = process.kill();
            let _ = process.wait();
        }
        runner.tpm_process = None;

        if let Some(ref socket_path) = runner.tpm_socket_path {
            if socket_path.exists() {
                let _ = std::fs::remove_file(socket_path);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    fn ssh_target(&self) -> ssh::SshTarget {
        return SshTarget {
            ip: "127.0.0.1".to_string(),
            port: self.runner.as_ref().unwrap().host_port.1,
            cred: self.base_image.ssh.clone(),
        };
    }

    fn os(&self) -> GuestOs {
        return self.base_image.os;
    }
}

impl Drop for QemuBackend {
    fn drop(&mut self) {
        if let Some(mut runner) = self.runner.take() {
            if let Some(ref mut process) = runner.qemu_process {
                let _ = process.kill();
                let _ = process.wait();
            }
            if let Some(ref mut process) = runner.tpm_process {
                let _ = process.kill();
                let _ = process.wait();
            }
            if let Some(ref socket_path) = runner.tpm_socket_path {
                let _ = std::fs::remove_file(socket_path);
            }

            let mut paths_to_delete: Vec<PathBuf> = Vec::new();
            paths_to_delete.reserve_exact(5);
            paths_to_delete.push(runner.host_port.0.get_path().clone());
            paths_to_delete.push(runner.temp_image.get_path().clone());
            if let Some(ref vars) = runner.temp_uefi_vars {
                paths_to_delete.push(vars.get_path().clone());
            }
            for (_, ref flock) in &runner.temp_additional_drives {
                paths_to_delete.push(flock.get_path().clone());
            }
            if let Some(ref flock) = runner.tpm_flock {
                paths_to_delete.push(flock.get_path().clone());
            }
            let tpm_state_dir = runner.tpm_state_dir.clone();

            // release flocks
            drop(runner);

            for path in &paths_to_delete {
                let _ = std::fs::remove_file(path);
            }
            if let Some(ref dir) = tpm_state_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }
}

fn qemu_system_binary(arch: Arch) -> String {
    if let Ok(custom) = std::env::var("VCI_QEMU_BINARY") {
        return custom;
    }

    let base = match arch {
        Arch::X64 => "qemu-system-x86_64",
        Arch::ARM64 => "qemu-system-aarch64",
        Arch::RISCV64 => "qemu-system-riscv64",
    };

    #[cfg(target_os = "windows")]
    return format!("{}.exe", base);

    #[cfg(not(target_os = "windows"))]
    return base.to_string();
}

fn qemu_img_binary() -> String {
    if let Ok(custom) = std::env::var("VCI_QEMU_IMG_BINARY") {
        return custom;
    }

    #[cfg(target_os = "windows")]
    return "qemu-img.exe".to_string();

    #[cfg(not(target_os = "windows"))]
    return "qemu-img".to_string();
}

fn qemu_machine(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "q35",
        Arch::ARM64 => "virt",
        Arch::RISCV64 => "virt",
    }
}

pub fn qemu_cpu(arch: Arch) -> &'static str {
    match arch {
        Arch::X64 => "max",
        Arch::ARM64 => "host",
        Arch::RISCV64 => "max",
    }
}

#[cfg(target_os = "linux")]
pub fn is_kvm_available() -> bool {
    return std::path::Path::new("/dev/kvm").exists();
}

#[cfg(target_os = "linux")]
pub fn check_kvm_access() -> Result<(), String> {
    let kvm_path = std::path::Path::new("/dev/kvm");

    if !kvm_path.exists() {
        return Err("KVM module not loaded (modprobe kvm_intel or kvm_amd)".to_string());
    }

    match std::fs::File::open(kvm_path) {
        Ok(_) => return Ok(()),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(
                    "Permission denied for /dev/kvm (add user to kvm group and re-login)"
                        .to_string(),
                );
            };
            return Err(format!("Cannot access /dev/kvm: {}", e));
        }
    }
}

fn get_port_flock() -> Result<(FileLock, u16), ()> {
    const PORT_RANGE_START: u16 = 50000;
    const PORT_RANGE_END: u16 = 60000;

    for port in PORT_RANGE_START..=PORT_RANGE_END {
        let lock_path = VCI_TEMP_PATH.join(format!("vci-qemu-port-{}.lock", port));
        let res = FileLock::try_new(lock_path);
        match res {
            Ok(lock) => {
                return Ok((lock, port));
            }
            _ => (),
        }
    }
    return Err(());
}

fn create_backing_file(
    source_path: &std::path::Path,
    dest_path: &std::path::Path,
) -> Result<FileLock, ()> {
    let qemu_img = qemu_img_binary();

    let flock = FileLock::try_new(dest_path).map_err(|_| ())?;

    let output = std::process::Command::new(&qemu_img)
        .args([
            "create",
            "-f",
            "qcow2",
            "-b",
            &source_path.display().to_string(),
            "-F",
            "qcow2",
            &dest_path.display().to_string(),
        ])
        .output()
        .map_err(|_| ())?;

    if !output.status.success() {
        return Err(());
    }

    return Ok(flock);
}
