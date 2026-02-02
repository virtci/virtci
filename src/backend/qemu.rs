use std::{path::PathBuf, process::Child};

use super::Arch;
use crate::{
    backend::VmBackend,
    file_lock::FileLock,
    job::{expand_path, expand_path_in_string},
    ssh,
};

pub struct QemuRunner {
    pub host_port: u16,
    pub temp_image: FileLock,
    pub temp_uefi_vars: Option<FileLock>,
    pub temp_additional_drives: Vec<(String, FileLock)>, // (original_spec, temp_path)
    qemu_process: Option<Child>,
    tpm_process: Option<Child>,
    tpm_state_dir: Option<PathBuf>,
    tpm_socket_path: Option<PathBuf>,
    guest_os: Option<ssh::GuestOs>,
}

pub struct QemuBackend {
    pub name: String,
    pub base_image: String,
    pub flock: FileLock,
    pub arch: Arch,
    pub cpus: u32,
    /// Megabytes
    pub memory: u64,
    pub user: String,
    pub pass: Option<String>,
    pub key: Option<String>,
    /// Port within the VM that SSH accesses.
    pub inside_vm_port: u16,
    pub uefi: Option<crate::yaml::UefiFirmware>,
    pub cpu_model: Option<String>,
    pub additional_drives: Option<Vec<String>>,
    pub additional_devices: Option<Vec<String>>,
    pub qemu_args: Option<Vec<String>>,
    pub tpm: Option<crate::yaml::TpmConfig>,
    pub nvme: bool,
    pub runner: Option<QemuRunner>,
}

impl QemuBackend {
    fn build_qemu_cmd(&self, offline: bool) -> std::process::Command {
        let mut cmd = std::process::Command::new(qemu_system_binary(self.arch));

        cmd.arg("-machine").arg(qemu_machine(self.arch));

        if let Some(ref cpu_model) = self.cpu_model {
            cmd.arg("-cpu").arg(cpu_model);
        } else {
            cmd.arg("-cpu").arg(qemu_cpu(self.arch));
        }

        cmd.arg("-name").arg(&self.name);
        cmd.arg("-m").arg(format!("{}M", self.memory));
        cmd.arg("-smp").arg(self.cpus.to_string());

        if let Some(ref uefi) = self.uefi {
            match uefi {
                crate::yaml::UefiFirmware::Boolean(_) | crate::yaml::UefiFirmware::Path(_) => {
                    // // Monolithic UEFI (use processed uefi_firmware path)
                    // if let Some(ref firmware_path) = self.job.uefi_firmware {
                    //     cmd.arg("-drive").arg(format!(
                    //         "if=pflash,format=raw,readonly=on,file={}",
                    //         firmware_path.display()
                    //     ));
                    // }
                }
                crate::yaml::UefiFirmware::Split(split) => {
                    // Split UEFI: code (readonly) + vars (writable)
                    let code_path = expand_path(&split.code);
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
            }
        }

        // Some VMs need additional drives like OpenCore bootloader for macOS
        for (drive_spec, _) in &self.runner.as_ref().unwrap().temp_additional_drives {
            cmd.arg("-drive").arg(drive_spec);
        }

        // main disk
        // if=none only when additional_devices will attach it
        // windows arm64 requires nvme? At least when made with UTM? Idk
        if self.additional_devices.is_some() {
            cmd.arg("-drive").arg(format!(
                "id=SystemDisk,if=none,file={},format=qcow2",
                self.runner.as_ref().unwrap().temp_image.get_path().display()
            ));
        } else {
            match self.arch {
                Arch::ARM64 | Arch::RISCV64 => {
                    cmd.arg("-drive").arg(format!(
                        "id=SystemDisk,if=none,file={},format=qcow2",
                        self.runner.as_ref().unwrap().temp_image.get_path().display()
                    ));
                    if self.nvme {
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
                        self.runner.as_ref().unwrap().temp_image.get_path().display()
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
                self.runner.as_ref().unwrap().host_port,
                self.inside_vm_port
            )
        } else {
            format!(
                "user,id=net0,hostfwd=tcp::{}-:{}",
                self.runner.as_ref().unwrap().host_port,
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
            let tpm_device = match &self.tpm {
                Some(crate::yaml::TpmConfig::Device(device)) => format!("{},tpmdev=tpm0", device),
                _ => match self.arch {
                    Arch::ARM64 | Arch::RISCV64 => "tpm-tis-device,tpmdev=tpm0".to_string(),
                    Arch::X64 => "tpm-tis,tpmdev=tpm0".to_string(),
                },
            };
            cmd.arg("-device").arg(tpm_device);
        }

        if let Some(ref additional_devices) = self.additional_devices {
            for device in additional_devices {
                let expanded_device = expand_path_in_string(device);
                cmd.arg("-device").arg(expanded_device);
            }
        }

        // edge case raw args
        if let Some(ref qemu_args) = self.qemu_args {
            for arg in qemu_args {
                let expanded_arg = expand_path_in_string(arg);
                cmd.arg(expanded_arg);
            }
        }

        return cmd;
    }
}

impl VmBackend for QemuBackend {
    fn clone_image(&self) -> Result<(), ()> {
        todo!()
    }

    fn start_vm(&mut self, offline: bool) {
        todo!()
    }

    fn stop_vm(&mut self) {
        todo!()
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
