use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::vm_image::{BackendConfig, ImageDescription, QemuConfig, TartConfig, VCI_HOME_PATH};

struct ProgressReader<R> {
    inner: R,
    total: u64,
    read_so_far: u64,
    last_percent: f32,
    label: String,
}

impl<R: Read> ProgressReader<R> {
    fn new(inner: R, total: u64, label: String) -> Self {
        Self {
            inner,
            total,
            read_so_far: 0,
            last_percent: 0.0,
            label,
        }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read_so_far += n as u64;

        let percent = if self.total > 0 {
            // scale up by 10
            ((self.read_so_far as f32 / self.total as f32) * 100.0) as f32
        } else {
            100.0
        };

        if percent != self.last_percent {
            self.last_percent = percent;
            print!(
                "\r  {} ... {:.1}% ({}/{})\x1b[K",
                self.label,
                percent,
                format_size(self.read_so_far),
                format_size(self.total),
            );
            std::io::stdout().flush().ok();

            if self.read_so_far >= self.total {
                println!();
            }
        }

        return Ok(n);
    }
}

fn format_size(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;

    if bytes >= GB {
        return format!("{:.1} GB", bytes as f64 / GB as f64);
    } else {
        return format!("{:.1} MB", bytes as f64 / MB as f64);
    }
}

pub fn run_export(name: &str, output: Option<PathBuf>) -> Result<(), String> {
    let desc = load_image(name)?;
    let output_path = output.unwrap_or_else(|| PathBuf::from(format!("{}.tar", name)));

    println!("Exporting '{}' to {}", name, output_path.display());

    let file = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create {}: {}", output_path.display(), e))?;
    let mut archive = tar::Builder::new(file);

    let mut exported_desc = desc.clone();
    exported_desc.managed = Some(true);

    match &desc.backend {
        BackendConfig::Qemu(qemu) => {
            export_qemu(name, qemu, &mut archive, &mut exported_desc)?;
        }
        BackendConfig::Tart(tart) => {
            export_tart(name, tart, &mut archive, &mut exported_desc)?;
        }
    }

    let vci_json = serde_json::to_string_pretty(&exported_desc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    let vci_bytes = vci_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(vci_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, format!("{}.vci", name), vci_bytes)
        .map_err(|e| format!("Failed to write .vci to archive: {}", e))?;

    archive
        .finish()
        .map_err(|e| format!("Failed to finalize archive: {}", e))?;

    println!("Export complete: {}", output_path.display());
    return Ok(());
}

fn load_image(name: &str) -> Result<ImageDescription, String> {
    let vci_path = VCI_HOME_PATH.join(format!("{}.vci", name));
    let contents = std::fs::read_to_string(&vci_path).map_err(|_| {
        format!(
            "Failed to load image description '{}' (looked at {})",
            name,
            vci_path.display()
        )
    })?;
    let mut desc: ImageDescription = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse image description '{}': {}", name, e))?;
    desc.name = name.to_string();
    return Ok(desc);
}

fn append_file<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    src_path: &Path,
    archive_name: &str,
) -> Result<(), String> {
    let file = std::fs::File::open(src_path)
        .map_err(|e| format!("Failed to open {}: {}", src_path.display(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read metadata for {}: {}", src_path.display(), e))?;
    let size = metadata.len();

    let label = filename_of(&src_path.to_string_lossy());
    let mut reader = ProgressReader::new(file, size, label);

    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();

    archive
        .append_data(&mut header, archive_name, &mut reader)
        .map_err(|e| format!("Failed to add {} to archive: {}", src_path.display(), e))?;

    return Ok(());
}

fn filename_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

fn parse_drive_file_path(drive_str: &str) -> Option<String> {
    for part in drive_str.split(',') {
        if let Some(path) = part.strip_prefix("file=") {
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
    }
    return None;
}

fn rewrite_drive_file_path(drive_str: &str, new_filename: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for part in drive_str.split(',') {
        if part.starts_with("file=") {
            parts.push(format!("file={}", new_filename));
        } else {
            parts.push(part.to_string());
        }
    }
    return parts.join(",");
}

fn export_qemu<W: std::io::Write>(
    name: &str,
    qemu: &QemuConfig,
    archive: &mut tar::Builder<W>,
    exported_desc: &mut ImageDescription,
) -> Result<(), String> {
    let image_path = Path::new(&qemu.image);
    let image_filename = filename_of(&qemu.image);
    append_file(archive, image_path, &format!("{}/{}", name, image_filename))?;

    let mut exported_uefi = qemu.uefi.clone();
    if let Some(ref uefi) = qemu.uefi {
        let code_filename = filename_of(&uefi.code);
        append_file(
            archive,
            Path::new(&uefi.code),
            &format!("{}/{}", name, code_filename),
        )?;

        let vars_filename = filename_of(&uefi.vars);
        append_file(
            archive,
            Path::new(&uefi.vars),
            &format!("{}/{}", name, vars_filename),
        )?;

        exported_uefi = Some(crate::vm_image::UefiSplit {
            code: code_filename,
            vars: vars_filename,
        });
    }

    let mut exported_drives = qemu.additional_drives.clone();
    if let Some(ref drives) = qemu.additional_drives {
        let mut rewritten = Vec::new();
        for drive_str in drives {
            if let Some(file_path) = parse_drive_file_path(drive_str) {
                let file_filename = filename_of(&file_path);
                append_file(
                    archive,
                    Path::new(&file_path),
                    &format!("{}/{}", name, file_filename),
                )?;
                rewritten.push(rewrite_drive_file_path(drive_str, &file_filename));
            } else {
                rewritten.push(drive_str.clone());
            }
        }
        exported_drives = Some(rewritten);
    }

    exported_desc.backend = BackendConfig::Qemu(QemuConfig {
        image: image_filename,
        uefi: exported_uefi,
        cpu_model: qemu.cpu_model.clone(),
        additional_drives: exported_drives,
        additional_devices: qemu.additional_devices.clone(),
        tpm: qemu.tpm,
        nvme: qemu.nvme,
    });

    return Ok(());
}

fn export_tart<W: std::io::Write>(
    name: &str,
    tart: &TartConfig,
    archive: &mut tar::Builder<W>,
    exported_desc: &mut ImageDescription,
) -> Result<(), String> {
    let tvm_filename = format!("{}.tvm", tart.vm_name);
    let temp_dir = std::env::temp_dir();
    let tvm_temp_path = temp_dir.join(&tvm_filename);

    println!(
        "  Running: tart export {} {}",
        tart.vm_name,
        tvm_temp_path.display()
    );

    let output = std::process::Command::new("tart")
        .arg("export")
        .arg(&tart.vm_name)
        .arg(&tvm_temp_path)
        .output()
        .map_err(|e| format!("Failed to run tart export: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Clean up temp file on failure
        let _ = std::fs::remove_file(&tvm_temp_path);
        return Err(format!("tart export failed: {}", stderr.trim()));
    }

    append_file(
        archive,
        &tvm_temp_path,
        &format!("{}/{}", name, tvm_filename),
    )?;

    let _ = std::fs::remove_file(&tvm_temp_path);

    exported_desc.backend = BackendConfig::Tart(TartConfig {
        vm_name: tart.vm_name.clone(),
    });

    return Ok(());
}
