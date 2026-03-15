// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{io::Write, path::PathBuf};

use anyhow::Context;

/// Decrypts a LUKS-encrypted qcow2 file into an unencrypted qcow2 with 2M cluster size.
pub fn decrypt_qcow2_file(
    qemu_img_bin: &str,
    secret: &str,
    encrypted_path: &str,
    img_name: &str,
    temp_dir: &std::path::Path,
) -> anyhow::Result<PathBuf> {
    let qemu_secret_file_path = temp_dir.join(".vci_qemu_secret");
    let mut file = {
        let res = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&qemu_secret_file_path)
            }

            #[cfg(windows)]
            {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&qemu_secret_file_path)
            }
        };

        res.with_context(|| {
            "Failed to create temporary file to hold qemu decryption secret".to_string()
        })?
    };

    file.write_all(secret.as_bytes()).with_context(|| {
        std::fs::remove_file(&qemu_secret_file_path).expect("Expected to remove secret file");
        "Failed to write qemu decryption secret to file".to_string()
    })?;

    let decrypted_qcow2 = temp_dir.join(format!("{img_name}.qcow2"));
    let output = std::process::Command::new(qemu_img_bin)
        .args([
            "convert",
            "-O",
            "qcow2",
            "-o",
            "cluster_size=2M",
            "--object",
            &format!("secret,id=sec0,file={}", qemu_secret_file_path.display()),
            "--image-opts",
            &format!(
                "driver=qcow2,file.driver=file,file.filename={encrypted_path},encrypt.key-secret=sec0"
            ),
            &decrypted_qcow2.display().to_string(),
        ])
        .output()
        .with_context(|| {
            std::fs::remove_file(&qemu_secret_file_path).expect("Expected to remove secret file");
            format!("Failed to decrypt qcow2 for '{img_name}'")
        })?;

    if !output.status.success() {
        std::fs::remove_file(&qemu_secret_file_path).expect("Expected to remove secret file");
        return Err(anyhow::anyhow!(
            "qemu-img decrypt qcow2 command failed with exit code: {}\nstderr: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    std::fs::remove_file(&qemu_secret_file_path).with_context(|| {
        "Failed to remove temporary file holding qemu decryption secret".to_string()
    })?;

    Ok(decrypted_qcow2)
}
