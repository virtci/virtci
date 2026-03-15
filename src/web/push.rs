// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

/*
Unencrypted:
qemu-img convert -O qcow2 -o cluster_size=2M source.qcow2 to_upload.qcow2

Encrypted:
qemu-img convert -O qcow2 \
-o cluster_size=2M,encrypt.format=luks,encrypt.key-secret=sec0
--object secret,id=sec0,file=/path/to/secret
source.qcow2 to_upload.qcow2

Commands above create the prepared qcow2 to upload to s3 storage.
-   `convert` should remove backing chains / snapshots
-   `cluster_size=2M` is the maximum cluster size, which should reduce HTTP round trips, according to
    https://events.static.linuxfound.org/sites/events/files/slides/kvm-forum-2017-slides.pdf slide 10x
-   `encrypt.format=luks,encrypt.key-secret=sec0` sets the luks encryption secret to the object name sec0
-   `--object secret,id=sec0,file=/path/to/secret sets the encryption secret value to be whatever
    is within the secret file.

For tart just upload the .tar file, until the custom apple virtualization framework stuff is done.
The .tar can be encrypted using the age crate perhaps.
*/

use std::{io::Write, path::PathBuf};

use anyhow::Context;

use crate::{
    backend::{expand_path, qemu::qemu_img_binary},
    cli::PushArgs,
    vm_image::{BackendConfig, ImageDescription, QemuConfig, UefiSplit},
    VciGlobalPaths,
};

pub fn run_push(args: &PushArgs, paths: &VciGlobalPaths) -> anyhow::Result<()> {
    let image_desc =
        ImageDescription::load_from_disk(&args.name, &paths.home).with_context(|| {
            format!(
                "Failed to load image description '{}' from disk to push to storage server",
                args.name
            )
        })?;

    paths.create_temp_dir()?;

    // connect to backend server, probably at like vm.virtci.com
    // perform auth here, connecting to the server
    //  1. get if auth is required from /api/auth/info
    //  2. if auth is required, and user does not have local auth access, prompt login TODO virtci login
    //  3. use auth token for all subsequent operations
    //  4. server will send session id that will ALSO be used for all operations

    match &image_desc.backend {
        BackendConfig::Qemu(old_qemu_config) => {
            // should not need to be file-locked I think
            let _new_qemu_config = create_qemu_upload_files(
                &image_desc.name,
                old_qemu_config,
                args.encrypt.as_ref(),
                paths,
            )?;
        }
        BackendConfig::Tart(_tart_config) => {}
    }

    // while doing the S3 upload, send a heartbeat to the server every 30 seconds or so, indicating
    // "hi im still uploading"
    // the server will check periodically to see if no heartbeat has come through without a session
    // being completed, if so, will cleanup any orphaned files, including AbortMultipartUpload for
    // S3.
    // The s3 itself will ALSO have auto-expire every 24h or so? Not sure yet.
    // during heartbeat, server can send necessary presigned s3 access urls / creds for multipart
    // upload.

    Ok(())
}

/// Generates the qcow2 file(s) necessary. Includes extra qcow2 files for like opencore and stuff,
/// as well as the potential UEFI files.
fn create_qemu_upload_files(
    img_name: &str,
    qemu_config: &QemuConfig,
    encrypt: Option<&String>,
    paths: &VciGlobalPaths,
) -> anyhow::Result<QemuConfig> {
    // TODO what happens if there are duplicate qcow2 file names for the additional drives / base image?
    let qemu_img_bin = qemu_img_binary();

    let new_base_qcow2 = match encrypt {
        Some(secret) => create_encrypted_qcow2_upload_file(
            &qemu_img_bin,
            secret,
            &qemu_config.image,
            img_name,
            &paths.temp,
        ),
        None => create_unencrypted_qcow2_upload_file(
            &qemu_img_bin,
            &qemu_config.image,
            img_name,
            &paths.temp,
        ),
    }?;

    let additional_drives: Option<Vec<String>> = match &qemu_config.additional_drives {
        None => None,
        Some(additional) => {
            let mut created_drives = Vec::<String>::new();
            for drive in additional {
                if let Some(file_start) = drive.find("file=") {
                    let after_file = &drive[file_start + 5..];
                    let file_path = if let Some(comma_pos) = after_file.find(',') {
                        &after_file[..comma_pos]
                    } else {
                        after_file
                    };

                    let source_path = expand_path(file_path);
                    let extra_drive_name = source_path
                        .file_name()
                        .expect("Expected file name for drive")
                        .display()
                        .to_string();
                    let new_drive_qcow2 = match encrypt {
                        Some(secret) => create_encrypted_qcow2_upload_file(
                            &qemu_img_bin,
                            secret,
                            &source_path.display().to_string(),
                            &extra_drive_name,
                            &paths.temp,
                        ),
                        None => create_unencrypted_qcow2_upload_file(
                            &qemu_img_bin,
                            &source_path.display().to_string(),
                            &extra_drive_name,
                            &paths.temp,
                        ),
                    }?;

                    let updated_spec = drive.replace(
                        &format!("file={file_path}"),
                        &format!("file={}", new_drive_qcow2.display()),
                    );

                    created_drives.push(updated_spec);
                } else {
                    eprintln!("[VirtCI Warning]: Skipping additional QEMU drive spec '{drive}'");
                }
            }
            Some(created_drives)
        }
    };

    // Code is readonly, but vars must be explicitly cloned.
    let uefi: Option<UefiSplit> = match &qemu_config.uefi {
        None => None,
        Some(split) => {
            let temp_vars_path = paths.temp.join(format!("vci-push-{img_name}-VARS.fd"));
            let contents = std::fs::read(expand_path(&split.vars))
                .with_context(|| format!("Failed to read UEFI vars file '{}'", split.vars))?;
            std::fs::write(&temp_vars_path, &contents)
                .with_context(|| format!("Failed to clone UEFI vars file '{}'", split.vars))?;
            Some(UefiSplit {
                code: split.code.clone(),
                vars: temp_vars_path.display().to_string(),
            })
        }
    };

    let new_config = QemuConfig {
        image: new_base_qcow2.display().to_string(),
        uefi,
        cpu_model: qemu_config.cpu_model.clone(),
        additional_drives,
        additional_devices: qemu_config.additional_devices.clone(),
        tpm: qemu_config.tpm,
        nvme: qemu_config.nvme,
        readonly_isos: qemu_config.readonly_isos.clone(),
    };

    return Ok(new_config);
}

fn create_unencrypted_qcow2_upload_file(
    qemu_img_bin: &str,
    img_path: &str,
    img_name: &str,
    temp_dir: &std::path::Path,
) -> anyhow::Result<PathBuf> {
    let unencrypted_qcow2 = temp_dir.join(format!("{img_name}.qcow2"));
    let output = std::process::Command::new(qemu_img_bin)
        .args([
            "convert",
            "-O",
            "qcow2",
            "-o",
            "cluster_size=2M",
            img_path,
            &unencrypted_qcow2.display().to_string(),
        ])
        .output()
        .with_context(|| format!("Failed to create unencrypted qcow2 for '{img_name}'"))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "qemu-img create unencrypted upload qcow2 command failed with exit code: {}\nstderr: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(unencrypted_qcow2)
}

fn create_encrypted_qcow2_upload_file(
    qemu_img_bin: &str,
    secret: &str,
    img_path: &str,
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
            "Failed to create temporary file to hold qemu encryption secret".to_string()
        })?
    };

    file.write_all(secret.as_bytes()).with_context(|| {
        std::fs::remove_file(&qemu_secret_file_path).expect("Expected to remove secret file");
        "Failed to write qemu encryption secret to file".to_string()
    })?;

    let encrypted_qcow2 = temp_dir.join(format!("{img_name}.qcow2"));
    let output = std::process::Command::new(qemu_img_bin)
        .args([
            "convert",
            "-O",
            "qcow2",
            "-o",
            "cluster_size=2M,encrypt.format=luks,encrypt.key-secret=sec0",
            "--object",
            &format!("secret,id=sec0,file={}", qemu_secret_file_path.display()),
            img_path,
            &encrypted_qcow2.display().to_string(),
        ])
        .output()
        .with_context(|| {
            std::fs::remove_file(&qemu_secret_file_path).expect("Expected to remove secret file");
            format!("Failed to create encrypted qcow2 for '{img_name}'")
        })?;

    if !output.status.success() {
        std::fs::remove_file(&qemu_secret_file_path).expect("Expected to remove secret file");
        return Err(anyhow::anyhow!(
            "qemu-img create encrypted upload qcow2 command failed with exit code: {}\nstderr: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    std::fs::remove_file(&qemu_secret_file_path).with_context(|| {
        "Failed to remove temporary file holding qemu encryption secret".to_string()
    })?;

    Ok(encrypted_qcow2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::pull::decrypt_qcow2_file;

    const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

    /// Checks that a converted qcow2 file has the right format and cluster size,
    /// and that the logical disk contents are identical.
    fn assert_qcow2_conversion(qemu_img_bin: &str, source: &str, converted: &std::path::Path) {
        let info_output = std::process::Command::new(qemu_img_bin)
            .args(["info", "--output=json", &converted.display().to_string()])
            .output()
            .expect("Failed to run qemu-img info");
        assert!(
            info_output.status.success(),
            "qemu-img info failed: {}",
            String::from_utf8_lossy(&info_output.stderr)
        );

        let info: serde_json::Value = serde_json::from_slice(&info_output.stdout)
            .expect("Failed to parse qemu-img info JSON");
        assert_eq!(
            info["format"].as_str().unwrap(),
            "qcow2",
            "Expected qcow2 format"
        );
        assert_eq!(
            info["cluster-size"].as_u64().unwrap(),
            2 * 1024 * 1024,
            "Expected 2M cluster size"
        );

        let cmp_output = std::process::Command::new(qemu_img_bin)
            .args([
                "compare",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                source,
                &converted.display().to_string(),
            ])
            .output()
            .expect("Failed to run qemu-img compare");
        assert!(
            cmp_output.status.success(),
            "qemu-img compare found content differences: {}",
            String::from_utf8_lossy(&cmp_output.stdout)
        );
    }

    #[test]
    #[ignore = "Integration Test"]
    fn test_create_unencrypted_qcow2_upload_file() {
        const VM_QCOW2_NAME: &str = "TEST_create_unencrypted_qcow2_upload_file";
        let temp = PathBuf::from(format!("{MANIFEST_DIR}/tests/temp/{VM_QCOW2_NAME}/temp"));
        std::fs::create_dir_all(&temp).expect("Failed to create temp dir");

        let qemu_img_bin = qemu_img_binary();

        {
            // x64
            let source =
                format!("{MANIFEST_DIR}/tests/upstream_image/debian-12-genericcloud-amd64.qcow2");

            let converted = create_unencrypted_qcow2_upload_file(
                &qemu_img_bin,
                &source,
                &format!("{VM_QCOW2_NAME}_x64"),
                &temp,
            )
            .expect("create_unencrypted_qcow2_upload_file failed");
            assert_qcow2_conversion(&qemu_img_bin, &source, &converted);
        }

        {
            // arm64
            let source =
                format!("{MANIFEST_DIR}/tests/upstream_image/debian-12-genericcloud-arm64.qcow2");

            let converted = create_unencrypted_qcow2_upload_file(
                &qemu_img_bin,
                &source,
                &format!("{VM_QCOW2_NAME}_arm64"),
                &temp,
            )
            .expect("create_unencrypted_qcow2_upload_file failed");
            assert_qcow2_conversion(&qemu_img_bin, &source, &converted);
        }
    }

    fn assert_encrypted_qcow2_info(qemu_img_bin: &str, encrypted: &std::path::Path) {
        let info_output = std::process::Command::new(qemu_img_bin)
            .args(["info", "--output=json", &encrypted.display().to_string()])
            .output()
            .expect("Failed to run qemu-img info");
        assert!(
            info_output.status.success(),
            "qemu-img info failed: {}",
            String::from_utf8_lossy(&info_output.stderr)
        );

        let info: serde_json::Value = serde_json::from_slice(&info_output.stdout)
            .expect("Failed to parse qemu-img info JSON");
        assert_eq!(
            info["format"].as_str().unwrap(),
            "qcow2",
            "Expected qcow2 format"
        );
        assert_eq!(
            info["cluster-size"].as_u64().unwrap(),
            2 * 1024 * 1024,
            "Expected 2M cluster size"
        );
        assert_eq!(
            info["format-specific"]["data"]["encrypt"]["format"]
                .as_str()
                .unwrap(),
            "luks",
            "Expected LUKS encryption"
        );
    }

    #[test]
    #[ignore = "Integration Test"]
    fn test_create_encrypted_qcow2_upload_file() {
        const VM_QCOW2_NAME: &str = "TEST_create_encrypted_qcow2_upload_file";
        const SECRET: &str = "password";
        let temp = PathBuf::from(format!("{MANIFEST_DIR}/tests/temp/{VM_QCOW2_NAME}/temp"));
        std::fs::create_dir_all(&temp).expect("Failed to create temp dir");

        let qemu_img_bin = qemu_img_binary();

        {
            // x64
            let source =
                format!("{MANIFEST_DIR}/tests/upstream_image/debian-12-genericcloud-amd64.qcow2");

            let encrypted = create_encrypted_qcow2_upload_file(
                &qemu_img_bin,
                SECRET,
                &source,
                &format!("{VM_QCOW2_NAME}_x64"),
                &temp,
            )
            .expect("create_encrypted_qcow2_upload_file failed");
            assert_encrypted_qcow2_info(&qemu_img_bin, &encrypted);

            let decrypted = decrypt_qcow2_file(
                &qemu_img_bin,
                SECRET,
                &encrypted.display().to_string(),
                &format!("{VM_QCOW2_NAME}_x64_decrypted"),
                &temp,
            )
            .expect("decrypt_qcow2_file failed");
            assert_qcow2_conversion(&qemu_img_bin, &source, &decrypted);
        }

        {
            // arm64
            let source =
                format!("{MANIFEST_DIR}/tests/upstream_image/debian-12-genericcloud-arm64.qcow2");

            let encrypted = create_encrypted_qcow2_upload_file(
                &qemu_img_bin,
                SECRET,
                &source,
                &format!("{VM_QCOW2_NAME}_arm64"),
                &temp,
            )
            .expect("create_encrypted_qcow2_upload_file failed");
            assert_encrypted_qcow2_info(&qemu_img_bin, &encrypted);

            let decrypted = decrypt_qcow2_file(
                &qemu_img_bin,
                SECRET,
                &encrypted.display().to_string(),
                &format!("{VM_QCOW2_NAME}_arm64_decrypted"),
                &temp,
            )
            .expect("decrypt_qcow2_file failed");
            assert_qcow2_conversion(&qemu_img_bin, &source, &decrypted);
        }
    }
}
