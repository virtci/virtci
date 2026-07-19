// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;

use anyhow::Context;

const RECOVERY_PARTITION_NAME: &str = "RecoveryOSContainer";

/// Delete macOS Recovery partition from a raw disk image so the main APFS container can later be
/// grown inside the VM to fill the  space. The VM must be shut down and the image not attached.
/// Returns `true` if a recovery partition was removed, `false` if there was none
/// (already deleted, or an image that never had one). Refuses to proceed if the
/// recovery partition is not the last one on the disk, since removing a
/// non-trailing partition would strand the freed space between other partitions supposedly.
pub fn delete_trailing_recovery(disk_img: &Path) -> anyhow::Result<bool> {
    let mut disk = gpt::GptConfig::new()
        .writable(true)
        .open(disk_img)
        .with_context(|| format!("Failed to open GPT of {}", disk_img.display()))?;

    let recovery: Vec<(u32, u64)> = disk
        .partitions()
        .iter()
        .filter(|(_, p)| p.name == RECOVERY_PARTITION_NAME)
        .map(|(id, p)| (*id, p.first_lba))
        .collect();

    let (rec_id, rec_first_lba) = match recovery.as_slice() {
        [] => return Ok(false),
        [only] => *only,
        _ => anyhow::bail!(
            "found {} partitions named '{RECOVERY_PARTITION_NAME}' so refusing to edit the GPT",
            recovery.len()
        ),
    };

    // It must be the last partition on disk
    let max_first_lba = disk
        .partitions()
        .values()
        .filter(|p| p.is_used())
        .map(|p| p.first_lba)
        .max()
        .unwrap_or(0);
    anyhow::ensure!(
        rec_first_lba == max_first_lba,
        "the recovery partition is not the last partition on disk so refusing to edit the GPT"
    );

    disk.remove_partition(rec_id)
        .context("failed to remove the recovery partition entry")?;

    disk.write()
        .context("failed to write the updated GPT back to the disk image")?;

    Ok(true)
}
