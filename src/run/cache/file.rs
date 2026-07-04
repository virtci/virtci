// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::global_paths::TargetPath;

use anyhow::Context;

use std::io::Read;

/// Buffer size to stream file.
const HASH_BUF_LEN: usize = 1 << 20;

/// Fine to go over WSL2 9p.
pub fn file_size_bytes(path: &TargetPath) -> anyhow::Result<u64> {
    let meta: std::fs::Metadata = std::fs::metadata(&path.path)
        .with_context(|| format!("failed to stat file {}", path.path.display()))?;
    Ok(meta.len())
}

/// Hash a sorted list of files matching `pattern`, resolved relative to `root_dir`. JUST the file
/// names (relative to `root_dir`), not their contents, so this tracks files being added or removed.
/// Only lists directory entries, which is fine over the WSL2 9p. Glob errors record a
/// sentinel.
pub fn hash_file_list(root_dir: &TargetPath, pattern: &str) -> String {
    // glob wants a `/`-separated pattern so normalize so Windows backslashes / a UNC root parse.
    let full = root_dir
        .path
        .join(pattern)
        .to_string_lossy()
        .replace('\\', "/");
    let Ok(paths) = glob::glob(&full) else {
        return "bad-glob".to_string();
    };
    let mut matches: Vec<String> = paths
        .filter_map(Result::ok)
        .map(|p| {
            p.strip_prefix(&root_dir.path)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    matches.sort();
    super::short_hash(matches.join("\n").as_bytes())
}

/// Stream a file through blake3 and return the full hex digest, using a bounded buffer.
///
/// For a WSL2 path the contents are read inside the distro (`wsl -d <distro> -- cat`, a native
/// sequential read piped out) rather than doing buffered I/O over the slow 9p/DrvFs bridge.
pub fn hash_file(path: &TargetPath) -> anyhow::Result<String> {
    #[cfg(target_os = "windows")]
    if let Some(distro) = &path.wsl_distro {
        return hash_file_in_wsl(distro, &path.native_path());
    }

    let mut file = std::fs::File::open(&path.path)
        .with_context(|| format!("failed to open {} for hashing", path.path.display()))?;
    hash_reader(&mut file)
}

/// Stream `reader` to EOF through blake3, returning the full hex digest.
fn hash_reader<R: Read>(reader: &mut R) -> anyhow::Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; HASH_BUF_LEN];
    loop {
        let n = reader
            .read(&mut buf)
            .context("failed to read while hashing")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Hash a file living inside a WSL2 distro by streaming `wsl -d <distro> -- cat <path>`. `cat`
/// reads it natively (fast, sequential) and we hash the piped bytes on the host side, keeping
/// blake3 as the algorithm without random 9p access.
#[cfg(target_os = "windows")]
fn hash_file_in_wsl(distro: &str, wsl_path: &str) -> anyhow::Result<String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("wsl")
        .args(["-d", distro, "--", "cat", wsl_path])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn `wsl cat {wsl_path}` for hashing"))?;

    let mut stdout = child.stdout.take().expect("stdout was piped");
    let hash = hash_reader(&mut stdout)?;

    let status = child
        .wait()
        .with_context(|| format!("failed to wait on `wsl cat {wsl_path}`"))?;
    anyhow::ensure!(
        status.success(),
        "`wsl cat {wsl_path}` failed while hashing"
    );
    Ok(hash)
}
