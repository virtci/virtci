// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use virtci::{global_paths::VciGlobalPaths, run_virtci_with_args, vm_image::list::load_all_images};

pub const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

pub fn upstream_img_path(file_name: &str) -> PathBuf {
    PathBuf::from(MANIFEST_DIR)
        .join(".ci/upstream")
        .join(file_name)
}

fn system_tests_global_paths_no_wsl(
    home: PathBuf,
    system: PathBuf,
    temp: PathBuf,
) -> VciGlobalPaths {
    VciGlobalPaths {
        user_home: home,
        system_home: system,
        temp,
        #[cfg(target_os = "windows")]
        wsl: None,
    }
}

pub fn image_is_registered(paths: &VciGlobalPaths, image_name: &str) -> bool {
    load_all_images(paths)
        .iter()
        .any(|img| img.name == image_name)
}

pub struct TestEnv {
    pub test_dir: PathBuf,
    pub paths: VciGlobalPaths,
}

pub fn test_env(test_name: &str) -> TestEnv {
    let test_dir = PathBuf::from(MANIFEST_DIR).join(".ci/temp").join(test_name);
    let paths = system_tests_global_paths_no_wsl(
        test_dir.join("home"),
        test_dir.join("system"),
        test_dir.join("temp"),
    );
    std::fs::create_dir_all(&test_dir).expect("Failed to create test temp directory");
    TestEnv { test_dir, paths }
}

/// Registers upstream ubuntu cloud images relative to repo root.
pub fn register_image(env: &TestEnv, image_name: &str, image_json: &str, image_file: &str) {
    let img = upstream_img_path(image_file);
    assert!(
        img.exists(),
        "Missing upstream image {}. Fetch it first with .ci/upstream/fetch_ubuntu_images.sh (or .ps1).",
        img.display()
    );

    if image_is_registered(&env.paths, image_name) {
        run_virtci_with_args(&env.paths, &["remove", image_name, "--force"]);
    }

    run_virtci_with_args(
        &env.paths,
        &[
            "setup", "--qemu", "--from", image_json, "--name", image_name,
        ],
    );
    assert!(image_is_registered(&env.paths, image_name));
}

pub fn register_image_from_json(env: &TestEnv, image_name: &str, image_json: &Path) {
    if image_is_registered(&env.paths, image_name) {
        run_virtci_with_args(&env.paths, &["remove", image_name, "--force"]);
    }
    run_virtci_with_args(
        &env.paths,
        &[
            "setup",
            "--qemu",
            "--from",
            image_json.to_str().expect("Non-UTF8 config path"),
            "--name",
            image_name,
        ],
    );
    assert!(image_is_registered(&env.paths, image_name));
}

/// Writes `workflow_yaml` to a temporary YAML file and runs it.
pub fn run_workflow(env: &TestEnv, workflow_yaml: &str) {
    let workflow_path = env.test_dir.join("workflow.yml");
    std::fs::write(&workflow_path, workflow_yaml).expect("Failed to write workflow file");

    run_virtci_with_args(
        &env.paths,
        &["run", workflow_path.to_str().expect("Non-UTF8 test path")],
    );
}

pub fn remove_image(env: &TestEnv, image_name: &str) {
    run_virtci_with_args(&env.paths, &["remove", image_name, "--force"]);
    assert!(!image_is_registered(&env.paths, image_name));
}

pub struct NativeImage {
    pub name: &'static str,
    pub json: &'static str,
    pub img_file: &'static str,
    pub arch_json: &'static str,
}

pub fn native_image() -> NativeImage {
    match virtci::util::cpu_arch::Arch::host() {
        virtci::util::cpu_arch::Arch::X64 => NativeImage {
            name: "cache-test-x64",
            json: ".ci/upstream/ubuntu_server_x64.json",
            img_file: "resolute-server-cloudimg-amd64.img",
            arch_json: "X64",
        },
        virtci::util::cpu_arch::Arch::ARM64 => NativeImage {
            name: "cache-test-arm64",
            json: ".ci/upstream/ubuntu_server_arm64.json",
            img_file: "resolute-server-cloudimg-arm64.img",
            arch_json: "ARM64",
        },
        other => panic!("no upstream Ubuntu image bundled for host arch {other:?}"),
    }
}

/// Cache namespace pinned for the tests, for determinism.
pub const CACHE_NAMESPACE: &str = "vci-cache-test";

/// What a single workflow run leaves behind, as observed purely from the host: whether a committed
/// cache slot exists, the identity of its boot disk, and the guest-baked build stamp copied back.
pub struct Observation {
    pub slot_present: bool,
    /// `(len, mtime_secs)`
    pub disk_meta: Option<(u64, u64)>,
    pub stamp: Option<String>,
}

/// Runs `workflow_path` with caching at [`CACHE_NAMESPACE`] and returns the host-observable
/// [`Observation`]. `extra_args` is appended after the workflow path (such as `--no-cache`).
pub fn run_and_observe(env: &TestEnv, workflow_path: &Path, extra_args: &[&str]) -> Observation {
    let path = workflow_path.to_str().expect("Non-UTF8 workflow path");
    let mut args: Vec<&str> = vec!["run", path, "--cache-namespace", CACHE_NAMESPACE];
    args.extend_from_slice(extra_args);
    run_virtci_with_args(&env.paths, &args);

    let slot = find_cache_slot(env);
    Observation {
        slot_present: slot.is_some(),
        disk_meta: slot.as_deref().and_then(disk_meta),
        stamp: read_stamp(env, "vci_stamp"),
    }
}

pub fn find_cache_slot(env: &TestEnv) -> Option<PathBuf> {
    fn walk(dir: &Path) -> Option<PathBuf> {
        if dir.join("cache.json").is_file() {
            return Some(dir.to_path_buf());
        }
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let p = entry.path();
            if p.is_dir()
                && let Some(found) = walk(&p)
            {
                return Some(found);
            }
        }
        None
    }
    walk(&env.paths.cache_dir().path)
}

fn disk_meta(slot: &Path) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(slot.join("disk.qcow2")).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((meta.len(), mtime))
}

pub fn stamp_out_dir(env: &TestEnv) -> PathBuf {
    env.test_dir.join("cache_out")
}

pub fn read_stamp(env: &TestEnv, name: &str) -> Option<String> {
    std::fs::read_to_string(stamp_out_dir(env).join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn stamp_workflow(image: &str, out_dir: &str, cache_block: &str) -> String {
    format!(
        r#"cache_job:
  image: {image}
  cpus: 2
  memory: 4G
{cache_block}  steps:
    - name: Bake build stamp
      run: test -f ~/vci_stamp || date +%s%N > ~/vci_stamp
    - name: Export stamp
      copy:
        from: vm:~/vci_stamp
        to: {out_dir}/
"#
    )
}

pub fn write_workflow(env: &TestEnv, workflow_yaml: &str) -> PathBuf {
    let out = stamp_out_dir(env);
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).expect("Failed to create stamp output dir");

    let workflow_path = env.test_dir.join("workflow.yml");
    std::fs::write(&workflow_path, workflow_yaml).expect("Failed to write workflow file");
    workflow_path
}
