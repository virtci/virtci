// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! Running these tests locally.
//!
//! ```sh
//! ./.ci/upstream/fetch_ubuntu_images.sh
//! cargo test --test local_workflow_cache -- --ignored --test-threads=1 --no-capture
//! ```
//!
//! ```powershell
//! .\.ci\upstream\fetch_ubuntu_images.ps1
//! cargo test --test local_workflow_cache -- --ignored --test-threads=1 --no-capture
//! ```

use std::path::Path;
use std::time::{Duration, SystemTime};

mod common;
use common::{
    NativeImage, Observation, TestEnv, native_image, read_stamp, register_image,
    register_image_from_json, remove_image, run_and_observe, stamp_out_dir, stamp_workflow,
    test_env, write_workflow,
};

const RETAIN_ENV: &str = "VIRTCI_CACHE_RETAIN_GB";

fn set_env(key: &str, value: &str) {
    // these tests run single threaded, this is fine.
    unsafe { std::env::set_var(key, value) };
}

fn unset_env(key: &str) {
    // these tests run single threaded, this is fine.
    unsafe { std::env::remove_var(key) };
}

fn slashed(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn out_dir_str(env: &TestEnv) -> String {
    slashed(&stamp_out_dir(env))
}

fn assert_hit(produced: &Observation, now: &Observation) {
    assert!(now.slot_present, "a hit must leave the cache slot in place");
    assert!(
        now.stamp.is_some(),
        "the guest build stamp should have been copied back on every run"
    );
    assert_eq!(
        now.disk_meta, produced.disk_meta,
        "a cache hit must boot from the cached disk, not rebuild it"
    );
    assert_eq!(
        now.stamp, produced.stamp,
        "a cache hit must preserve the produce-time guest build stamp"
    );
}

fn assert_miss(produced: &Observation, now: &Observation) {
    assert!(now.slot_present, "a miss should produce a fresh cache slot");
    assert_ne!(
        now.disk_meta, produced.disk_meta,
        "a miss must rebuild the boot disk"
    );
    assert_ne!(
        now.stamp, produced.stamp,
        "a miss must regenerate the guest build stamp"
    );
}

fn produce(env: &TestEnv, workflow: &Path) -> Observation {
    let obs = run_and_observe(env, workflow, &[]);
    assert!(
        obs.slot_present,
        "the first run should produce a committed cache slot"
    );
    assert!(obs.stamp.is_some(), "the guest build stamp should exist");
    obs
}

#[test]
#[ignore = "System Test"]
fn cache_invalidates_on_files_modified() {
    let ni = native_image();
    let env = test_env("cache_files_modified");
    set_env(RETAIN_ENV, "0");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let tracked = env.test_dir.join("tracked.txt");
    std::fs::write(&tracked, b"v1").expect("write tracked file");
    let cache_block = format!("  cache:\n    files_modified:\n      - {}\n", slashed(&tracked));
    let workflow = write_workflow(
        &env,
        &stamp_workflow(ni.name, &out_dir_str(&env), &cache_block),
    );

    let produced = produce(&env, &workflow);
    assert_hit(&produced, &run_and_observe(&env, &workflow, &[]));

    std::fs::write(&tracked, b"v2-changed").expect("modify tracked file");
    assert_miss(&produced, &run_and_observe(&env, &workflow, &[]));

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}

#[test]
#[ignore = "System Test"]
fn cache_invalidates_on_files_list() {
    let ni = native_image();
    let env = test_env("cache_files_list");
    set_env(RETAIN_ENV, "0");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let srcs = env.test_dir.join("srcs");
    let _ = std::fs::remove_dir_all(&srcs);
    std::fs::create_dir_all(&srcs).expect("create srcs dir");
    std::fs::write(srcs.join("a.txt"), b"a").expect("write a.txt");
    let cache_block = format!(
        "  cache:\n    files_list:\n      - {}/*.txt\n",
        slashed(&srcs)
    );
    let workflow = write_workflow(
        &env,
        &stamp_workflow(ni.name, &out_dir_str(&env), &cache_block),
    );

    let produced = produce(&env, &workflow);
    assert_hit(&produced, &run_and_observe(&env, &workflow, &[]));

    std::fs::write(srcs.join("b.txt"), b"b").expect("add b.txt to the tracked set");
    assert_miss(&produced, &run_and_observe(&env, &workflow, &[]));

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}

#[test]
#[ignore = "System Test"]
fn cache_invalidates_on_env_value() {
    const VAR: &str = "VCI_CACHE_SYS_ENV_TEST";
    let ni = native_image();
    let env = test_env("cache_env");
    set_env(RETAIN_ENV, "0");
    set_env(VAR, "one");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let cache_block = format!("  cache:\n    env:\n      - {VAR}\n");
    let workflow = write_workflow(
        &env,
        &stamp_workflow(ni.name, &out_dir_str(&env), &cache_block),
    );

    let produced = produce(&env, &workflow);
    assert_hit(&produced, &run_and_observe(&env, &workflow, &[]));

    set_env(VAR, "two-changed");
    assert_miss(&produced, &run_and_observe(&env, &workflow, &[]));

    remove_image(&env, ni.name);
    unset_env(VAR);
    unset_env(RETAIN_ENV);
}

#[test]
#[ignore = "System Test"]
fn cache_expires_after_max_age() {
    let ni = native_image();
    let env = test_env("cache_max_age");
    set_env(RETAIN_ENV, "0");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let cache_block = "  cache:\n    max_age: 1s\n";
    let workflow = write_workflow(
        &env,
        &stamp_workflow(ni.name, &out_dir_str(&env), cache_block),
    );

    let produced = produce(&env, &workflow);

    // Belt-and-suspenders: the boot cycle alone exceeds 1s, but sleep to make expiry deterministic.
    std::thread::sleep(Duration::from_secs(2));
    assert_miss(&produced, &run_and_observe(&env, &workflow, &[]));

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}

#[test]
#[ignore = "System Test"]
fn cache_invalidates_on_workflow_change() {
    let ni = native_image();
    let env = test_env("cache_yaml_changed");
    set_env(RETAIN_ENV, "0");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let workflow = write_workflow(&env, &stamp_workflow(ni.name, &out_dir_str(&env), ""));
    let produced = produce(&env, &workflow);

    // Append a trailing comment: still valid YAML, but a different file hash.
    let mut yaml = std::fs::read_to_string(&workflow).expect("read workflow");
    yaml.push_str("\n# cache-busting comment\n");
    std::fs::write(&workflow, yaml).expect("rewrite workflow");

    assert_miss(&produced, &run_and_observe(&env, &workflow, &[]));

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}

#[test]
#[ignore = "System Test"]
fn cache_invalidates_on_base_image_change() {
    let ni = native_image();
    let env = test_env("cache_base_image");
    set_env(RETAIN_ENV, "0");

    let base_copy = env.test_dir.join("base_copy.img");
    std::fs::copy(common::upstream_img_path(ni.img_file), &base_copy).expect("copy base disk");
    let config = write_base_image_json(&env, &ni, &base_copy);
    register_image_from_json(&env, ni.name, &config);

    let workflow = write_workflow(&env, &stamp_workflow(ni.name, &out_dir_str(&env), ""));
    let produced = produce(&env, &workflow);

    let future = SystemTime::now() + Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(&base_copy)
        .expect("open base copy")
        .set_modified(future)
        .expect("bump base disk mtime");

    assert_miss(&produced, &run_and_observe(&env, &workflow, &[]));

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}

fn write_base_image_json(env: &TestEnv, ni: &NativeImage, base_copy: &Path) -> std::path::PathBuf {
    let seed = common::upstream_img_path("seed.iso");
    let json = format!(
        r#"{{
  "os": "Linux",
  "arch": "{arch}",
  "backend": {{
    "type": "qemu",
    "image": "{image}",
    "uefi": {{ "code": "auto", "vars": "auto" }},
    "cpu_model": null,
    "additional_drives": null,
    "additional_devices": null,
    "tpm": false,
    "nvme": false,
    "readonly_isos": ["{seed}"]
  }},
  "ssh": {{ "user": "virtci", "pass": "virtci", "key": null }}
}}
"#,
        arch = ni.arch_json,
        image = slashed(base_copy),
        seed = slashed(&seed),
    );
    let path = env.test_dir.join("base_image.json");
    std::fs::write(&path, json).expect("write base image json");
    path
}

#[test]
#[ignore = "System Test"]
fn cache_respects_storage_limit() {
    let ni = native_image();
    let env = test_env("cache_storage_limit");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let workflow = write_workflow(&env, &stamp_workflow(ni.name, &out_dir_str(&env), ""));

    set_env(RETAIN_ENV, "100000000");
    let refused = run_and_observe(&env, &workflow, &[]);
    assert!(
        !refused.slot_present,
        "an unsatisfiable retain floor must skip the cache write"
    );
    assert!(
        refused.stamp.is_some(),
        "the run itself still succeeds even when caching is skipped"
    );

    set_env(RETAIN_ENV, "0");
    let cached = run_and_observe(&env, &workflow, &[]);
    assert!(
        cached.slot_present,
        "with the floor disabled the workflow should cache normally"
    );

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}

#[test]
#[ignore = "System Test"]
fn cache_skips_marked_steps_on_hit() {
    let ni = native_image();
    let env = test_env("cache_skip_if_cached");
    set_env(RETAIN_ENV, "0");
    register_image(&env, ni.name, ni.json, ni.img_file);

    let out = out_dir_str(&env);
    let yaml = format!(
        r#"cache_job:
  image: {image}
  cpus: 2
  memory: 4G
  steps:
    - name: Cold-only stamp
      run: date +%s%N > ~/cold_stamp
      skip_if_cached: true
    - name: Every-run stamp
      run: date +%s%N > ~/warm_stamp
    - name: Bake build stamp
      run: test -f ~/vci_stamp || date +%s%N > ~/vci_stamp
    - name: Export cold
      copy:
        from: vm:~/cold_stamp
        to: {out}/
    - name: Export warm
      copy:
        from: vm:~/warm_stamp
        to: {out}/
    - name: Export stamp
      copy:
        from: vm:~/vci_stamp
        to: {out}/
"#,
        image = ni.name,
        out = out,
    );
    let workflow = write_workflow(&env, &yaml);

    let produced = produce(&env, &workflow);
    let cold_produced = read_stamp(&env, "cold_stamp");
    let warm_produced = read_stamp(&env, "warm_stamp");
    assert!(cold_produced.is_some() && warm_produced.is_some());

    let hit = run_and_observe(&env, &workflow, &[]);
    assert_hit(&produced, &hit);

    let cold_hit = read_stamp(&env, "cold_stamp");
    let warm_hit = read_stamp(&env, "warm_stamp");
    assert_eq!(
        cold_hit, cold_produced,
        "the skip_if_cached step must NOT re-run on a hit (its stamp stays the produce-time one)"
    );
    assert_ne!(
        warm_hit, warm_produced,
        "an ordinary step must still run on a hit (its stamp advances)"
    );

    remove_image(&env, ni.name);
    unset_env(RETAIN_ENV);
}
