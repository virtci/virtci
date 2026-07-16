// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! Running these tests locally.
//!
//! ```sh
//! ./.ci/upstream/fetch_ubuntu_images.sh
//! cargo test --test ubuntu_vms_full_workflow_run -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! ```powershell
//! .\.ci\upstream\fetch_ubuntu_images.ps1
//! cargo test --test ubuntu_vms_full_workflow_run -- --ignored --test-threads=1 --nocapture
//! ```

use std::path::Path;

mod common;
use common::{register_image, remove_image, run_workflow, test_env};

fn thorough_workflow(image: String, test_dir: String, crlf_check: &str) -> String {
    format!(
        r#"first_job:
  image: {image}
  cpus: 3
  memory: 8G
  host_env:
    - VIRTCI_TEST_HOST_ENV
  steps:
    - name: Say Hello
      run: echo hello

    - name: Multiline Run
      run: |
        set -e
        mkdir -p ~/proj
        echo first > ~/proj/a.txt
        echo second >> ~/proj/a.txt
        test "$(wc -l < ~/proj/a.txt)" = "2"

    - name: Step Env
      run: test "$TEST_VALUE" = "42"
      env:
        TEST_VALUE: 42

    - name: Host Env Forwarding
      run: test "$VIRTCI_TEST_HOST_ENV" = "from-host"

    - name: Copy To VM
      copy:
        # Directory copies move the *contents* of `from` into `to`,
        # so the destination directory is named explicitly.
        from: {test_dir}/copy_in
        to: vm:~/copy_in
        crlf: true
        exclude:
          - excluded

    - name: Verify Copy To VM
      run: |
        set -e
        test -f ~/copy_in/hello.txt
        test -f ~/copy_in/sub/nested.txt
        test ! -e ~/copy_in/excluded
        {crlf_check}

    - name: Copy To VM With Ignore File
      copy:
        from: {test_dir}/copy_in
        to: vm:~/copy_ignore
        ignore_file: .virtciignore

    - name: Verify Ignore File Applied
      run: |
        set -e
        test -f ~/copy_ignore/hello.txt
        test -f ~/copy_ignore/sub/nested.txt
        test ! -e ~/copy_ignore/ignored_dir
        test ! -e ~/copy_ignore/skip.log

    - name: Workdir
      workdir: ~/copy_in
      run: |
        set -e
        test "$(pwd)" = "$HOME/copy_in"
        test -f hello.txt

    - name: Failing Run Continues
      run: this-command-does-not-exist
      continue_on_error: true

    - name: Step Timeout Kills Sleep
      run: sleep 30 && echo marker > ~/timeout_marker
      timeout: 5S
      continue_on_error: true

    - name: No Mkdir Fails
      copy:
        from: {test_dir}/copy_in/hello.txt
        to: vm:~/this/path/does/not/exist/
        no_mkdir: true
      continue_on_error: true

    - name: Still Running After Failures
      run: test ! -e ~/timeout_marker

    - name: Restart Offline With Fewer Resources
      restart:
        offline: true
        cpus: 2
        memory: 6G

    - name: Verify Restart State
      run: |
        set -e
        test "$(nproc)" = "2"
        mem_kb=$(grep MemTotal /proc/meminfo | tr -s ' ' | cut -d ' ' -f 2)
        test "$mem_kb" -gt 4194304
        test "$mem_kb" -lt 7340032
        test -f ~/proj/a.txt

    - name: Verify Offline
      run: |
        if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'; then exit 1; fi

    - name: Restart Online
      restart:
        offline: false
        cpus: 3
        memory: 8G

    - name: Verify Online
      run: curl -fsS --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 20 --max-time 60 http://archive.ubuntu.com/ > /dev/null

    - name: Build Artifacts
      run: |
        set -e
        mkdir -p ~/build/out
        echo binary-payload > ~/build/out/tool.bin

    - name: Copy Artifacts To Host
      copy:
        from: vm:~/build/**/*.bin
        to: {test_dir}/copy_out

    - name: Copy Empty Glob Allowed
      copy:
        from: vm:~/build/**/*.absent
        to: {test_dir}/copy_out
        allow_empty: true

second_job:
  image: {image}
  cpus: 2
  memory: 6G
  steps:
    - name: Second Job In Same File
      run: echo second job ran
"#
    )
}

fn dir_contains_file_with_extension(dir: &Path, ext: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if dir_contains_file_with_extension(&path, ext) {
                return true;
            }
        } else if path.extension().is_some_and(|e| e == ext) {
            return true;
        }
    }
    false
}

/// Exercises the full workflow syntax from docs/workflow_yaml_syntax.md against
/// an upstream Ubuntu cloud image: job-level `cpus`/`memory`/`host_env`,
/// `run` (single and multiline), `copy` in both directions with `exclude`,
/// `ignore_file` (a nested `.virtciignore`), `crlf`, `no_mkdir`, `allow_empty`,
/// and globs, `restart` with `offline`/
/// `cpus`/`memory`, plus step-level `workdir`, `timeout`, `env`, and
/// `continue_on_error`, and multiple jobs in one workflow file.
fn run_thorough_system_test(test_name: &str, image_name: &str, image_json: &str, image_file: &str) {
    let env = test_env(test_name);

    // Host-side fixture for the copy-to-VM steps. hello.txt is written with
    // CRLF line endings so the `crlf: true` conversion is observable in-guest.
    let copy_in = env.test_dir.join("copy_in");
    let _ = std::fs::remove_dir_all(&copy_in);
    std::fs::create_dir_all(copy_in.join("sub")).expect("Failed to create copy_in fixture");
    std::fs::create_dir_all(copy_in.join("excluded")).expect("Failed to create copy_in fixture");
    std::fs::write(copy_in.join("hello.txt"), "hello world\r\nsecond line\r\n")
        .expect("Failed to write fixture");
    std::fs::write(copy_in.join("sub/nested.txt"), "nested\n").expect("Failed to write fixture");
    std::fs::write(copy_in.join("excluded/skip.txt"), "should not be copied\n")
        .expect("Failed to write fixture");

    std::fs::write(copy_in.join(".virtciignore"), "ignored_dir/\n*.log\n")
        .expect("Failed to write fixture");
    std::fs::create_dir_all(copy_in.join("ignored_dir")).expect("Failed to create copy_in fixture");
    std::fs::write(copy_in.join("ignored_dir/nope.txt"), "ignored\n")
        .expect("Failed to write fixture");
    std::fs::write(copy_in.join("skip.log"), "ignored\n").expect("Failed to write fixture");

    // Destination for the copy-back-to-host steps, fresh every run.
    let copy_out = env.test_dir.join("copy_out");
    let _ = std::fs::remove_dir_all(&copy_out);
    std::fs::create_dir_all(&copy_out).expect("Failed to create copy_out directory");

    // Forwarded into the VM via the job's `host_env`.
    unsafe { std::env::set_var("VIRTCI_TEST_HOST_ENV", "from-host") };

    // CRLF conversion only runs when host and guest line conventions disagree
    // (Windows host -> Unix VM). On a Unix host the file arrives unconverted.
    let crlf_check = if cfg!(target_os = "windows") {
        r#"! grep -q "$(printf '\r')" ~/copy_in/hello.txt"#
    } else {
        r#"grep -q "$(printf '\r')" ~/copy_in/hello.txt"#
    };

    let test_dir = env.test_dir.to_string_lossy().replace('\\', "/");

    let workflow_yaml = thorough_workflow(image_name.to_string(), test_dir, crlf_check);

    register_image(&env, image_name, image_json, image_file);
    run_workflow(&env, &workflow_yaml);
    remove_image(&env, image_name);

    // The VM-to-host glob copy must have landed the built artifact.
    assert!(
        dir_contains_file_with_extension(&copy_out, "bin"),
        "Expected a .bin artifact copied back from the VM under {}",
        copy_out.display()
    );
}

#[test]
#[ignore = "System Test"]
fn ubuntu_full_workflow_run_x64() {
    run_thorough_system_test(
        "ubuntu_full_workflow_run_x64",
        "ubuntu-x64",
        ".ci/upstream/ubuntu_server_x64.json",
        "resolute-server-cloudimg-amd64.img",
    );
}

#[test]
#[ignore = "System Test"]
fn ubuntu_full_workflow_run_arm64() {
    run_thorough_system_test(
        "ubuntu_full_workflow_run_arm64",
        "ubuntu-arm64",
        ".ci/upstream/ubuntu_server_arm64.json",
        "resolute-server-cloudimg-arm64.img",
    );
}

#[test]
#[ignore = "System Test"]
fn ubuntu_full_workflow_run_riscv64() {
    run_thorough_system_test(
        "ubuntu_full_workflow_run_riscv64",
        "ubuntu-riscv64",
        ".ci/upstream/ubuntu_server_riscv64.json",
        "resolute-server-cloudimg-riscv64.img",
    );
}
