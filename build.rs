// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/file_lock/process_time.c");
    println!("cargo:rerun-if-changed=src/file_lock/flock.c");

    cc::Build::new()
        .file("src/file_lock/process_time.c")
        .file("src/file_lock/flock.c")
        // .warnings(true)
        // .extra_warnings(true)
        // .cargo_warnings(true)
        // .warnings_into_errors(true)
        .compile("vci-native");

    build_frontend();
}

fn build_frontend() {
    println!("cargo:rerun-if-changed=web/src");
    println!("cargo:rerun-if-changed=web/index.html");
    println!("cargo:rerun-if-changed=web/package.json");

    if !Path::new("web/package.json").exists() {
        return;
    }

    if !Path::new("web/node_modules").exists() {
        let status = Command::new("npm")
            .args(["install"])
            .current_dir("web")
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!("npm install failed with status: {s}"),
            Err(e) => {
                println!("cargo:warning=npm not found, skipping frontend build: {e}");
                return;
            }
        }
    }

    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir("web")
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("npm run build failed with status: {s}"),
        Err(e) => {
            println!("cargo:warning=npm not found, skipping frontend build: {e}");
        }
    }
}
