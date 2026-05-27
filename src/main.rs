// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use virtci::{global_paths::VciGlobalPaths, run_virtci_cli};

fn main() {
    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut paths = VciGlobalPaths::default();
    #[cfg(target_os = "windows")]
    {
        use virtci::global_paths::WslPaths;

        match WslPaths::new() {
            Ok(wsl_paths) => paths.wsl = Some(wsl_paths),
            Err(e) => {
                eprintln!(
                    "Encountered non-fatal issue querying WSL2 information on VirtCI startup."
                );
                eprintln!("{e}");
            }
        }
    }

    run_virtci_cli(&paths);
}
