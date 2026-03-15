// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use virtci::{run_virtci_cli, VciGlobalPaths};

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    run_virtci_cli(&VciGlobalPaths::default());
}
