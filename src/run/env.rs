// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{collections::HashMap, path::PathBuf};

pub enum EnvLoad {
    /// The `.env` file from the current working directory
    DotEnvCwd,
    File {
        path: PathBuf,
    },
}

/// Loads extra environment variables beyond what is in the process's environment,
/// like from a `.env` file in the current working directory or a specific file.
/// NOTE, generally, shell env vars take precende over `.env` ones, and we'll
/// respect that.
pub fn load_extra_env_vars(load: &EnvLoad) -> anyhow::Result<HashMap<String, String>> {
    let iter = match load {
        EnvLoad::DotEnvCwd => dotenvy::from_filename_iter(".env")?,
        EnvLoad::File { path } => dotenvy::from_path_iter(path)?,
    };

    let mut map = HashMap::<String, String>::default();
    for items in iter {
        let pair = items?;
        map.insert(pair.0, pair.1);
    }
    Ok(map)
}
