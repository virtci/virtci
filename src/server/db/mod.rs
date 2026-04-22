// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::Context;
use rusqlite::{Connection, Transaction};

mod migrations;

pub struct SQLiteDBOpenFile {
    pub path: PathBuf,
}

pub enum SQLiteDBOpenParams {
    Memory,
    File(SQLiteDBOpenFile),
}

pub struct SQLiteDB {
    conn: rusqlite::Connection,
}

impl SQLiteDB {
    pub fn new(open_params: &SQLiteDBOpenParams) -> anyhow::Result<Arc<RwLock<SQLiteDB>>> {
        let mut conn = match open_params {
            SQLiteDBOpenParams::Memory => {
                Connection::open_in_memory().expect("Failed to create SQLite DB in memory")
            }
            SQLiteDBOpenParams::File(file) => Connection::open(&file.path).with_context(|| {
                format!("Unable to create SQLite db at {}", file.path.display())
            })?,
        };

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
        )
        .with_context(|| "Unable to setup db".to_string())?;

        migrations::migrate_if_needed(&mut conn)?;

        return Ok(Arc::new(RwLock::new(SQLiteDB { conn })));
    }
}
