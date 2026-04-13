// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use anyhow::Context;
use rusqlite::{Connection, Transaction};

mod v1;

/// Maps to SQLite `user_version`.
const SCHEMA_VERSION: i32 = 1;

fn get_db_schema_version(conn: &Connection) -> i32 {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap_or(0)
}

pub fn migrate_if_needed(conn: &mut Connection) -> anyhow::Result<()> {
    let current_version = get_db_schema_version(conn);

    if current_version < SCHEMA_VERSION {
        let tx = conn.transaction()?;
        run_migrations(&tx, current_version + 1, SCHEMA_VERSION).with_context(|| {
            format!("Failed to migrate from {current_version} to {SCHEMA_VERSION}")
        })?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", SCHEMA_VERSION))
            .with_context(|| format!("Failed to set db schema version to {SCHEMA_VERSION}"))?;
        tx.commit()
            .with_context(|| "DB commit failed".to_string())?;
    }

    Ok(())
}

fn run_migrations(tx: &Transaction, from_version: i32, to_version: i32) -> anyhow::Result<()> {
    for version in from_version..=to_version {
        match version {
            1 => v1::create_tables(tx)?,
            _ => anyhow::bail!("Unknown migration version: {}", version),
        }
    }
    Ok(())
}
