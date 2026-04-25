// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use rusqlite::{Connection, Transaction};

use crate::server::auth::TokenScope;

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

/// `User` if the DB `is_provisioned` is false, otherwise `Namespace`.
/// Contains the id for either the `users` or `namespaces` tables.
pub enum ApiTokenProvision {
    User(i64),
    Namespace(i64),
}

/// Entry of `api_tokens` table in DB.
pub struct ApiTokenInfo {
    pub id: i64,
    pub token_hash: Vec<u8>,
    pub token_prefix: String,
    pub name: String,
    pub provision: ApiTokenProvision,
    pub scope: TokenScope,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub last_used_ip: Option<String>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// Entry of `namespaces` table in DB. JSONB columns (`public_personal_info`,
/// `settings`) are surfaced as raw bytes; callers deserialize if they need them.
pub struct NamespaceInfo {
    pub id: i64,
    pub slug: String,
    pub owner_user_id: i64,
    pub storage_used_bytes: i64,
    pub created_by_user_id: i64,
    pub display_name: Option<String>,
    pub avatar_s3_url: Option<String>,
    pub public_personal_info: Vec<u8>,
    pub is_verified: bool,
    pub personal: bool,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
    pub purge_after: Option<i64>,
    pub settings: Vec<u8>,
}

pub struct ImageInfo {
    pub id: i64,
    pub namespace_id: i64,
    pub name: String,
    pub is_private: bool,
    pub versioned: bool,
    pub description: Option<String>,
    pub star_count: i64,
    pub created_at: i64,
    pub deleted_at: Option<i64>,
    pub purge_after: Option<i64>,
}

impl SQLiteDB {
    pub fn new(open_params: &SQLiteDBOpenParams) -> anyhow::Result<Arc<Mutex<SQLiteDB>>> {
        // TODO in the future support multiple concurrent readers.
        // SQLite is fine with it but rusqlite is not with the normal connection thingy.
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

        return Ok(Arc::new(Mutex::new(SQLiteDB { conn })));
    }

    pub fn api_token_info(&self, token_hash_lookup: &[u8]) -> anyhow::Result<ApiTokenInfo> {
        let (
            id,
            is_provisioned,
            token_hash,
            token_prefix,
            name,
            user_id,
            namespace_id,
            scope_int,
            created_at,
            last_used_at,
            last_used_ip,
            expires_at,
            revoked_at,
        ): (
            i64,
            bool,
            Vec<u8>,
            String,
            String,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<i64>,
            Option<i64>,
        ) = self
            .conn
            .query_row(
                "SELECT id, is_provisioned, token_hash, token_prefix, name, user_id, \
                        namespace_id, scope, created_at, last_used_at, last_used_ip, \
                        expires_at, revoked_at \
                 FROM api_tokens WHERE token_hash = ?1",
                rusqlite::params![token_hash_lookup],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                    ))
                },
            )
            .with_context(|| "Failed to fetch api_token row".to_string())?;

        // `api_tokens` CHECK constraint ensures the combination is well-formed.
        // Anything that deviated is probably a database corruption or something.
        let provision = if is_provisioned {
            let ns_id = namespace_id.with_context(|| {
                format!("api_tokens row {id}: provisioned token has NULL namespace_id")
            })?;
            ApiTokenProvision::Namespace(ns_id)
        } else {
            let uid = user_id
                .with_context(|| format!("api_tokens row {id}: personal token has NULL user_id"))?;
            ApiTokenProvision::User(uid)
        };

        let scope = match scope_int {
            0 => TokenScope::ReadOnly,
            1 => TokenScope::ReadWrite,
            2 => TokenScope::Maintain,
            3 => TokenScope::Admin,
            other => anyhow::bail!("api_tokens row {id}: invalid scope value {other}"),
        };

        Ok(ApiTokenInfo {
            id,
            token_hash,
            token_prefix,
            name,
            provision,
            scope,
            created_at,
            last_used_at,
            last_used_ip,
            expires_at,
            revoked_at,
        })
    }

    pub fn namespace_by_slug(&self, slug: &str) -> anyhow::Result<NamespaceInfo> {
        let (
            id,
            slug,
            owner_user_id,
            storage_used_bytes,
            created_by_user_id,
            display_name,
            avatar_s3_url,
            public_personal_info,
            is_verified,
            personal,
            created_at,
            deleted_at,
            purge_after,
            settings,
        ): (
            i64,
            String,
            i64,
            i64,
            i64,
            Option<String>,
            Option<String>,
            Vec<u8>,
            bool,
            bool,
            i64,
            Option<i64>,
            Option<i64>,
            Vec<u8>,
        ) = self
            .conn
            .query_row(
                "SELECT id, slug, owner_user_id, storage_used_bytes, created_by_user_id, \
                        display_name, avatar_s3_url, public_personal_info, is_verified, \
                        personal, created_at, deleted_at, purge_after, settings \
                 FROM namespaces WHERE slug = ?1",
                rusqlite::params![slug],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                    ))
                },
            )
            .with_context(|| format!("Failed to find namespace with slug {slug:?}"))?;

        Ok(NamespaceInfo {
            id,
            slug,
            owner_user_id,
            storage_used_bytes,
            created_by_user_id,
            display_name,
            avatar_s3_url,
            public_personal_info,
            is_verified,
            personal,
            created_at,
            deleted_at,
            purge_after,
            settings,
        })
    }

    pub fn namespace_by_id(&self, namespace_id: i64) -> anyhow::Result<NamespaceInfo> {
        let (
            id,
            slug,
            owner_user_id,
            storage_used_bytes,
            created_by_user_id,
            display_name,
            avatar_s3_url,
            public_personal_info,
            is_verified,
            personal,
            created_at,
            deleted_at,
            purge_after,
            settings,
        ): (
            i64,
            String,
            i64,
            i64,
            i64,
            Option<String>,
            Option<String>,
            Vec<u8>,
            bool,
            bool,
            i64,
            Option<i64>,
            Option<i64>,
            Vec<u8>,
        ) = self
            .conn
            .query_row(
                "SELECT id, slug, owner_user_id, storage_used_bytes, created_by_user_id, \
                        display_name, avatar_s3_url, public_personal_info, is_verified, \
                        personal, created_at, deleted_at, purge_after, settings \
                 FROM namespaces WHERE id = ?1",
                rusqlite::params![namespace_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                    ))
                },
            )
            .with_context(|| format!("Failed to find namespace with id {namespace_id}"))?;

        Ok(NamespaceInfo {
            id,
            slug,
            owner_user_id,
            storage_used_bytes,
            created_by_user_id,
            display_name,
            avatar_s3_url,
            public_personal_info,
            is_verified,
            personal,
            created_at,
            deleted_at,
            purge_after,
            settings,
        })
    }

    /// Gets a non-deleted image by namespace name and image name.
    pub fn active_image_info_by_namespace_name(
        &self,
        namespace_name: &str,
        image_name: &str,
    ) -> anyhow::Result<ImageInfo> {
        let (
            id,
            namespace_id,
            name,
            is_private,
            versioned,
            description,
            star_count,
            created_at,
            deleted_at,
            purge_after,
        ): (
            i64,
            i64,
            String,
            bool,
            bool,
            Option<String>,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
        ) = self
            .conn
            .query_row(
                "SELECT i.id, i.namespace_id, i.name, i.is_private, i.versioned, \
                        i.description, i.star_count, i.created_at, i.deleted_at, i.purge_after \
                 FROM images i \
                 JOIN namespaces n ON n.id = i.namespace_id \
                 WHERE n.slug = ?1 AND i.name = ?2 AND i.deleted_at IS NULL",
                rusqlite::params![namespace_name, image_name],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ))
                },
            )
            .with_context(|| {
                format!("Failed to find image {image_name:?} in namespace {namespace_name:?}")
            })?;

        Ok(ImageInfo {
            id,
            namespace_id,
            name,
            is_private,
            versioned,
            description,
            star_count,
            created_at,
            deleted_at,
            purge_after,
        })
    }
}
