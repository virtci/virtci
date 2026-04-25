// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use anyhow::Context;
use rusqlite::Transaction;

pub fn create_tables(tx: &Transaction) -> anyhow::Result<()> {
    tx.execute_batch(
        "
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            avatar_s3_url TEXT,
            public_personal_info JSONB NOT NULL DEFAULT '{}',
            mfa_required BOOLEAN NOT NULL DEFAULT 0,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER,
            created_at INTEGER NOT NULL,
            email_verified_at INTEGER,
            disabled_at INTEGER
        );

        CREATE TABLE mfa_totp (
            user_id INTEGER PRIMARY KEY,
            secret_encrypted BLOB NOT NULL,
            confirmed_at INTEGER,
            last_counter INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE mfa_recovery_codes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE account_recovery_tokens (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash BLOB NOT NULL,
            kind TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE oauth_accounts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE UNIQUE INDEX idx_oauth_provider_provider_id ON oauth_accounts(provider, provider_id);

        CREATE TABLE web_sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            ip TEXT NOT NULL,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        -- Namespaces and members
        CREATE TABLE namespaces (
            id INTEGER PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            owner_user_id INTEGER NOT NULL,
            storage_used_bytes INTEGER NOT NULL DEFAULT 0,
            created_by_user_id INTEGER NOT NULL,
            display_name TEXT,
            avatar_s3_url TEXT,
            public_personal_info JSONB NOT NULL DEFAULT '{}',
            is_verified BOOLEAN NOT NULL DEFAULT 0,
            personal BOOLEAN NOT NULL,
            created_at INTEGER NOT NULL,
            deleted_at INTEGER,
            purge_after INTEGER,
            settings JSONB NOT NULL DEFAULT '{}',
            FOREIGN KEY (owner_user_id) REFERENCES users(id),
            FOREIGN KEY (created_by_user_id) REFERENCES users(id)
        );

        CREATE TABLE namespace_members (
            namespace_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
            added_at INTEGER NOT NULL,
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            PRIMARY KEY (namespace_id, user_id)
        );

        CREATE TABLE namespace_invites (
            id INTEGER PRIMARY KEY,
            namespace_id INTEGER NOT NULL,
            username TEXT NOT NULL COLLATE NOCASE,
            role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
            invited_by INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            accepted_at INTEGER,
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id),
            FOREIGN KEY (invited_by) REFERENCES users(id)
        );

        CREATE UNIQUE INDEX idx_namespace_invites_namespace_username ON namespace_invites(namespace_id, username) WHERE accepted_at IS NULL;

        -- API tokens
        CREATE TABLE api_tokens (
            id INTEGER PRIMARY KEY,
            is_provisioned BOOLEAN NOT NULL,
            token_hash BLOB NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            name TEXT NOT NULL,
            user_id INTEGER,
            namespace_id INTEGER,
            scope INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            last_used_ip TEXT,
            expires_at INTEGER,
            revoked_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id),
            CHECK (
                (is_provisioned = 0 AND user_id IS NOT NULL AND namespace_id IS NULL) OR
                (is_provisioned = 1 AND namespace_id IS NOT NULL)
            )
        );

        -- Images and versions
        CREATE TABLE images (
            id INTEGER PRIMARY KEY,
            namespace_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            is_private BOOLEAN NOT NULL DEFAULT 0,
            versioned BOOLEAN NOT NULL DEFAULT 0,
            description TEXT,
            star_count INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            deleted_at INTEGER,
            purge_after INTEGER,
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
        );

        CREATE INDEX idx_images_namespace ON images(namespace_id);
        CREATE UNIQUE INDEX idx_images_ns_name_active ON images(namespace_id, name) WHERE deleted_at IS NULL;

        CREATE TABLE image_versions (
            id INTEGER PRIMARY KEY,
            image_id INTEGER NOT NULL,
            version TEXT,
            content_digest TEXT NOT NULL,
            total_bytes INTEGER NOT NULL,
            image_desc JSONB NOT NULL,
            release_notes TEXT,
            created_by_token_id INTEGER NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('uploading', 'ready', 'failed', 'deleting')),
            pull_count INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            deleted_at INTEGER,
            purge_after INTEGER,
            FOREIGN KEY (image_id) REFERENCES images(id),
            FOREIGN KEY (created_by_token_id) REFERENCES api_tokens(id)
        );

        CREATE INDEX idx_image_versions_image ON image_versions(image_id);
        CREATE UNIQUE INDEX idx_image_versions_image_version ON image_versions(image_id, version) WHERE version IS NOT NULL;
        CREATE UNIQUE INDEX idx_image_versions_image_digest ON image_versions(image_id, content_digest);

        CREATE TABLE image_version_tags (
            image_version_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY (image_version_id) REFERENCES image_versions(id),
            PRIMARY KEY (image_version_id, value)
        );

        CREATE TABLE image_aliases (
            image_id INTEGER NOT NULL,
            image_version_id INTEGER NOT NULL,
            alias TEXT NOT NULL CHECK (alias != 'latest'),
            description TEXT,
            FOREIGN KEY (image_id) REFERENCES images(id),
            FOREIGN KEY (image_version_id) REFERENCES image_versions(id),
            PRIMARY KEY (image_id, alias)
        );

        CREATE INDEX idx_image_aliases_version ON image_aliases(image_version_id);

        CREATE TABLE image_stars (
            user_id INTEGER NOT NULL,
            image_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (image_id) REFERENCES images(id),
            PRIMARY KEY (user_id, image_id)
        );

        CREATE INDEX idx_image_stars_image ON image_stars(image_id);

        CREATE TABLE image_files (
            id INTEGER PRIMARY KEY,
            version_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            s3_object_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            FOREIGN KEY (version_id) REFERENCES image_versions(id)
        );

        CREATE INDEX idx_image_files_version ON image_files(version_id);

        CREATE TABLE multipart_uploads (
            id INTEGER PRIMARY KEY,
            s3_key TEXT NOT NULL,
            s3_upload_id TEXT NOT NULL,
            version_id INTEGER NOT NULL,
            started_at INTEGER NOT NULL,
            FOREIGN KEY (version_id) REFERENCES image_versions(id)
        );

        CREATE INDEX idx_multipart_uploads_version ON multipart_uploads(version_id);

        -- Audit log (no FKs for append-only preservation)
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            actor_user_id INTEGER,
            actor_token_id INTEGER,
            namespace_id INTEGER,
            action TEXT NOT NULL,
            target TEXT,
            ip TEXT,
            user_agent TEXT,
            at INTEGER NOT NULL
        );

        CREATE INDEX idx_audit_log_actor_user ON audit_log(actor_user_id);
        CREATE INDEX idx_audit_log_actor_token ON audit_log(actor_token_id);
        CREATE INDEX idx_audit_log_namespace ON audit_log(namespace_id);
        CREATE INDEX idx_audit_log_at ON audit_log(at);

        -- Notifications
        CREATE TABLE user_notifications (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            namespace_id INTEGER,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            link TEXT,
            created_at INTEGER NOT NULL,
            read_at INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
        );

        CREATE INDEX idx_user_notifications_user ON user_notifications(user_id);
        CREATE INDEX idx_user_notifications_namespace ON user_notifications(namespace_id);

        -- Billing (SaaS only)
        CREATE TABLE plan_pricing (
            id INTEGER PRIMARY KEY,
            currency TEXT NOT NULL,
            base_cost INTEGER NOT NULL,
            base_gb_included INTEGER NOT NULL,
            extra_cost INTEGER NOT NULL,
            extra_gb_included INTEGER NOT NULL
        );

        CREATE TABLE subscriptions (
            id INTEGER PRIMARY KEY,
            namespace_id INTEGER NOT NULL UNIQUE,
            pricing_id INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active', 'past_due', 'canceled')),
            current_period_start INTEGER NOT NULL,
            current_period_end INTEGER NOT NULL,
            storage_cap_bytes INTEGER NOT NULL,
            peak_cap_bytes INTEGER NOT NULL,
            peak_storage_bytes INTEGER NOT NULL,
            external_customer_id TEXT,
            external_subscription_id TEXT,
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id),
            FOREIGN KEY (pricing_id) REFERENCES plan_pricing(id)
        );

        CREATE TABLE usage_events (
            id INTEGER PRIMARY KEY,
            namespace_id INTEGER NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('storage_sample', 'push')),
            bytes INTEGER NOT NULL,
            recorded_at INTEGER NOT NULL,
            FOREIGN KEY (namespace_id) REFERENCES namespaces(id)
        );

        CREATE INDEX idx_usage_events_namespace ON usage_events(namespace_id);
        CREATE INDEX idx_usage_events_recorded_at ON usage_events(recorded_at);

        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY,
            subscription_id INTEGER NOT NULL,
            period_start INTEGER NOT NULL,
            period_end INTEGER NOT NULL,
            currency TEXT NOT NULL,
            subtotal INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('draft', 'open', 'paid', 'void')),
            external_invoice_id TEXT,
            FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
        );

        CREATE INDEX idx_invoices_subscription ON invoices(subscription_id);
        "
    ).with_context(|| "Unable to create schema version 1 tables".to_string())?;
    Ok(())
}
