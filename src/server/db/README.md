# Server DB Schema

This document is a dev reference describing the SQLite database schema for the VirtCI storage management server. It covers reasoning as to why each design decision was made.

## Deployment Modes

The storage server runs in one of two modes, set on startup.

### SaaS

- Billing is active, and storage limits come from subscription plans.
- MFA is enforced for admins of a paid namespace.

### Self-Hosted

- Billing tables exist but aren't used.
- Storage limits come entirely from the S3 storage API.
- Versioning is freely available and MFA is optional.
- Anonymous write usage is permitted if auth requirements are disabled.

## Version 0.2.0

## SQLite configuration

Every connection must set:

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

WAL mode is required for being able to backup the DB into S3 storage, using Litestream (or similar).

Foreign Keys are required.

The write pool will just be 1, but there can be a larger read pool. Multi-step writes must go in a singular transaction.

## Authentication model

There are four user types (principals) in the system, with two token kinds and one session
type. Understanding this hierarchy is critical to understanding most of the
schema below.

Note that if your self-hosted instance has authentication disabled, none of these user types will have any restrictions.

### Principals

| Principal | Credentials | Capabilities |
|---|---|---|
| Anonymous | None | Pull public VM images only |
| Web User | Email + password + MFA -> session cookie | Anything their namespace-specific auth token permits. |
| CLI User Personal | Personal API token | Pull public or private VMs from any namespace they are a member of. Cannot push to a non-personal namespace. |
| CLI User Token | Provisioned API token | Whatever the token is provisioned for for the namespace it is provisioned for. |

### Token kinds

API tokens are either personal, for your own namespace, or provisioned, by a namespace for other users, automated runners, or bots.

#### Personal Tokens

Personal tokens are created by a user for their own CLI use. They have no stored scope and also are not bound to a specific namespace. At CLI use time with that auth token, they are granted pull access to every public or private VM of any namespace they are a member of. A personal token cannot push to a non-personal namespace.

Removing a user from a namespace will automatically revoke their pull access without needing to perform any token rotation.

#### Provisioned Tokens

Provisioned tokens are created by a namespace admin through the web dashboard. They are bound to a single namespace with explicit scope rules. They are intended to allow pushing new VMs, managing them, and more. This can be for users, CI/CD runners, bots, or anything else.

### Provisioned Token Scope

Provisioned tokens use a four-level heirarchical scope, in which each level includes the permissions of all levels below it:

| Scope | Integer | Capabilities (cumulative) |
|---|---|---|
| `ReadOnly` | 0 | Pull images, list images, read metadata |
| `ReadWrite` | 1 | Push new images with visibility, create new tags |
| `Maintain` | 2 | Modify existing images (change visibility, delete images/versions, lock/unlock tags, toggle versioning) |
| `Admin` | 3 | Manage namespace members, manage provisioned tokens, web dashboard billing, namespace settings |

This maps to the `TokenScope` enum in `src/server/auth/mod.rs`.

For billing, only `Admin` can manage financial information. All other token scopes are treated as `ReadOnly`.

### Token Format

All tokens use the `vci_` prefix, followed by base32-encoded random bytes (32 bytes of entropy). Upon token creation, the plaintext is shown to the user exactly once, and after that, only the hash is stored.

### Web Sessions

The web dashboard uses traditional session cookies, not API tokens. After email/password login + optional MFA verification, the server creates a `web_sessions` row setting a session cookie. Web sessions have a fixed expiry, bound to the IP used to create the session.

### MFA

For right now, MFA will be done as TOTP.

In SaaS mode, MFA is enforced for any modification operations of a namespace with active paid subscriptions.

In self-hosted mode, MFA is optional.

## Tables

All colums with `_at` in them use 64-bit `INTEGER` entries as unix epoch seconds. The actual VirtCI executable code is responsible for using those integers as time stamps.

### `users`

Humans who log in via the web dashboard.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `email` | TEXT NOT NULL UNIQUE COLLATE NOCASE | Stored with user provided casing, but uniqueness and lookups are case-insensitive. |
| `password_hash` | TEXT | Argon2id PHC-format string (includes salt). Null for OAuth. |
| `username` | TEXT NOT NULL UNIQUE COLLATE NOCASE | Must be URL-safe and CLI-safe, cause it's used in S3 paths and CLI commands. Immutable for the user. |
| `mfa_required` | BOOLEAN NOT NULL DEFAULT false | True if the user has completed MFA enrollment. |
| `failed_login_count` | INTEGER NOT NULL DEFAULT 0 | Reset to 0 on successful login. |
| `locked_until` | INTEGER | Set after N failed attempts. Null = not locked. |
| `created_at` | INTEGER NOT NULL | |
| `email_verified_at` | INTEGER | Null = unverified. |
| `disabled_at` | INTEGER | Null = active. Soft-disable, not delete. |

Emails are stored exactly as the user typed it, preserving casing, but all lookups and uniqueness checks are done case-insensitively.

`failed_login_count` and `locked_until` provide login throttling. If a malicious actor is spamming to try to crack a password, rate limiting at the application level can impede this.

### `mfa_totp`

TOTP enrollment for a user. One row per user (single TOTP device).

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | INTEGER PK | FK to `users.id` |
| `secret_encrypted` | BLOB NOT NULL | TOTP secret, encrypted with env key |
| `confirmed_at` | INTEGER | Null = enrolled but not yet confirmed with a valid code |
| `last_counter` | INTEGER NOT NULL DEFAULT 0 | Prevents code reuse within the same time step |

### `mfa_recovery_codes`

One-time-use recovery codes for MFA bypass when the TOTP device is unavailable.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `user_id` | INTEGER NOT NULL | FK to `users.id` |
| `code_hash` | TEXT NOT NULL | Argon2id hash of the recovery code |
| `used_at` | INTEGER | Null = unused. Non-null = consumed, shown in UI as used. |

### `account_recovery_tokens`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `user_id` | INTEGER NOT NULL | FK to `users.id`. |
| `token_hash` | BLOB NOT NULL | Hash of the URL token. |
| `kind` | TEXT NOT NULL | `password_reset` or `mfa_reset`. |
| `created_at` | INTEGER NOT NULL | |
| `expires_at` | INTEGER NOT NULL | Short lived, like 10 minutes. |
| `used_at` | INTEGER | |

### `oauth_accounts`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `user_id` | INTEGER NOT NULL | FK to `users.id`. |
| `provider` | TEXT NOT NULL | e.g. `google`, `microsoft`, `github` |
| `provider_id` | TEXT NOT NULL | External user id. |
| `created_at` | INTEGER NOT NULL | |
| UNIQUE | (provider, provider_id) | |

### `web_sessions`

Server-side session records for just the web dashboard.

| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT PK | Hash of cryptographically random session ID. The non-hashed one is stored as a cookie in the users browser. |
| `user_id` | INTEGER NOT NULL | FK to `users.id` |
| `created_at` | INTEGER NOT NULL | |
| `expires_at` | INTEGER NOT NULL | |
| `ip` | TEXT NOT NULL | IP at session creation, for basic fixation detection |
| `user_agent` | TEXT | |

Sessions are fixed-expiry only. There is no sliding window. A future change could be to create a new session if the user makes an authenticated request within 24 hours of expiry?

### `namespaces`

Each namespace is a user / organization. The namespace slug maps to an S3 path prefix (`slug/...`). A namespace is also the billable entity in SaaS mode. There is only ever one subscription per namespace.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `slug` | TEXT NOT NULL UNIQUE | Must be URL-safe and CLI-safe, cause it's used in S3 paths and CLI commands. Immutable for the user. |
| `owner_user_id` | INTEGER NOT NULL | FK to `users.id`. The human responsible. |
| `storage_used_bytes` | INTEGER NOT NULL DEFAULT 0 | Counter, updated with any modifications to namespace images. |
| `created_by_user_id` | INTEGER NOT NULL | FK to `users.id`. May be different than `owner_user_id` as ownership could be transferred. |
| `display_name` | TEXT | Display name for the namespace. All operations will still use `slug`, but when viewing the page, `display_name` will also be shown. |
| `created_at` | INTEGER NOT NULL | |
| `deleted_at` | INTEGER | Null = active |
| `purge_after` | INTEGER | When the server should begin sweeping hard-deletes, removing S3 objects. If NULL, don't delete. |
| `settings` | JSONB NOT NULL DEFAULT '{}' | |

`storage_used_bytes` must be updated in the same transaction that does any modification to any image tables / files. The check is performed against the billable storage bytes in SaaS mode, and skipped for self-hosted mode (assumed that the storage is just there).

Slugs are unique, and cannot be modified after creation. If a user deletes a slug, it won't be usable. The `owner_user_id` email could be used for some form of recovery of the slug name later.

### `namespace_members`

Many-to-many relationship between users and namespaces.

| Column | Type | Notes |
|--------|------|-------|
| `namespace_id` | INTEGER NOT NULL | FK to `namespaces.id`. |
| `user_id` | INTEGER NOT NULL | FK to `users.id`. |
| `role` | TEXT NOT NULL CHECK (role IN ('owner','admin','member')) | |
| `added_at` | INTEGER NOT NULL | |
| PRIMARY KEY | `(namespace_id, user_id)` | |

Roles gate web dashboard actions:

- `member`: Can view namespace and see / pull private VMs.
- `admin`: Can provision token, manage VM images, and manage members (excluding owner).
- `owner`: Full control, manages billing. There may only be 1 owner per namespace. Managed in the application layer to eventually support ownership transfer.

For CLI auth, membership alone grants pull access for personal tokens. Push requires a provisioned token regardless of role.

### `namespace_invites`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `namespace_id` | INTEGER NOT NULL | FK to `namespaces.id`. |
| `username` | TEXT NOT NULL COLLATE NOCASE | |
| `role` | TEXT NOT NULL CHECK (role IN ('admin','member')) | |
| `invited_by` | INTEGER NOT NULL | FK to `users.id`. |
| `created_at` | INTEGER NOT NULL | |
| `expires_at` | INTEGER NOT NULL | |
| `accepted_at` | INTEGER | Null = active |

Invites are accepted in the web dashboard, but an email is sent to the email of `username` instructing them to do so.

`username` must be unique to `namespace_id`.

### `api_tokens`

Authentication tokens for CLI and CI use.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `is_provisioned` | BOOLEAN NOT NULL CHECK | If `false`, is a personal token. |
| `token_hash` | BLOB NOT NULL UNIQUE | blake3 hash of the token (prefix stripped). |
| `token_prefix` | TEXT NOT NULL | First 8 chars of `vci_...` for UI identification |
| `name` | TEXT NOT NULL | Human label, e.g. "GitHub Actions" or "laptop" |
| `user_id` | INTEGER | NULL if `is_provisioned = true`. |
| `namespace_id` | INTEGER | NOT NULL if `is_provisioned = true`. |
| `scope` | INTEGER | NOT NULL if `is_provisioned = true`. 0=ReadOnly, 1=ReadWrite, 2=Maintain, 3=Admin. |
| `created_at` | INTEGER NOT NULL | |
| `last_used_at` | INTEGER | Updated on each successful auth resolution |
| `expires_at` | INTEGER | Default to created_at + 90 days. Nullable for non-expiring (should be discouraged). |
| `revoked_at` | INTEGER | Non-null = revoked, cannot be un-revoked |
| CHECK | | See constraint below |

```sql
CHECK (
  (is_provisioned = false AND user_id IS NOT NULL AND namespace_id IS NULL AND scope IS NULL) OR
  (is_provisioned = true AND namespace_id IS NOT NULL AND scope IS NOT NULL)
)
```

This constraint makes malformed tokens unrepresentable. A personal token always
has a user and never has a namespace or scope. A provisioned token always has a
namespace and scope.

The `scope` integer maps to the `TokenScope` enum:

- 0 = `ReadOnly` - pull, list, read metadata
- 1 = `ReadWrite` - push new images with specified visibility, create tags
- 2 = `Maintain` - modify existing images (change visibility, delete, toggle versioning, lock/unlock tags)
- 3 = `Admin` - manage namespace members, manage provisioned tokens, namespace settings

`expires_at` defaults to 90 days. Dashboard shows a warning at 14 days remaining. Tokens that expired aren't automatically deleted, but are disabled for an audit trail, being filtered out by auth resolution.

### `images`

A logical VM image. The actual bytes live in S3; this table tracks metadata.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `namespace_id` | INTEGER NOT NULL | FK to `namespaces.id` |
| `name` | TEXT NOT NULL | Image name, unique within namespace |
| `is_private` | BOOLEAN NOT NULL DEFAULT false | |
| `versioned` | BOOLEAN NOT NULL DEFAULT false | |
| `description` | TEXT | |
| `created_at` | INTEGER NOT NULL | |
| `deleted_at` | INTEGER | |
| `purge_after` | INTEGER | |

```sql
CREATE UNIQUE INDEX idx_images_ns_name_active ON images(namespace_id, name) WHERE deleted_at IS NULL;
```

It is possible to delete a VM image to re-use that name later on.

When `versioned = false` (the default), a push will overwrite the previous version. When `versioned = true`, a new push creates a new VM entry entirely, without deleting the old ones. This is configured based on plan/storage limits.

### `image_versions`

An immutable snapshot of a VM image's contents at a point in time.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `image_id` | INTEGER NOT NULL | FK to `images.id`. |
| `version` | TEXT | Identifier for the version. May not be `latest`. May be null. |
| `content_digest` | TEXT NOT NULL | blake3 hash of canonical manifest (sorted file paths + sha256 + sizes). |
| `total_bytes` | INTEGER NOT NULL | |
| `image_desc` | JSONB NOT NULL | Maps to a serialized `ImageDescription` entry. |
| `created_by_token_id` | INTEGER NOT NULL | FK to `api_tokens.id`. |
| `state` | TEXT NOT NULL CHECK (state IN ('uploading','ready','failed','deleting')) | Tracks upload lifecycle. If `uploading`, its not visible to pulls or web management yet. `failed` means it must be cleaned up. `deleting` is set to indicate it's being deleted from S3. |
| `pull_count` | INTEGER NOT NULL DEFAULT 0 | The amount of times this specific version has been pulled. |
| `created_at` | INTEGER NOT NULL | |
| `deleted_at` | INTEGER | |
| `purge_after` | INTEGER | |

The latest image version is the one that has the latest `created_at`.

`content_digest` enables two things. Firstly, clients can verify that the bits match, providing integrity verification. Secondly, if no change occurs for a push target, the push can be skipped. It is unique to an `image_id`.

`version` needs to be unique for `image_id`.

### `image_version_tags`

| Column | Type | Notes |
|--------|------|-------|
| `image_version_id` | INTEGER NOT NULL | FK to `image_versions.id` |
| `category` | TEXT NOT NULL | e.g. `os`, `arch`, `language`, `framework`, `toolchain`, `driver`. |
| `value` | TEXT NOT NULL | e.g. `Windows 11`, `arm64`, `Node.js` |
| PRIMARY KEY | `(image_version_id, value)` | |

If `category = 'arch'`, the possible values are `x86_64`, `arm64`, or `riscv64` for now.

### `image_aliases`

Allow assigning an alias to an image. Example `my-org/ubuntu:stable` would allow pinning to non-latest.

| Column | Type | Notes |
|--------|------|-------|
| `image_id` | INTEGER NOT NULL | FK to `images.id`. Stored to ensure no duplicate aliases across versions. |
| `image_version_id` | INTEGER NOT NULL | FK to `image_versions.id`. The actual relevant data. |
| `alias` | TEXT NOT NULL | e.g. `stable`, `production`, `nightly`. `latest` is not permitted. |
| PRIMARY KEY | `(image_id, alias)` | |

### `image_files`

Individual files within an image version. Each row is a durable record of an
object in S3.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `version_id` | INTEGER NOT NULL | FK to `image_versions.id` |
| `file_name` | TEXT NOT NULL | e.g. `disk.qcow2`, `OVMF_VARS_4M.fd` |
| `s3_object_path` | TEXT NOT NULL | Full S3 object. If versioned `{namespace_slug}/{image_name}/{version}/{file_name}`, otherwise `{namespace_slug}/{image_name}/{file_name}`. |
| `size_bytes` | INTEGER NOT NULL | |
| `sha256` | TEXT NOT NULL | Hex-encoded SHA-256 of the file contents |

### `multipart_uploads`

S3 multipart upload state.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `s3_key` | TEXT NOT NULL | |
| `s3_upload_id` | TEXT NOT NULL | From S3 CreateMultipartUpload response. |
| `version_id` | INTEGER NOT NULL | FK to `image_versions.id`. |
| `started_at` | INTEGER NOT NULL | |

On server startup, a sweep queries for rows where `started_at` was longer than a pre-determined maximum session time (maybe 24 hours?) and calls `AbortMultipartUpload` for each.

### `audit_log`

Append-only log of significant actions.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `actor_user_id` | INTEGER | Null if action was by a provisioned token with no user. |
| `actor_token_id` | INTEGER | Null if action was via web session. |
| `namespace_id` | INTEGER | Null for user-level actions. |
| `action` | TEXT NOT NULL | e.g. `image.push`, `token.create`, `member.add`, `billing.update`. |
| `target` | TEXT | Human-readable target, e.g. `namespace/ubuntu-node:latest`. |
| `ip` | TEXT | |
| `user_agent` | TEXT | |
| `at` | INTEGER NOT NULL | |

Doesn't use FKs so that any deleted entries in other tables will preserve the audit log.

Old audit logs can be deleted. Pull operations are not recorded in the audit log as those will account for the overwhelming majority of operations.

If `actor_user_id` is not null, but `namespace_id` is null, that's a user action that doesn't pertain to their VMs itself, such as billing info, MFA update, password setting, etc.

### `user_notifications`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `user_id` | INTEGER NOT NULL | |
| `namespace_id` | INTEGER | Null for user-level actions. |
| `kind` | TEXT NOT NULL | e.g. `token_expiry`, `storage_maxed`, `payment_failed`. |
| `title` | TEXT NOT NULL | |
| `body` | TEXT NOT NULL | |
| `link` | TEXT | Optional navigation link. |
| `created_at` | INTEGER NOT NULL | |
| `read_at` | INTEGER | Null means unread. |

Any notification that is `read_at` can be deleted from the db after some time (maybe 2 days?).

Notifications need to be de-duplicated at the application level to ensure not spamming the user with the same notification.

If `user_id` is not null, but `namespace_id` is null, that's a user action that doesn't pertain to their VMs itself, such as billing info, MFA update, password setting, etc.

### `plan_pricing` (SaaS only)

Static-ish plan definitions. Changed rarely, by developers, not by users.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `currency` | TEXT NOT NULL | ISO 4217: 'cad', 'usd', 'eur', 'cny'. |
| `base_cost` | INTEGER NOT NULL | The base price, required for minimum transaction for payment processors. Measured in smallest currency unit for `currency`, such as cents. |
| `base_gb_included` | INTEGER NOT NULL | The amount of GB included for the `base_cost`. |
| `extra_cost` | INTEGER NOT NULL | Cost for extra storage, measured in smallest currency unit for `currency`, such as cents. |
| `extra_gb_included` | INTEGER NOT NULL | The amount of GB included for every N charge of `extra_cost`. |

### `subscriptions` (SaaS only)

One active subscription for namespace. The third party payment processor is the source of truth for actual payment state, this just acts as a mirror for the dashboard and quota checks.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `namespace_id` | INTEGER NOT NULL UNIQUE | FK to `namespaces.id`. |
| `pricing_id` | INTEGER NOT NULL | FK to `plan_pricing.id`. |
| `status` | TEXT NOT NULL CHECK (status IN ('active','past_due','canceled')) | |
| `current_period_start` | INTEGER NOT NULL | |
| `current_period_end` | INTEGER NOT NULL | |
| `storage_cap_bytes` | INTEGER NOT NULL | What the user set in their plan, not considering any potential overage. |
| `peak_cap_bytes` | INTEGER NOT NULL | How many bytes of capacity was set or needed as the peak during this payment period, in denominations of `plan_pricing.base_gb_included` + `plan_pricing.extra_gb_included`. |
| `peak_storage_bytes` | INTEGER NOT NULL | How many bytes of capacity was actual used at maximum during the payment period, in denominations of `plan_pricing.base_gb_included` + `plan_pricing.extra_gb_included`. |
| `external_customer_id` | TEXT | Third party payment processor customer ID. |
| `external_subscription_id` | TEXT | Third party payment processor subscription ID. |

### `usage_events` (SaaS only)

Append-only ledger of billable events. The append-only property is the key security and audit feature: disputes are resolved against immutable history, not a counter that could have been modified.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `namespace_id` | INTEGER NOT NULL | FK to `namespaces.id` |
| `kind` | TEXT NOT NULL CHECK (kind IN ('storage_sample','push')) | |
| `bytes` | INTEGER NOT NULL | |
| `recorded_at` | INTEGER NOT NULL | |

Every write operation causes the `usage_events` to be updated.

### `invoices` (SaaS only)

Local mirror of payment processor invoices for dashboard display.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `subscription_id` | INTEGER NOT NULL | FK to `subscriptions.id` |
| `period_start` | INTEGER NOT NULL | |
| `period_end` | INTEGER NOT NULL | |
| `currency` | TEXT NOT NULL | ISO 4217: 'cad', 'usd', 'eur', 'cny' |
| `subtotal` | INTEGER NOT NULL | Measured in smallest currency unit for `currency`, such as cents. |
| `status` | TEXT NOT NULL CHECK (status IN ('draft','open','paid','void')) | |
| `external_invoice_id` | TEXT | Third party payment processor invoice ID |
