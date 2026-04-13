// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamespaceSettings {
    #[serde(default)]
    default_private_new_vms: bool,
    #[serde(default)]
    require_member_mfa: bool,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    allows_versioning: bool,
    /// To avoid users accidentally getting massive charges, this should be false by default. The overage rate is consistent.
    #[serde(default)]
    allows_overage: bool,
    #[serde(default)]
    soft_delete_retention_days: i32,
}

impl Default for NamespaceSettings {
    fn default() -> NamespaceSettings {
        NamespaceSettings {
            default_private_new_vms: false,
            require_member_mfa: false,
            description: None,
            allows_versioning: false,
            allows_overage: false,
            soft_delete_retention_days: 7,
        }
    }
}
