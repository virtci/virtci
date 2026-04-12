// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum TokenScope {
    /// Cannot `ReadWrite`, `Maintain`, or `Admin`. Lowest level of privilege.
    ReadOnly,
    /// Has `ReadOnly`, but not `Maintain` or `Admin`. Medium level of privilege.
    ReadWrite,
    /// Has `ReadOnly` and `ReadWrite`. Can modify VMs after the fact, including deleting them. High level of privilege.
    Maintain,
    /// Has `ReadOnly` and `ReadWrite`. Highest level of privilege. Can do anything for the specific permission type.2
    Admin,
}

impl TokenScope {
    pub fn has_readwrite(self) -> bool {
        match self {
            TokenScope::ReadOnly => false,
            TokenScope::ReadWrite | TokenScope::Maintain | TokenScope::Admin => true,
        }
    }

    pub fn has_admin(self) -> bool {
        match self {
            TokenScope::ReadOnly | TokenScope::ReadWrite | TokenScope::Maintain => false,
            TokenScope::Admin => true,
        }
    }
}

#[derive(Debug)]
pub struct TokenPermissions {
    /// Namespace specific vm.
    pub namespace_vm: TokenScope,
    /// ALL tokens must have at least `ReadOnly` for this,
    /// as everyone should be able to fetch global vms.
    pub global_vm: TokenScope,
}

#[derive(Debug)]
pub enum AuthContext {
    Authenticated {
        token_hash: blake3::Hash,
    },
    /// Generally only Anonymous in a self-hosted environment where credentials and stuff aren't important.
    Anonymous,
}

/// If the "vci_" prefix is present, strips it. It is the responsibility of the API endpoints to
/// ensure the prefix is present, but the endpoints are free to strip it themselves.
pub fn hash_auth_token(token: &str) -> blake3::Hash {
    blake3::hash(token.trim_start_matches("vci_").as_bytes())
}

pub fn auth_required() -> bool {
    // TODO check local config / env vars
    false
}

impl TokenPermissions {
    pub fn token_namespace_perms(_token: &str, _namespace: &str) -> TokenPermissions {
        // TODO actual SQLite check
        return TokenPermissions {
            namespace_vm: TokenScope::Admin,
            global_vm: TokenScope::Admin,
        };
    }

    pub fn token_global_perms(_token: &str) -> TokenPermissions {
        // TODO actual SQLite check
        return TokenPermissions {
            namespace_vm: TokenScope::Admin,
            global_vm: TokenScope::Admin,
        };
    }
}
