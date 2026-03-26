// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{vm_image::RemoteInfo, web::server::auth::AuthContext};

/// Only the 52 least significant bits are used, to ensure easy JSON serialization.
#[derive(Debug, Eq, Hash, PartialOrd, Ord, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub struct SessionId(i64);

impl SessionId {
    pub fn new_rand() -> SessionId {
        const RELEVANT_BITS: i64 = 0xFFFFFFFFFFFFF;
        let id: i64 = rand::random();
        return SessionId(id & RELEVANT_BITS);
    }
}

#[derive(Debug)]
pub enum SessionType {
    Pull,
    Push(PushSession),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PushSession {
    /// Account that owns the VM. If `None`, a VM is considered "globally accessible".
    pub account: Option<String>,
    /// Actual VM name. Duplicate `name` is not allowed per `account`.
    /// TODO override existing VM?
    pub name: String,
}

#[derive(Debug)]
struct StoredSession {
    auth: AuthContext,
    session_type: SessionType,
}

#[derive(Debug, Default)]
pub struct Sessions {
    sessions: HashMap<SessionId, StoredSession>,
    /// SOA with `timeout_timestamps`. Is sorted from lowest session id value to highest.
    timeout_ids: Vec<SessionId>,
    /// SOA with `timeout_ids`. Measured in seconds `RemoteInfo::now_secs()`.
    /// The cleanup thread should be able to traverse all entries as fast
    /// as possible, and traversing a hashmap through its iterator has poor cache coherency.
    /// Holding the mutex to check all entries is a rare operation compared to normal operations,
    /// but it's slow and will halt the others. On top of that, binary search is fast enough to
    /// find the right index for the heartbeat timestamp update.
    timeout_timestamps: Vec<u64>,
}

pub enum SessionAuthErr {
    /// Not an actual session
    NotASession,
    /// VirtCI auth tokens need "vci_" at the start
    Prefix,
    /// Use didn't supply a token but one was expected.
    MissingToken,
    /// The token used for the session does not match the supplied one.
    TokenMismatch,
}

impl Sessions {
    pub fn add_session(self: &mut Self, auth: AuthContext, session_type: SessionType) -> SessionId {
        let mut id = SessionId::new_rand();
        while self.sessions.contains_key(&id) {
            id = SessionId::new_rand();
        }

        self.sessions
            .insert(id, StoredSession { auth, session_type });

        // https://doc.rust-lang.org/std/vec/struct.Vec.html#method.binary_search
        // binary_search() returns an Err() containing the index where the element could be
        // inserted while maintaining order. Since it doesn't exist from the above check,
        // we use that.
        let insert_index = self
            .timeout_ids
            .binary_search(&id)
            .expect_err("Session id not have been in the vec");

        self.timeout_ids.insert(insert_index, id);
        self.timeout_timestamps
            .insert(insert_index, RemoteInfo::now_secs());

        return id;
    }

    pub fn touch_timestamp(self: &mut Self, id: SessionId) {
        if let Ok(index) = self.timeout_ids.binary_search(&id) {
            self.timeout_timestamps[index] = RemoteInfo::now_secs();
        }
    }

    pub fn remove_stale_sessions(self: &mut Self, timeout_secs: u64) {
        let mut indices_to_remove = Vec::<usize>::new();

        let now = RemoteInfo::now_secs();
        for (index, timestamp) in self.timeout_timestamps.iter().enumerate() {
            if now - timestamp > timeout_secs {
                indices_to_remove.push(index);
            }
        }

        for index in indices_to_remove {
            let session_id = self.timeout_ids[index];

            let _ = self.sessions.remove(&session_id);
            // TODO cleanup stale uploads from s3

            self.timeout_ids.remove(index);
            self.timeout_timestamps.remove(index);
        }
    }

    /// If session is anonymous, don't bother checking token.
    pub fn is_token_authorized_for_session(
        self: &Self,
        id: SessionId,
        token: Option<&String>,
    ) -> Result<(), SessionAuthErr> {
        if let Some(auth) = self.session_auth(id) {
            match auth {
                AuthContext::Anonymous => Ok(()),
                AuthContext::Authenticated { token_hash } => {
                    if let Some(token_str) = token {
                        if !token_str.starts_with("vci_") {
                            return Err(SessionAuthErr::Prefix);
                        }

                        let hashed_token = super::auth::hash_auth_token(token_str);
                        // constant time equality check, not vulnerable to timing attacks
                        if hashed_token.eq(token_hash) {
                            return Ok(());
                        }
                        return Err(SessionAuthErr::TokenMismatch);
                    } else {
                        return Err(SessionAuthErr::MissingToken);
                    }
                }
            }
        } else {
            return Err(SessionAuthErr::NotASession);
        }
    }

    pub fn session_auth<'a>(self: &'a Self, id: SessionId) -> Option<&'a AuthContext> {
        match self.sessions.get(&id) {
            Some(session_info) => Some(&session_info.auth),
            None => None,
        }
    }
}

impl SessionAuthErr {
    pub fn json_api_response(self: &Self) -> &str {
        match self {
            SessionAuthErr::NotASession => {
                r#"
                                {
                                    "type": "error",
                                    "error": "auth not a session"
                                }
                                "#
            }
            SessionAuthErr::Prefix => {
                r#"
                                {
                                    "type": "error",
                                    "error": "token should have 'vci_' prefix"
                                }
                                "#
            }
            SessionAuthErr::MissingToken => {
                r#"
                                {
                                    "type": "error",
                                    "error": "expected an auth token"
                                }
                                "#
            }
            SessionAuthErr::TokenMismatch => {
                r#"
                                {
                                    "type": "error",
                                    "error": "session is authenticated for a different token"
                                }
                                "#
            }
        }
    }
}
