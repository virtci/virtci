// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::vm_image::RemoteInfo;

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
    /// Account that owns the VM.
    pub account: String,
    /// Actual VM name. Duplicate `name` is not allowed per `account`.
    /// TODO override existing VM?
    pub name: String,
}

#[derive(Debug)]
struct StoredSession {
    // TODO auth
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

impl Sessions {
    pub fn add_session(self: &mut Self, session_type: SessionType) -> SessionId {
        let mut id = SessionId::new_rand();
        while self.sessions.contains_key(&id) {
            id = SessionId::new_rand();
        }

        self.sessions.insert(id, StoredSession { session_type });

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
}
