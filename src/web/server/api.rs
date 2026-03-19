// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
};
use tiny_http::{Request, Response, StatusCode};

use super::session::{SessionId, Sessions};

type ApiResponse = Response<std::io::Cursor<Vec<u8>>>;

pub fn handle_api(
    path: &str,
    request: &mut Request,
    sessions: &Arc<Mutex<Sessions>>,
) -> ApiResponse {
    match path {
        "api/health" => endpoint::health(),
        "api/auth/info" => endpoint::auth_info(),
        "api/session/heartbeat" => endpoint::session_heartbeat(request, sessions),
        //"api/vm/push/begin" => endpoint::vm_push_begin(request, sessions),
        _ => Response::from_data(b"not found".to_vec()).with_status_code(StatusCode(404)),
    }
}

use super::web_assets::content_type_header;

mod endpoint {
    use crate::vm_image::RemoteInfo;

    use super::*;

    pub fn health() -> ApiResponse {
        Response::from_string("ok")
            .with_header(content_type_header("text/plain"))
            .with_status_code(StatusCode(200))
    }

    pub fn auth_info() -> ApiResponse {
        Response::from_string(&*DEFAULT_AUTH_INFO_STR)
            .with_header(content_type_header("application/json"))
            .with_status_code(StatusCode(200))
    }

    pub fn session_heartbeat(
        request: &mut Request,
        sessions: &Arc<Mutex<Sessions>>,
    ) -> ApiResponse {
        // TODO Auth

        const READ_ERR_MESSAGE: &str = r#"
        {
            "type": "error",
            "error": "failed to read session heartbeat request"
        }
        "#;

        const PARSE_ERR_MESSAGE: &str = r#"
        {
            "type": "error",
            "error": "failed to parse session heartbeat request"
        }
        "#;

        let mut contents = String::new();
        if let Err(_) = request.as_reader().read_to_string(&mut contents) {
            return Response::from_string(READ_ERR_MESSAGE)
                .with_header(content_type_header("application/json"))
                .with_status_code(StatusCode(400));
        }

        match serde_json::from_str::<SessionHeartbeatRequest>(&contents) {
            Err(_) => {
                return Response::from_string(PARSE_ERR_MESSAGE)
                    .with_header(content_type_header("application/json"))
                    .with_status_code(StatusCode(400));
            }
            Ok(heartbeat) => {
                {
                    // update heartbeat time stamp
                    let mut lock = sessions.lock().expect("Failed to acquire mutex");
                    (*lock).touch_timestamp(heartbeat.session_id);
                }

                // why does tiny_http use generics for different response types :(
                return Response::from_string("{}")
                    .with_header(content_type_header("application/json"))
                    .with_status_code(StatusCode(204));
            }
        }
    }

    // pub fn vm_push_begin(
    //     request: &Request,
    //     sessions: &Arc<Mutex<Sessions>>,
    // ) -> ApiResponse {
    // }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthInfo {
    auth_required: bool,
}

impl Default for AuthInfo {
    fn default() -> AuthInfo {
        AuthInfo {
            auth_required: false,
        }
    }
}

// Serialize once to reduce any possible overhead
static DEFAULT_AUTH_INFO_STR: LazyLock<String> = LazyLock::new(|| {
    let auth_info = AuthInfo::default();
    serde_json::to_string(&auth_info).expect("What")
});

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionHeartbeatRequest {
    // r#type: String,
    session_id: SessionId,
}
