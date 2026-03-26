// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Request, Response, StatusCode};

use super::auth;
use super::session::{SessionId, Sessions};

type ApiResponse = Response<std::io::Cursor<Vec<u8>>>;

pub fn handle_api(
    path: &str,
    request: &mut Request,
    sessions: &Arc<Mutex<Sessions>>,
) -> ApiResponse {
    match path {
        "api/health" => endpoint::health(request),
        "api/auth/info" => endpoint::auth_info(request),
        "api/session/heartbeat" => endpoint::session_heartbeat(request, sessions),
        "api/vm/push/begin" => endpoint::vm_push_begin(request, sessions),
        _ => Response::from_data(b"not found".to_vec()).with_status_code(StatusCode(404)),
    }
}

/// Auth tokens are stored in the `Authorization` or `authorization` header, and is prefixed with "Bearer".
fn extract_bearer_token(request: &Request) -> Option<String> {
    for header in request.headers() {
        if header.field.equiv("Authorization") {
            let value = header.value.as_str();
            if let Some(token) = value.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn api_json_str_response(json_msg: &str, status_code: u16) -> ApiResponse {
    Response::from_string(json_msg)
        .with_header(content_type_header("application/json"))
        .with_status_code(StatusCode(status_code))
}

/// Takes a message as a string literal, and a status code as an expression, creating an API response.
///
/// Example usage:
/// ```
/// api_err_response!("auth token required", 401)
/// ```
macro_rules! api_err_response {
    ($msg:literal, $status:expr) => {{
        const JSON_BODY: &str = concat!("{", r#"\"type\":\"error\",\"error\":\""#, $msg, "\"}");
        Response::from_string(JSON_BODY)
            .with_header(content_type_header("application/json"))
            .with_status_code(StatusCode($status))
    }};
}

use super::web_assets::content_type_header;

mod endpoint {
    use tiny_http::Method;

    use crate::web::server::{
        auth::AuthContext,
        session::{PushSession, SessionAuthErr, SessionType},
    };

    use super::*;

    pub fn health(request: &Request) -> ApiResponse {
        if request.method() != &Method::Get {
            return api_err_response!("endpoint 'api/health' only supports GET", 405);
        }

        Response::from_string("ok")
            .with_header(content_type_header("text/plain"))
            .with_status_code(StatusCode(200))
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct AuthInfoResponse {
        auth_required: bool,
    }

    impl Default for AuthInfoResponse {
        fn default() -> AuthInfoResponse {
            AuthInfoResponse {
                auth_required: auth::auth_required(),
            }
        }
    }

    // Serialize once to reduce any possible overhead
    static DEFAULT_AUTH_INFO_STR: LazyLock<String> = LazyLock::new(|| {
        let auth_info = AuthInfoResponse::default();
        serde_json::to_string(&auth_info).expect("What")
    });

    pub fn auth_info(request: &Request) -> ApiResponse {
        if request.method() != &Method::Get {
            return api_err_response!("endpoint 'api/auth/info' only supports GET", 405);
        }

        api_json_str_response(&*DEFAULT_AUTH_INFO_STR, 200)
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct SessionHeartbeatRequest {
        // r#type: String,
        session_id: SessionId,
    }

    pub fn session_heartbeat(
        request: &mut Request,
        sessions: &Arc<Mutex<Sessions>>,
    ) -> ApiResponse {
        if request.method() != &Method::Post {
            return api_err_response!("endpoint 'api/session/heartbeat' only supports POST", 405);
        }

        let auth_token = extract_bearer_token(request);
        if auth_token.is_none() && super::super::auth::auth_required() {
            return api_err_response!("auth token required", 401);
        }

        let mut contents = String::new();
        if let Err(_) = request.as_reader().read_to_string(&mut contents) {
            return api_err_response!("failed to read session heartbeat request", 400);
        }

        match serde_json::from_str::<SessionHeartbeatRequest>(&contents) {
            Err(_) => {
                return api_err_response!("failed to parse session heartbeat request", 400);
            }
            Ok(heartbeat) => {
                {
                    // update heartbeat time stamp
                    let mut lock = sessions.lock().expect("Failed to acquire mutex");
                    match (*lock)
                        .is_token_authorized_for_session(heartbeat.session_id, auth_token.as_ref())
                    {
                        Ok(_) => (*lock).touch_timestamp(heartbeat.session_id),
                        Err(e) => {
                            return api_json_str_response(e.json_api_response(), 401);
                        }
                    }
                }

                // why does tiny_http use generics for different response types :(
                return api_json_str_response("{}", 204);
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VmPushBeginRequest {
        push: PushSession,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VmPushBeginResponse {
        // r#type: String,
        session_id: SessionId,
    }

    pub fn vm_push_begin(request: &mut Request, sessions: &Arc<Mutex<Sessions>>) -> ApiResponse {
        if request.method() != &Method::Post {
            return api_err_response!("endpoint 'api/vm/push/begin' only supports POST", 405);
        }

        let auth_token = extract_bearer_token(request);
        if auth_token.is_none() && auth::auth_required() {
            return api_err_response!("auth token required", 401);
        }

        let mut contents = String::new();
        if let Err(_) = request.as_reader().read_to_string(&mut contents) {
            return api_err_response!("failed to read vm push begin request", 400);
        }

        match serde_json::from_str::<VmPushBeginRequest>(&contents) {
            Err(_) => {
                return api_err_response!("failed to parse vm push begin request", 400);
            }
            Ok(push) => {
                let session_id = {
                    let auth = if auth::auth_required() {
                        let token = auth_token
                            .as_ref()
                            .expect("check was earlier in the function");
                        if !token.starts_with("vci_") {
                            return api_json_str_response(
                                SessionAuthErr::Prefix.json_api_response(),
                                401,
                            );
                        }
                        if let Some(account) = &push.push.account {
                            let perms =
                                auth::TokenPermissions::token_account_perms(&token, &account);
                            if perms.account_vm.has_readwrite() {
                                AuthContext::Authenticated {
                                    token_hash: auth::hash_auth_token(&token),
                                }
                            } else {
                                return api_err_response!(
                                    "token does not have write permissions for account",
                                    403
                                );
                            }
                        } else {
                            let perms = auth::TokenPermissions::token_global_perms(&token);
                            if perms.global_vm.has_readwrite() {
                                AuthContext::Authenticated {
                                    token_hash: auth::hash_auth_token(&token),
                                }
                            } else {
                                return api_err_response!(
                                    "token does not have write permissions for global",
                                    403
                                );
                            }
                        }
                    } else {
                        AuthContext::Anonymous
                    };

                    let mut lock = sessions.lock().expect("Failed to acquire mutex");

                    (*lock).add_session(
                        auth,
                        SessionType::Push(PushSession {
                            account: push.push.account,
                            name: push.push.name,
                        }),
                    )
                };

                let response = VmPushBeginResponse { session_id };

                return api_json_str_response(
                    &serde_json::to_string(&response).expect("How did this fail"),
                    200,
                );
            }
        }
    }
}
