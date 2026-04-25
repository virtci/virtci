// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Request, Response, StatusCode};

use crate::server::db::{ApiTokenProvision, SQLiteDB};
use crate::vm_image::RemoteInfo;

use super::auth;
use super::session::{SessionId, Sessions};

type ApiResponse = Response<std::io::Cursor<Vec<u8>>>;

pub fn handle_api(
    path: &str,
    request: &mut Request,
    sessions: &Arc<Mutex<Sessions>>,
    db: &Arc<Mutex<SQLiteDB>>,
) -> ApiResponse {
    match path {
        "api/health" => endpoint::health(request),
        "api/auth/info" => endpoint::auth_info(request),
        "api/session/heartbeat" => endpoint::session_heartbeat(request, sessions),
        "api/vm/push/begin" => endpoint::vm_push_begin(request, sessions, db),
        "api/vm/push/end" => endpoint::vm_push_end(request, sessions, db),
        "api/vm/pull/begin" => endpoint::vm_pull_begin(request, sessions, db),
        // pull doesn't need an end as it's stateless
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

    use crate::server::{
        auth::AuthContext,
        session::{PushFile, PushSession, SessionAuthErr, SessionType},
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
    pub struct VmPushRequestFileInfo {
        /// File name with extension
        name: String,
        /// In bytes
        size: u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VmPushBeginRequest {
        /// Slug of the target namespace.
        namespace: String,
        /// VM name itself
        name: String,
        files: Vec<VmPushRequestFileInfo>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VmPushResponseFileInfo {
        file: String,
        upload_id: String,
        /// In bytes. Will be 64 MB, 128 MB, 256 MB, or 512 MB.
        part_size: u64,
        /// Presigned URLs
        part_urls: Vec<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct VmPushBeginResponse {
        session_id: SessionId,
        uploads: Vec<VmPushResponseFileInfo>,
    }

    pub fn vm_push_begin(
        request: &mut Request,
        sessions: &Arc<Mutex<Sessions>>,
        db: &Arc<Mutex<SQLiteDB>>,
    ) -> ApiResponse {
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
                // Single db lock spans token + namespace lookup, released before
                // `sessions.lock()`. No nesting, consistent lock ordering.
                let (auth, namespace) = if auth::auth_required() {
                    let token = auth_token
                        .as_ref()
                        .expect("check was earlier in the function");
                    if !token.starts_with("vci_") {
                        return api_json_str_response(
                            SessionAuthErr::Prefix.json_api_response(),
                            401,
                        );
                    }
                    let token_hash = auth::hash_auth_token(token);

                    let db_lock = db.lock().expect("db lock poisoned");
                    let info = match db_lock.api_token_info(token_hash.as_bytes()) {
                        Ok(info) => info,
                        Err(_) => return api_err_response!("auth token not recognized", 401),
                    };

                    if info.revoked_at.is_some() {
                        return api_err_response!("auth token has been revoked", 401);
                    }
                    if let Some(exp) = info.expires_at {
                        if RemoteInfo::now_secs() as i64 >= exp {
                            return api_err_response!("auth token has expired", 401);
                        }
                    }

                    let ns_info = match db_lock.namespace_by_slug(&push.namespace) {
                        Ok(info) => info,
                        Err(_) => return api_err_response!("namespace not found", 404),
                    };
                    drop(db_lock);

                    if ns_info.deleted_at.is_some() {
                        return api_err_response!("namespace has been deleted", 410);
                    }

                    if !info.scope.has_readwrite() {
                        return api_err_response!("token scope insufficient to push", 403);
                    }

                    match info.provision {
                        ApiTokenProvision::Namespace(token_ns_id) => {
                            if token_ns_id != ns_info.id {
                                return api_err_response!(
                                    "token is not scoped to the target namespace",
                                    403
                                );
                            }
                        }
                        ApiTokenProvision::User(token_uid) => {
                            if !(ns_info.personal && ns_info.owner_user_id == token_uid) {
                                return api_err_response!(
                                    "personal tokens can only push to their owner's personal namespace",
                                    403
                                );
                            }
                        }
                    }

                    (AuthContext::Authenticated { token_hash }, ns_info.slug)
                } else {
                    (AuthContext::Anonymous, push.namespace.clone())
                };

                let prefix = format!("{namespace}/{}", push.name);

                let files: Vec<PushFile> = push
                    .files
                    .iter()
                    .map(|f| {
                        let s3_path = format!("{prefix}/{}", f.name);
                        PushFile::new(s3_path, f.size) // TODO upload_id
                    })
                    .collect();

                let uploads: Vec<VmPushResponseFileInfo> = files
                    .iter()
                    .map(|f| VmPushResponseFileInfo {
                        file: f.s3_path.clone(),
                        upload_id: f.upload_id.clone(),
                        part_size: f.part_size,
                        part_urls: Vec::new(), // TODO generate presigned URLs
                    })
                    .collect();

                let push_session = PushSession {
                    namespace,
                    image_name: push.name,
                    files,
                };

                let session_id = {
                    let mut lock = sessions.lock().expect("Failed to acquire mutex");
                    (*lock).add_session(auth, SessionType::Push(push_session))
                };

                let response = VmPushBeginResponse {
                    session_id,
                    uploads,
                };

                return api_json_str_response(
                    &serde_json::to_string(&response).expect("How did this fail"),
                    200,
                );
            }
        }
    }

    pub fn vm_push_end(
        request: &mut Request,
        sessions: &Arc<Mutex<Sessions>>,
        db: &Arc<Mutex<SQLiteDB>>,
    ) -> ApiResponse {
        if request.method() != &Method::Post {
            return api_err_response!("endpoint 'api/vm/push/end' only supports POST", 405);
        }

        todo!()
    }

    pub fn vm_pull_begin(
        request: &mut Request,
        sessions: &Arc<Mutex<Sessions>>,
        db: &Arc<Mutex<SQLiteDB>>,
    ) -> ApiResponse {
        if request.method() != &Method::Get {
            return api_err_response!("endpoint 'api/vm/pull/begin' only supports GET", 405);
        }

        // validate, but allow for public image no matter any token, even a missing token
        // get signed s3 urls
        // update pull count, fine if failure
        // use non-egress fee providers, cause these files are MASSIVE

        todo!()
    }
}
