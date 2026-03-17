// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self};

use anyhow::Context;
use tiny_http::{Response, StatusCode};

use crate::vm_image::RemoteInfo;

mod api;
mod web_assets;

const DEFAULT_PORT: u16 = 6399;
const DEFAULT_S3_URLS: [&str; 1] = ["localhost:3900"];

pub struct Server {
    should_stop: Arc<AtomicBool>,
    _config: ServerConfig,
    _http_server: Arc<tiny_http::Server>,
    http_server_thread: Option<thread::JoinHandle<()>>,
    sessions: Arc<Mutex<HashMap<api::SessionId, u64>>>,
}

impl Server {
    pub fn new(config: ServerConfig) -> anyhow::Result<Server> {
        let addr = format!("0.0.0.0:{}", config.port);

        let http_server: Arc<tiny_http::Server> =
            Arc::new(tiny_http::Server::http(&addr).map_err(|e| anyhow::anyhow!(e))?);
        let http_server_clone = http_server.clone();

        let should_stop = Arc::new(AtomicBool::new(false));
        let should_stop_clone = should_stop.clone();

        let sessions = Arc::new(Mutex::new(HashMap::<api::SessionId, u64>::default()));
        let sessions_clone = sessions.clone();

        let http_server_thread = thread::spawn(move || {
            serve_web(
                http_server_clone.as_ref(),
                should_stop_clone.as_ref(),
                &sessions_clone,
            )
        });

        return Ok(Server {
            should_stop,
            _config: config,
            _http_server: http_server,
            http_server_thread: Some(http_server_thread),
            sessions,
        });
    }

    pub fn add_session(self: &Self, id: api::SessionId) {
        let mut lock = self.sessions.lock().expect("what");
        (*lock).insert(id, RemoteInfo::now_secs());
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::SeqCst);
        thread::yield_now();
        if let Some(http_thread) = self.http_server_thread.take() {
            http_thread.join().expect("Failed to join thread");
        }
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    pub port: u16,
    pub s3: Vec<String>,
}

fn serve_web(
    http_server: &tiny_http::Server,
    should_stop: &AtomicBool,
    sessions: &Arc<Mutex<HashMap<api::SessionId, u64>>>,
) {
    for request in http_server.incoming_requests() {
        let mut request = request;
        if should_stop.load(Ordering::SeqCst) {
            break;
        }
        let path = request.url().trim_start_matches('/');
        let path = path.split('?').next().unwrap_or(path);
        let mut path_buf: [u8; 64] = [0; 64]; // need to then do a mutable borrow of request

        if path.len() > path_buf.len() {
            let _ = request
                .respond(Response::from_string("route too long").with_status_code(StatusCode(404)));
            continue;
        }

        path_buf[..path.len()].copy_from_slice(path.as_bytes());

        let response = if path.starts_with("api/") {
            api::handle_api(
                str::from_utf8(&path_buf[..path.len()]).expect("HUH"),
                &mut request,
                sessions,
            )
        } else {
            web_assets::serve_static(path)
        };

        let _ = request.respond(response);
    }
}

impl Default for ServerConfig {
    /// Load environment variable overrides, or just defaults if the env variables are not set.
    fn default() -> ServerConfig {
        let port = match std::env::var("VIRTCI_BACKEND_PORT") {
            Ok(val) => val.parse::<u16>().unwrap_or(DEFAULT_PORT),
            Err(_) => DEFAULT_PORT,
        };

        let s3 = {
            if let Ok(val) = std::env::var("VIRTCI_S3_URLS") {
                let url_split = val.split(' ');
                let mut vec = Vec::<String>::new();
                for url in url_split {
                    vec.push(url.to_string());
                }
                vec
            } else {
                let mut vec = Vec::<String>::new();
                for url in DEFAULT_S3_URLS {
                    vec.push(url.to_string());
                }
                vec
            }
        };

        ServerConfig { port, s3 }
    }
}
