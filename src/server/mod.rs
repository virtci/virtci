// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self};

use tiny_http::{Response, StatusCode};

mod api;
mod auth;
mod db;
mod namespace;
mod session;
mod web_assets;

use session::Sessions;

use crate::server::db::{SQLiteDB, SQLiteDBOpenFile, SQLiteDBOpenParams};
use crate::VciGlobalPaths;

const DEFAULT_PORT: u16 = 6399;
const DEFAULT_S3_URLS: [&str; 1] = ["localhost:3900"];

pub struct Server {
    should_stop: Arc<AtomicBool>,
    _config: ServerConfig,
    _http_server: Arc<tiny_http::Server>,
    http_server_thread: Option<thread::JoinHandle<()>>,
    /// Does periodic cleanup sweeping
    cleanup_thread: Option<thread::JoinHandle<()>>,
    db: Arc<RwLock<SQLiteDB>>,
    pub sessions: Arc<Mutex<Sessions>>,
}

impl Server {
    pub fn new(config: ServerConfig, _paths: &VciGlobalPaths) -> anyhow::Result<Server> {
        let addr = format!("0.0.0.0:{}", config.port);

        let http_server: Arc<tiny_http::Server> =
            Arc::new(tiny_http::Server::http(&addr).map_err(|e| anyhow::anyhow!(e))?);
        let http_server_clone = http_server.clone();

        let should_stop = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(Mutex::new(Sessions::default()));

        let http_server_thread = {
            let should_stop_clone = should_stop.clone();
            let sessions_clone = sessions.clone();
            thread::spawn(move || {
                serve_web(
                    http_server_clone.as_ref(),
                    should_stop_clone.as_ref(),
                    &sessions_clone,
                )
            })
        };

        let cleanup_thread = {
            let should_stop_clone = should_stop.clone();
            let sessions_clone = sessions.clone();
            thread::spawn(move || run_periodic_cleanup(should_stop_clone.as_ref(), &sessions_clone))
        };

        let db_open_params = if let Some(db_path) = &config.db_path {
            if !db_path.is_dir() {
                return Err(anyhow::anyhow!(
                    "Expected directory for database path, not a file"
                ));
            }
            SQLiteDBOpenParams::File(SQLiteDBOpenFile {
                path: db_path.clone(),
            })
        } else {
            SQLiteDBOpenParams::Memory
        };
        let db = SQLiteDB::new(&db_open_params)?;

        println!("listening on port {}", config.port);

        return Ok(Server {
            should_stop,
            _config: config,
            _http_server: http_server,
            http_server_thread: Some(http_server_thread),
            cleanup_thread: Some(cleanup_thread),
            db,
            sessions,
        });
    }

    pub fn wait(mut self) {
        if let Some(http_thread) = self.http_server_thread.take() {
            http_thread.join().expect("Failed to join server thread");
        }
        if let Some(cleanup_thread) = self.cleanup_thread.take() {
            cleanup_thread.join().expect("Failed to join server thread");
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::SeqCst);
        thread::yield_now();
        if let Some(http_thread) = self.http_server_thread.take() {
            http_thread.join().expect("Failed to join thread");
        }
        if let Some(cleanup_thread) = self.cleanup_thread.take() {
            cleanup_thread.join().expect("Failed to join thread");
        }
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    pub port: u16,
    pub s3: Vec<String>,
    pub db_path: Option<PathBuf>,
}

fn serve_web(
    http_server: &tiny_http::Server,
    should_stop: &AtomicBool,
    sessions: &Arc<Mutex<Sessions>>,
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

fn run_periodic_cleanup(should_stop: &AtomicBool, sessions: &Arc<Mutex<Sessions>>) {
    const CLI_SESSION_DURATION_CHECK: std::time::Duration = std::time::Duration::from_mins(1);
    const CLI_SESSION_TIMEOUT_SECS: u64 = 120;
    let mut cli_session_timer = std::time::Duration::default();

    loop {
        let start = std::time::SystemTime::now();
        thread::sleep(std::time::Duration::from_millis(100));
        if should_stop.load(Ordering::SeqCst) {
            break;
        }
        let end = std::time::SystemTime::now();
        let elapsed = end.duration_since(start).expect("what");

        cli_session_timer += elapsed;

        if cli_session_timer >= CLI_SESSION_DURATION_CHECK {
            let mut lock = sessions.lock().expect("Failed to lock");
            (*lock).remove_stale_sessions(CLI_SESSION_TIMEOUT_SECS);
        }
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

        ServerConfig {
            port,
            s3,
            db_path: None,
        }
    }
}
