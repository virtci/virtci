// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use tiny_http::{Response, Server, StatusCode};

use super::web_assets;

const DEFAULT_PORT: u16 = 6399;
const DEFAULT_S3_URLS: [&str; 1] = ["localhost:3900"];

#[derive(Debug)]
pub struct ServerConfig {
    pub port: u16,
    pub s3: Vec<String>,
}

pub fn serve(config: &ServerConfig) {
    let addr = format!("0.0.0.0:{}", config.port);
    let server = Server::http(&addr).unwrap_or_else(|e| {
        panic!("Failed to start HTTP server on {addr}: {e}");
    });

    println!("Web UI available at localhost:{}", config.port);

    for request in server.incoming_requests() {
        let path = request.url().trim_start_matches('/');
        let path = path.split('?').next().unwrap_or(path);

        let response = if path.starts_with("api/") {
            handle_api(path)
        } else {
            web_assets::serve_static(path)
        };

        let _ = request.respond(response);
    }
}

fn handle_api(path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    match path {
        "api/health" => Response::from_data(b"ok".to_vec())
            .with_header(web_assets::content_type_header("text/plain"))
            .with_status_code(StatusCode(200)),
        _ => Response::from_data(b"not found".to_vec()).with_status_code(StatusCode(404)),
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
