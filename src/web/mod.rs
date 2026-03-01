// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use rust_embed::Embed;
use tiny_http::{Header, Response, Server, StatusCode};

const DEFAULT_PORT: u16 = 8080;

#[derive(Embed)]
#[folder = "web/dist"]
struct WebAssets;

/// If `port` is not supplied, try to get the `VIRTCI_BACKEND_PORT` environment variable.
/// If THAT is not supplied, use `DEFAULT_PORT` which is 8080.
pub fn serve(port: Option<u16>) {
    // If the `port` is
    let port = port
        .or_else(|| {
            std::env::var("VIRTCI_BACKEND_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("0.0.0.0:{port}");
    let server = Server::http(&addr).unwrap_or_else(|e| {
        panic!("Failed to start HTTP server on {addr}: {e}");
    });

    println!("Web UI available at http://localhost:{port}");

    for request in server.incoming_requests() {
        let path = request.url().trim_start_matches('/');
        let path = path.split('?').next().unwrap_or(path);

        let response = if path.starts_with("api/") {
            handle_api(path)
        } else {
            serve_static(path)
        };

        let _ = request.respond(response);
    }
}

fn handle_api(path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    match path {
        "api/health" => Response::from_data(b"ok".to_vec())
            .with_header(content_type_header("text/plain"))
            .with_status_code(StatusCode(200)),
        _ => Response::from_data(b"not found".to_vec()).with_status_code(StatusCode(404)),
    }
}

fn serve_static(path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let (file, mime_path) = if path.is_empty() {
        (WebAssets::get("index.html"), "index.html")
    } else {
        let file = WebAssets::get(path);
        if file.is_some() {
            (file, path)
        } else {
            (WebAssets::get("index.html"), "index.html")
        }
    };

    match file {
        Some(file) => {
            let mime = mime_guess::from_path(mime_path).first_or_octet_stream();
            Response::from_data(file.data.to_vec())
                .with_header(content_type_header(mime.as_ref()))
                .with_status_code(StatusCode(200))
        }
        None => Response::from_data(b"not found".to_vec()).with_status_code(StatusCode(404)),
    }
}

fn content_type_header(mime: &str) -> Header {
    Header::from_bytes("Content-Type", mime).expect("valid content-type header")
}
