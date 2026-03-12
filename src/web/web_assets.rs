// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use rust_embed::Embed;
use tiny_http::{Header, Response, StatusCode};

#[derive(Embed)]
#[folder = "web/dist"]
struct WebAssets;

pub fn serve_static(path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
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

pub fn content_type_header(mime: &str) -> Header {
    Header::from_bytes("Content-Type", mime).expect("valid content-type header")
}
