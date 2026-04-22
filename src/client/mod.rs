// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::net::TcpStream;
pub mod pull;
pub mod push;

// TODO make a basic HTTP client, using std::net::TcpStream

#[cfg(test)]
mod tests {
    use crate::server::{Server, ServerConfig};

    use super::*;

    #[test]
    fn test_health_endpoint() {
        let server = Server::new(
            ServerConfig {
                port: 9999,
                s3: Vec::default(),
                db_path: None,
            },
            &crate::VciGlobalPaths::default(),
        )
        .expect("How did this fail what");

        // TODO http client sends a request to "api/health", expects status 200 and text/plain "ok" as a response
    }
}
