use std::net::TcpListener;

const PORT_RANGE_START: u16 = 50000;
const PORT_RANGE_END: u16 = 60000;

/// find available TCP port for SSH
pub fn find_available_port() -> Option<u16> {
    for port in PORT_RANGE_START..=PORT_RANGE_END {
        if is_port_available(port) {
            return Some(port);
        }
    }
    return None;
}

fn is_port_available(port: u16) -> bool {
    return TcpListener::bind(("127.0.0.1", port)).is_ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_available_port() {
        let port = find_available_port();
        assert!(port.is_some());
        let port = port.unwrap();
        assert!(port >= PORT_RANGE_START && port <= PORT_RANGE_END);
    }

    #[test]
    fn test_port_is_available() {
        let port = find_available_port().unwrap();
        let _listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert!(!is_port_available(port));
    }
}
