//! HTTP/1.0 over the legacy TLS connection.
//!
//! Connects a TCP socket, runs the handshake, sends a close-delimited HTTP/1.0
//! request, and reads the response until the peer closes. HTTP/1.0 avoids the
//! chunked-encoding and `Expect: 100-continue` behaviour that the ancient IIS
//! stack on the EKENG appliance mishandles.

use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::error::TlsError;
use crate::handshake;
use crate::record::{Connection, CT_ALERT, CT_APPLICATION_DATA};
use crate::{HttpResponse, Method};

/// Maximum response body accepted.
const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024;

/// Ports for which the `Host` header omits the port number.
const STANDARD_PORTS: [u16; 2] = [80, 443];

/// Perform one HTTP request over a freshly established legacy TLS connection.
pub(crate) fn request(
    method: Method,
    url: &str,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<HttpResponse, TlsError> {
    let target = Target::parse(url)?;
    let timeout_secs = timeout.as_secs().max(1);

    let stream = connect(&target, timeout)?;
    let mut conn = Connection::new(stream, target.host.clone(), target.port, timeout_secs);

    log::debug!(
        "legacy TLS handshake with {}:{} (TLS 1.0 + RC4)",
        target.host,
        target.port
    );
    handshake::perform(&mut conn, timeout)?;
    log::warn!(
        "using legacy TLS (TLS 1.0 + RC4) for {}:{}; this cipher suite is deprecated",
        target.host,
        target.port
    );

    let request_bytes = build_request(method, &target, body, extra_headers)?;
    conn.write(CT_APPLICATION_DATA, &request_bytes)?;

    let raw = read_response(&mut conn, &target, timeout)?;
    parse_response(&raw, &target)
}

/// A parsed request target.
struct Target {
    host: String,
    port: u16,
    path: String,
}

impl Target {
    /// Parse an `https://host[:port][/path][?query]` URL.
    fn parse(url: &str) -> Result<Self, TlsError> {
        let rest = url.strip_prefix("https://").ok_or_else(|| {
            TlsError::InvalidUrl(format!("legacy TLS requires an https URL: {url}"))
        })?;

        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };

        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            // IPv6 literal: `[addr]` or `[addr]:port`. A plain rsplit on ':'
            // would split inside the address, so parse the brackets explicitly.
            let (addr, after) = rest.split_once(']').ok_or_else(|| {
                TlsError::InvalidUrl(format!("unterminated IPv6 literal in URL: {url}"))
            })?;
            let port = match after.strip_prefix(':') {
                Some(p) => p
                    .parse::<u16>()
                    .map_err(|_| TlsError::InvalidUrl(format!("invalid port in URL: {url}")))?,
                None if after.is_empty() => 443,
                None => {
                    return Err(TlsError::InvalidUrl(format!(
                        "unexpected text after IPv6 literal in URL: {url}"
                    )))
                }
            };
            (addr.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => {
                    let port = p
                        .parse::<u16>()
                        .map_err(|_| TlsError::InvalidUrl(format!("invalid port in URL: {url}")))?;
                    (h.to_string(), port)
                }
                None => (authority.to_string(), 443),
            }
        };

        if host.is_empty() {
            return Err(TlsError::InvalidUrl(format!("URL has no host: {url}")));
        }

        // The request line needs an absolute path; a bare query gets a "/" root.
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };

        Ok(Self { host, port, path })
    }

    /// The `Host` header value, including the port only when non-standard.
    fn host_header(&self) -> String {
        // An IPv6 literal must be bracketed in a Host header (RFC 7230 section 5.4).
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if STANDARD_PORTS.contains(&self.port) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

fn connect(target: &Target, timeout: Duration) -> Result<TcpStream, TlsError> {
    let addrs = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|source| TlsError::Connect {
            host: target.host.clone(),
            port: target.port,
            source,
        })?;

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                // The read/write timeout underpins every deadline in this module.
                // If the OS refuses it, fail loud rather than silently fall back
                // to a socket that can block forever.
                let set_timeout = stream
                    .set_read_timeout(Some(timeout))
                    .and_then(|()| stream.set_write_timeout(Some(timeout)));
                if let Err(source) = set_timeout {
                    return Err(TlsError::Connect {
                        host: target.host.clone(),
                        port: target.port,
                        source,
                    });
                }
                stream.set_nodelay(true).ok(); // latency hint only; non-fatal
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }

    let source = last_err.unwrap_or_else(|| ErrorKind::AddrNotAvailable.into());
    if matches!(source.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        Err(TlsError::Timeout {
            host: target.host.clone(),
            port: target.port,
            timeout_secs: timeout.as_secs().max(1),
        })
    } else {
        Err(TlsError::Connect {
            host: target.host.clone(),
            port: target.port,
            source,
        })
    }
}

fn build_request(
    method: Method,
    target: &Target,
    body: Option<&[u8]>,
    extra_headers: &[(&str, &str)],
) -> Result<Vec<u8>, TlsError> {
    use std::fmt::Write as _;

    // Writes into a String are infallible, so the fmt::Result is discarded.
    let mut head = String::new();
    let _ = write!(head, "{} {} HTTP/1.0\r\n", method.as_str(), target.path);
    let host_header = target.host_header();
    let host_value = validate_header("Host", &host_header)?;
    let _ = write!(head, "Host: {host_value}\r\n");
    head.push_str("Connection: close\r\n");
    if let Some(b) = body {
        let _ = write!(head, "Content-Length: {}\r\n", b.len());
    }
    for (name, value) in extra_headers {
        let value = validate_header(name, value)?;
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("\r\n");

    let mut request = head.into_bytes();
    if let Some(b) = body {
        request.extend_from_slice(b);
    }
    Ok(request)
}

/// Reject header values with embedded CR/LF to prevent header injection (CWE-113).
///
/// Raw HTTP construction makes this critical -- unlike a hardened HTTP client, we
/// build the request bytes by hand.
fn validate_header<'a>(name: &str, value: &'a str) -> Result<&'a str, TlsError> {
    if value.contains(['\r', '\n']) {
        Err(TlsError::Protocol(format!(
            "HTTP header {name} contains invalid CR/LF characters"
        )))
    } else {
        Ok(value)
    }
}

/// Read the full response, close-delimited, enforcing the size and time limits.
fn read_response(
    conn: &mut Connection,
    target: &Target,
    timeout: Duration,
) -> Result<Vec<u8>, TlsError> {
    let deadline = Instant::now() + timeout;
    let mut raw = Vec::new();

    loop {
        if Instant::now() > deadline {
            return Err(TlsError::Timeout {
                host: target.host.clone(),
                port: target.port,
                timeout_secs: timeout.as_secs().max(1),
            });
        }

        let Some(record) = conn.read()? else {
            break; // clean or abrupt TCP close ends the HTTP/1.0 body
        };

        match record.content_type {
            CT_APPLICATION_DATA => {
                raw.extend_from_slice(&record.payload);
                if raw.len() > MAX_RESPONSE_SIZE {
                    return Err(TlsError::ResponseTooLarge {
                        host: target.host.clone(),
                        port: target.port,
                        limit: MAX_RESPONSE_SIZE,
                    });
                }
            }
            CT_ALERT => {
                let level = record.payload.first().copied().unwrap_or(0);
                let description = record.payload.get(1).copied().unwrap_or(0);
                if description == 0 {
                    break; // close_notify: clean end of stream
                }
                if level == 2 {
                    return Err(TlsError::Protocol(format!("fatal TLS alert {description}")));
                }
                // A non-fatal, non-close alert: tolerate and keep reading.
            }
            // Renegotiation (CT_HANDSHAKE) or other post-handshake records are
            // not expected; ignore them rather than aborting a completed response.
            _ => {}
        }
    }

    Ok(raw)
}

/// Split an HTTP/1.0 response into status, headers, and body.
fn parse_response(raw: &[u8], target: &Target) -> Result<HttpResponse, TlsError> {
    let header_end = find_subsequence(raw, b"\r\n\r\n").ok_or_else(|| {
        TlsError::Protocol(format!(
            "invalid HTTP response from {}:{} (no header terminator)",
            target.host, target.port
        ))
    })?;

    let head = String::from_utf8_lossy(&raw[..header_end]);
    let body = raw[header_end + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| TlsError::Protocol("empty HTTP response".into()))?;

    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            TlsError::Protocol(format!("cannot parse HTTP status line: {status_line:?}"))
        })?;
    let reason = parts.collect::<Vec<_>>().join(" ");

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    Ok(HttpResponse {
        status,
        reason,
        headers,
        body,
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_with_port_and_path() {
        let t = Target::parse("https://ca.gov.am:8080/SAPIWS/DSS.asmx").unwrap();
        assert_eq!(t.host, "ca.gov.am");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/SAPIWS/DSS.asmx");
        assert_eq!(t.host_header(), "ca.gov.am:8080");
    }

    #[test]
    fn parse_url_defaults() {
        let t = Target::parse("https://example.com").unwrap();
        assert_eq!(t.port, 443);
        assert_eq!(t.path, "/");
        assert_eq!(t.host_header(), "example.com");
    }

    #[test]
    fn parse_url_rejects_http() {
        assert!(Target::parse("http://example.com").is_err());
    }

    #[test]
    fn parse_ipv6_literal_with_port() {
        let t = Target::parse("https://[2001:db8::1]:8080/x").unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/x");
        // The Host header must re-bracket the IPv6 literal.
        assert_eq!(t.host_header(), "[2001:db8::1]:8080");
    }

    #[test]
    fn parse_ipv6_literal_default_port() {
        let t = Target::parse("https://[::1]").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 443);
        assert_eq!(t.host_header(), "[::1]");
    }

    #[test]
    fn parse_ipv6_unterminated_is_rejected() {
        assert!(Target::parse("https://[::1:8080/x").is_err());
    }

    #[test]
    fn header_injection_rejected() {
        assert!(validate_header("X", "ok").is_ok());
        assert!(validate_header("X", "bad\r\nInjected: 1").is_err());
    }

    #[test]
    fn parse_response_extracts_parts() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\nhello body";
        let target = Target::parse("https://h/").unwrap();
        let resp = parse_response(raw, &target).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.body, b"hello body");
        assert_eq!(resp.header("content-type"), Some("text/xml"));
    }
}
