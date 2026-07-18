//! The TLS 1.0 record layer for stream ciphers (RC4) with an HMAC MAC.
//!
//! Handles framing (`type || version || length || fragment`), the per-direction
//! RC4 keystream, sequence numbers, and the record MAC computed over
//! `seq_num || type || version || length || fragment` (RFC 2246 section 6.2.3.1).
//! Only the two RC4 cipher suites are supported, so the bulk cipher is always
//! RC4-128; the MAC algorithm is MD5 (suite `0x0004`) or SHA-1 (`0x0005`).

use std::io::{Read, Write};
use std::net::TcpStream;

use hmac::{Hmac, Mac};
use md5::Md5;
use rc4::consts::U16;
use rc4::{KeyInit, Rc4 as Rc4Cipher, StreamCipher};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::error::TlsError;

/// Negotiated TLS version. We advertise and speak TLS 1.0 exclusively.
pub(crate) const TLS_VERSION: [u8; 2] = [3, 1];

/// Maximum plaintext fragment per record (2^14, RFC 2246 section 6.2.1).
pub(crate) const MAX_FRAGMENT: usize = 16384;

/// Maximum ciphertext we will accept in a single record: plaintext limit plus
/// the 2048-byte expansion budget the spec allows for MAC and padding.
const MAX_CIPHERTEXT: usize = MAX_FRAGMENT + 2048;

// Record content types.
pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

/// MAC algorithm of the negotiated cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacAlg {
    Md5,
    Sha1,
}

impl MacAlg {
    /// MAC output length in bytes.
    pub(crate) fn output_len(self) -> usize {
        match self {
            MacAlg::Md5 => 16,
            MacAlg::Sha1 => 20,
        }
    }
}

/// A decrypted record handed back to the caller.
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) content_type: u8,
    pub(crate) payload: Vec<u8>,
}

/// RC4 keystream generator for one direction, wrapping the `rc4` crate so the
/// fixed 16-byte key size and stateful keystream stay encapsulated.
struct Rc4 {
    inner: Rc4Cipher<U16>,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        Self {
            inner: <Rc4Cipher<U16> as KeyInit>::new_from_slice(key)
                .expect("RC4-128 key is always 16 bytes"),
        }
    }

    /// XOR `buf` with the next keystream bytes (encrypt and decrypt are identical).
    fn process(&mut self, buf: &mut [u8]) {
        self.inner.apply_keystream(buf);
    }
}

/// Per-direction cipher state, active only after the corresponding
/// ChangeCipherSpec. Before that, records are sent and received in the clear.
struct CipherState {
    rc4: Rc4,
    mac_key: Vec<u8>,
    mac_alg: MacAlg,
    seq: u64,
}

impl CipherState {
    fn new(enc_key: &[u8], mac_key: &[u8], mac_alg: MacAlg) -> Self {
        Self {
            rc4: Rc4::new(enc_key),
            mac_key: mac_key.to_vec(),
            mac_alg,
            seq: 0,
        }
    }
}

/// A framed TLS 1.0 connection over a TCP stream.
///
/// Owns the socket and both directional cipher states. The handshake code drives
/// it: sending cleartext handshake records, activating ciphers on ChangeCipherSpec,
/// then exchanging encrypted records.
pub(crate) struct Connection {
    stream: TcpStream,
    host: String,
    port: u16,
    timeout_secs: u64,
    read_state: Option<CipherState>,
    write_state: Option<CipherState>,
}

impl Connection {
    pub(crate) fn new(stream: TcpStream, host: String, port: u16, timeout_secs: u64) -> Self {
        Self {
            stream,
            host,
            port,
            timeout_secs,
            read_state: None,
            write_state: None,
        }
    }

    /// The peer's host and port, for error messages.
    pub(crate) fn peer(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }

    /// Activate the read (server->client) cipher after the server's ChangeCipherSpec.
    pub(crate) fn activate_read(&mut self, enc_key: &[u8], mac_key: &[u8], mac_alg: MacAlg) {
        self.read_state = Some(CipherState::new(enc_key, mac_key, mac_alg));
    }

    /// Activate the write (client->server) cipher after our ChangeCipherSpec.
    pub(crate) fn activate_write(&mut self, enc_key: &[u8], mac_key: &[u8], mac_alg: MacAlg) {
        self.write_state = Some(CipherState::new(enc_key, mac_key, mac_alg));
    }

    /// Write one record, fragmenting `data` into `MAX_FRAGMENT`-sized records.
    /// An empty payload still emits one (empty) record, as required for e.g. an
    /// empty client Certificate message body carrier.
    pub(crate) fn write(&mut self, content_type: u8, data: &[u8]) -> Result<(), TlsError> {
        if data.is_empty() {
            return self.write_one(content_type, data);
        }
        for chunk in data.chunks(MAX_FRAGMENT) {
            self.write_one(content_type, chunk)?;
        }
        Ok(())
    }

    fn write_one(&mut self, content_type: u8, plaintext: &[u8]) -> Result<(), TlsError> {
        let mut fragment = plaintext.to_vec();

        if let Some(state) = &mut self.write_state {
            let mac = compute_mac(
                state.mac_alg,
                &state.mac_key,
                state.seq,
                content_type,
                TLS_VERSION,
                &fragment,
            );
            state.seq = state.seq.wrapping_add(1);
            fragment.extend_from_slice(&mac);
            state.rc4.process(&mut fragment);
        }

        let len = u16::try_from(fragment.len())
            .map_err(|_| TlsError::Protocol("outgoing record exceeds 65535 bytes".into()))?;

        let mut record = Vec::with_capacity(5 + fragment.len());
        record.push(content_type);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(&fragment);
        self.write_all(&record)
    }

    /// Read one record, decrypting and MAC-verifying if the read cipher is active.
    ///
    /// Returns `Ok(None)` on a clean EOF at a record boundary: legacy IIS closes
    /// the TCP connection without a close_notify alert, so a bare EOF here is a
    /// normal end-of-stream rather than an error.
    pub(crate) fn read(&mut self) -> Result<Option<Record>, TlsError> {
        let Some(header) = self.read_header()? else {
            return Ok(None);
        };
        let content_type = header[0];
        let version = [header[1], header[2]];
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));

        if len > MAX_CIPHERTEXT {
            return Err(TlsError::Protocol(format!(
                "record length {len} exceeds maximum {MAX_CIPHERTEXT}"
            )));
        }

        let mut fragment = vec![0u8; len];
        self.read_exact(&mut fragment)?;

        if let Some(state) = &mut self.read_state {
            state.rc4.process(&mut fragment);
            let mac_len = state.mac_alg.output_len();
            if fragment.len() < mac_len {
                return Err(TlsError::Protocol("record shorter than its MAC".into()));
            }
            let split = fragment.len() - mac_len;
            let received_mac = fragment.split_off(split);
            let expected = compute_mac(
                state.mac_alg,
                &state.mac_key,
                state.seq,
                content_type,
                version,
                &fragment,
            );
            state.seq = state.seq.wrapping_add(1);
            if !constant_time_eq(&received_mac, &expected) {
                return Err(TlsError::Protocol("bad record MAC".into()));
            }
        }

        Ok(Some(Record {
            content_type,
            payload: fragment,
        }))
    }

    /// Read a 5-byte record header, or `None` if the peer closed cleanly first.
    fn read_header(&mut self) -> Result<Option<[u8; 5]>, TlsError> {
        let mut header = [0u8; 5];
        // Probe the first byte: 0 bytes means EOF exactly at a record boundary.
        match self.stream.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(err) => return Err(self.io_error(err)),
        }
        self.read_exact(&mut header[1..])?;
        Ok(Some(header))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TlsError> {
        self.stream
            .read_exact(buf)
            .map_err(|err| self.io_error(err))
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), TlsError> {
        self.stream.write_all(buf).map_err(|err| self.io_error(err))
    }

    /// Map a socket error to the appropriate retryable/non-retryable variant.
    fn io_error(&self, err: std::io::Error) -> TlsError {
        use std::io::ErrorKind::{TimedOut, WouldBlock};
        if matches!(err.kind(), WouldBlock | TimedOut) {
            TlsError::Timeout {
                host: self.host.clone(),
                port: self.port,
                timeout_secs: self.timeout_secs,
            }
        } else {
            TlsError::Connect {
                host: self.host.clone(),
                port: self.port,
                source: err,
            }
        }
    }
}

/// Compute the record MAC: `HMAC(mac_key, seq || type || version || length || fragment)`.
fn compute_mac(
    alg: MacAlg,
    mac_key: &[u8],
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    fragment: &[u8],
) -> Vec<u8> {
    let len = u16::try_from(fragment.len()).expect("fragment length fits in u16");
    let header = [
        content_type,
        version[0],
        version[1],
        len.to_be_bytes()[0],
        len.to_be_bytes()[1],
    ];
    let seq = seq.to_be_bytes();
    match alg {
        MacAlg::Md5 => mac_with::<HmacMd5>(mac_key, &seq, &header, fragment),
        MacAlg::Sha1 => mac_with::<HmacSha1>(mac_key, &seq, &header, fragment),
    }
}

/// HMAC over `seq || header || fragment`, keyed by `mac_key`, for one MAC algorithm.
fn mac_with<M: Mac + KeyInit>(
    mac_key: &[u8],
    seq: &[u8],
    header: &[u8],
    fragment: &[u8],
) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(mac_key).expect("HMAC accepts keys of any length");
    mac.update(seq);
    mac.update(header);
    mac.update(fragment);
    mac.finalize().into_bytes().to_vec()
}

/// Length-checked constant-time byte comparison for MAC verification. `subtle`
/// short-circuits only on a length mismatch (lengths are not secret) and is
/// otherwise data-independent, unlike a hand-rolled loop the optimizer may spoil.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6229 RC4 key-stream vector for the 16-byte key 0x0102030405...0f10:
    // the first 16 keystream bytes are known. Encrypting a zero buffer yields
    // exactly the keystream.
    #[test]
    fn rc4_rfc6229_keystream() {
        use std::fmt::Write as _;
        let key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut buf = [0u8; 16];
        Rc4::new(&key).process(&mut buf);
        let hex = buf.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, "9ac7cc9a609d1ef7b2932899cde41b97");
    }

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
