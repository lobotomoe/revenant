//! The TLS 1.0 client handshake for `TLS_RSA_WITH_RC4_128_MD5` / `_SHA`.
//!
//! Implements exactly the RSA key-exchange flow, no client authentication and no
//! extensions -- the classic RFC 2246 ClientHello an IIS 5.1-era appliance
//! expects:
//!
//! ```text
//! Client                                     Server
//!   ClientHello            -->
//!                          <--   ServerHello, Certificate, ServerHelloDone
//!   ClientKeyExchange
//!   [ChangeCipherSpec]
//!   Finished               -->
//!                          <--   [ChangeCipherSpec], Finished
//! ```

use const_oid::ObjectIdentifier;
use der::Decode;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha1::Digest as _;
use x509_cert::Certificate;

use crate::error::TlsError;
use crate::record::{
    constant_time_eq, Connection, MacAlg, CT_ALERT, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE,
};

// Handshake message types (RFC 2246 section 7.4).
const HT_SERVER_HELLO: u8 = 2;
const HT_CERTIFICATE: u8 = 11;
const HT_SERVER_KEY_EXCHANGE: u8 = 12;
const HT_CERTIFICATE_REQUEST: u8 = 13;
const HT_SERVER_HELLO_DONE: u8 = 14;
const HT_CLIENT_HELLO: u8 = 1;
const HT_CLIENT_KEY_EXCHANGE: u8 = 16;
const HT_FINISHED: u8 = 20;

// The two RC4 cipher suites we offer, most preferred first.
const SUITE_RSA_RC4_MD5: u16 = 0x0004;
const SUITE_RSA_RC4_SHA: u16 = 0x0005;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

const FINISHED_LEN: usize = 12;
const ENC_KEY_LEN: usize = 16;

/// Run the handshake to completion, leaving `conn` with both cipher directions
/// active and ready for application data.
pub(crate) fn perform(conn: &mut Connection) -> Result<(), TlsError> {
    let mut transcript: Vec<u8> = Vec::new();

    // -- ClientHello ---------------------------------------------------------
    let mut client_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_random);
    let client_hello = hs_message(HT_CLIENT_HELLO, &build_client_hello_body(&client_random));
    conn.write(CT_HANDSHAKE, &client_hello)?;
    transcript.extend_from_slice(&client_hello);

    // -- Server flight: ServerHello .. ServerHelloDone -----------------------
    let mut reader = HandshakeReader::default();
    let server = read_server_flight(conn, &mut reader, &mut transcript)?;
    let ServerParams {
        server_random,
        mac_alg,
        pubkey,
        client_cert_requested,
    } = server;

    // A server that requested client authentication still accepts an anonymous
    // client if we send an empty Certificate message before ClientKeyExchange.
    if client_cert_requested {
        let empty_cert = hs_message(HT_CERTIFICATE, &put_u24(0));
        conn.write(CT_HANDSHAKE, &empty_cert)?;
        transcript.extend_from_slice(&empty_cert);
    }

    // -- ClientKeyExchange: RSA-encrypted premaster secret -------------------
    let mut premaster = [0u8; 48];
    premaster[0] = 3; // client_version major, echoed back to defeat rollback
    premaster[1] = 1; // client_version minor (TLS 1.0)
    rand::thread_rng().fill_bytes(&mut premaster[2..]);

    let encrypted = pubkey
        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &premaster)
        .map_err(|err| {
            handshake_err(conn, &format!("RSA encryption of premaster failed: {err}"))
        })?;

    let mut cke_body = Vec::with_capacity(2 + encrypted.len());
    let enc_len = u16::try_from(encrypted.len())
        .map_err(|_| handshake_err(conn, "RSA ciphertext too large"))?;
    cke_body.extend_from_slice(&enc_len.to_be_bytes());
    cke_body.extend_from_slice(&encrypted);
    let cke = hs_message(HT_CLIENT_KEY_EXCHANGE, &cke_body);
    conn.write(CT_HANDSHAKE, &cke)?;
    transcript.extend_from_slice(&cke);

    // -- Key derivation ------------------------------------------------------
    let master_secret = {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&client_random);
        seed.extend_from_slice(&server_random);
        crate::prf::prf(&premaster, b"master secret", &seed, 48)
    };

    let mac_key_len = mac_alg.output_len();
    let key_block = {
        // Key expansion reverses the random order: server_random then client_random.
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        crate::prf::prf(
            &master_secret,
            b"key expansion",
            &seed,
            2 * mac_key_len + 2 * ENC_KEY_LEN,
        )
    };
    let client_mac_key = &key_block[..mac_key_len];
    let server_mac_key = &key_block[mac_key_len..2 * mac_key_len];
    let client_write_key = &key_block[2 * mac_key_len..2 * mac_key_len + ENC_KEY_LEN];
    let server_write_key =
        &key_block[2 * mac_key_len + ENC_KEY_LEN..2 * mac_key_len + 2 * ENC_KEY_LEN];

    // -- ChangeCipherSpec + client Finished ----------------------------------
    // CCS goes out under the old (null) cipher; then the write cipher activates.
    conn.write(CT_CHANGE_CIPHER_SPEC, &[1])?;
    conn.activate_write(client_write_key, client_mac_key, mac_alg);

    let client_verify = finished_verify_data(&master_secret, b"client finished", &transcript);
    let finished = hs_message(HT_FINISHED, &client_verify);
    conn.write(CT_HANDSHAKE, &finished)?;
    transcript.extend_from_slice(&finished);

    // The server's Finished is verified over the transcript up to and including
    // our Finished, so compute the expected value before reading it.
    let expected_server_verify =
        finished_verify_data(&master_secret, b"server finished", &transcript);

    // -- Server ChangeCipherSpec + Finished ----------------------------------
    read_change_cipher_spec(conn)?;
    conn.activate_read(server_write_key, server_mac_key, mac_alg);

    let (msg_type, body) = reader.next(conn, &mut transcript)?;
    if msg_type != HT_FINISHED {
        return Err(handshake_err(
            conn,
            &format!("expected server Finished, got handshake type {msg_type}"),
        ));
    }
    if body.len() != FINISHED_LEN || !constant_time_eq(&body, &expected_server_verify) {
        return Err(handshake_err(conn, "server Finished verify_data mismatch"));
    }

    Ok(())
}

/// What the server's first flight tells us: its random, the negotiated MAC
/// algorithm, its RSA public key, and whether it asked for a client certificate.
struct ServerParams {
    server_random: [u8; 32],
    mac_alg: MacAlg,
    pubkey: RsaPublicKey,
    client_cert_requested: bool,
}

/// Read ServerHello through ServerHelloDone, collecting the parameters needed to
/// derive keys and encrypt the premaster secret.
fn read_server_flight(
    conn: &mut Connection,
    reader: &mut HandshakeReader,
    transcript: &mut Vec<u8>,
) -> Result<ServerParams, TlsError> {
    let mut server_random: Option<[u8; 32]> = None;
    let mut mac_alg: Option<MacAlg> = None;
    let mut server_pubkey: Option<RsaPublicKey> = None;
    let mut client_cert_requested = false;

    loop {
        let (msg_type, body) = reader.next(conn, transcript)?;
        match msg_type {
            HT_SERVER_HELLO => {
                let hello = parse_server_hello(&body).map_err(|r| handshake_err(conn, &r))?;
                server_random = Some(hello.random);
                mac_alg = Some(hello.mac_alg);
            }
            HT_CERTIFICATE => {
                server_pubkey = Some(parse_leaf_public_key(&body)?);
            }
            HT_CERTIFICATE_REQUEST => client_cert_requested = true,
            HT_SERVER_KEY_EXCHANGE => {
                return Err(handshake_err(
                    conn,
                    "server sent ServerKeyExchange; only RSA key exchange is supported",
                ));
            }
            HT_SERVER_HELLO_DONE => break,
            other => {
                return Err(handshake_err(
                    conn,
                    &format!("unexpected handshake message type {other} in server flight"),
                ));
            }
        }
    }

    let server_random =
        server_random.ok_or_else(|| handshake_err(conn, "server did not send ServerHello"))?;
    let mac_alg = mac_alg.ok_or_else(|| handshake_err(conn, "server did not send ServerHello"))?;
    let pubkey =
        server_pubkey.ok_or_else(|| handshake_err(conn, "server did not present a certificate"))?;
    Ok(ServerParams {
        server_random,
        mac_alg,
        pubkey,
        client_cert_requested,
    })
}

/// Assemble the ClientHello body: TLS 1.0, our two RC4 suites, null compression,
/// no extensions.
fn build_client_hello_body(client_random: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(43);
    body.extend_from_slice(&[3, 1]); // client_version
    body.extend_from_slice(client_random);
    body.push(0); // session_id length: none
                  // cipher_suites
    body.extend_from_slice(&4u16.to_be_bytes()); // 2 suites * 2 bytes
    body.extend_from_slice(&SUITE_RSA_RC4_MD5.to_be_bytes());
    body.extend_from_slice(&SUITE_RSA_RC4_SHA.to_be_bytes());
    // compression_methods: just null
    body.push(1);
    body.push(0);
    body
}

struct ServerHello {
    random: [u8; 32],
    mac_alg: MacAlg,
}

fn parse_server_hello(body: &[u8]) -> Result<ServerHello, String> {
    // version(2) random(32) sid_len(1) sid(n) cipher(2) compression(1)
    let mut r = ByteReader::new(body);
    r.skip(2)?; // server_version -- we already committed to TLS 1.0
    let random: [u8; 32] = r.take(32)?.try_into().expect("took exactly 32 bytes");
    let sid_len = usize::from(r.take(1)?[0]);
    r.skip(sid_len)?;
    let suite = u16::from_be_bytes(r.take(2)?.try_into().expect("took exactly 2 bytes"));
    let mac_alg = match suite {
        SUITE_RSA_RC4_MD5 => MacAlg::Md5,
        SUITE_RSA_RC4_SHA => MacAlg::Sha1,
        other => {
            return Err(format!(
                "server chose unsupported cipher suite 0x{other:04x}"
            ))
        }
    };
    Ok(ServerHello { random, mac_alg })
}

/// Parse the Certificate message and extract the leaf certificate's RSA public key.
fn parse_leaf_public_key(body: &[u8]) -> Result<RsaPublicKey, TlsError> {
    let mut r = ByteReader::new(body);
    r.take_u24().map_err(TlsError::Certificate)?; // certificate_list length
    let cert_len = r.take_u24().map_err(TlsError::Certificate)?; // leaf certificate length
    let cert_der = r.take(cert_len).map_err(TlsError::Certificate)?;

    let cert = Certificate::from_der(cert_der)
        .map_err(|err| TlsError::Certificate(format!("cannot parse leaf certificate: {err}")))?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != RSA_ENCRYPTION {
        return Err(TlsError::Certificate(format!(
            "server public key is not RSA (algorithm {})",
            spki.algorithm.oid
        )));
    }
    let key_der = spki.subject_public_key.as_bytes().ok_or_else(|| {
        TlsError::Certificate("RSA public key bit string is not byte-aligned".into())
    })?;
    RsaPublicKey::from_pkcs1_der(key_der)
        .map_err(|err| TlsError::Certificate(format!("cannot decode RSA public key: {err}")))
}

/// `verify_data = PRF(master_secret, label, MD5(transcript) || SHA-1(transcript))[..12]`.
fn finished_verify_data(master_secret: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(36);
    seed.extend_from_slice(&md5::Md5::digest(transcript));
    seed.extend_from_slice(&sha1::Sha1::digest(transcript));
    crate::prf::prf(master_secret, label, &seed, FINISHED_LEN)
}

/// Read the server's ChangeCipherSpec record, surfacing any alert as an error.
fn read_change_cipher_spec(conn: &mut Connection) -> Result<(), TlsError> {
    let record = conn
        .read()?
        .ok_or_else(|| handshake_err(conn, "peer closed before ChangeCipherSpec"))?;
    match record.content_type {
        CT_CHANGE_CIPHER_SPEC => Ok(()),
        CT_ALERT => Err(alert_to_error(conn, &record.payload)),
        other => Err(handshake_err(
            conn,
            &format!("expected ChangeCipherSpec, got record type {other}"),
        )),
    }
}

/// Reassembles handshake messages from records, tolerating messages that span
/// records and records that pack several messages.
#[derive(Default)]
struct HandshakeReader {
    buffer: Vec<u8>,
}

impl HandshakeReader {
    fn next(
        &mut self,
        conn: &mut Connection,
        transcript: &mut Vec<u8>,
    ) -> Result<(u8, Vec<u8>), TlsError> {
        loop {
            if self.buffer.len() >= 4 {
                let len = u24(self.buffer[1..4]
                    .try_into()
                    .expect("slice is exactly 3 bytes"));
                if self.buffer.len() >= 4 + len {
                    let message: Vec<u8> = self.buffer.drain(..4 + len).collect();
                    transcript.extend_from_slice(&message);
                    let body = message[4..].to_vec();
                    return Ok((message[0], body));
                }
            }
            let record = conn
                .read()?
                .ok_or_else(|| handshake_err(conn, "peer closed during handshake"))?;
            match record.content_type {
                CT_HANDSHAKE => self.buffer.extend_from_slice(&record.payload),
                CT_ALERT => return Err(alert_to_error(conn, &record.payload)),
                other => {
                    return Err(handshake_err(
                        conn,
                        &format!("unexpected record type {other} during handshake"),
                    ));
                }
            }
        }
    }
}

// -- Small parsing helpers --------------------------------------------------

/// A forward-only byte reader that returns a reason string on truncation. The
/// caller attaches connection context (peer, error kind) at the boundary.
struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        match self.pos.checked_add(n).filter(|&e| e <= self.data.len()) {
            Some(end) => {
                let slice = &self.data[self.pos..end];
                self.pos = end;
                Ok(slice)
            }
            None => Err("handshake message truncated".to_owned()),
        }
    }

    fn take_u24(&mut self) -> Result<usize, String> {
        Ok(u24(self.take(3)?.try_into().expect("took exactly 3 bytes")))
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.take(n).map(|_| ())
    }
}

fn u24(b: [u8; 3]) -> usize {
    (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

fn put_u24(v: usize) -> [u8; 3] {
    let bytes = u32::try_from(v)
        .expect("u24 length fits in u32")
        .to_be_bytes();
    debug_assert!(bytes[0] == 0, "handshake length {v} exceeds 24 bits");
    [bytes[1], bytes[2], bytes[3]]
}

fn hs_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(msg_type);
    message.extend_from_slice(&put_u24(body.len()));
    message.extend_from_slice(body);
    message
}

fn handshake_err(conn: &Connection, reason: &str) -> TlsError {
    let (host, port) = conn.peer();
    TlsError::Handshake {
        host,
        port,
        reason: reason.to_string(),
    }
}

/// Map a received alert record to a descriptive handshake error.
fn alert_to_error(conn: &Connection, payload: &[u8]) -> TlsError {
    let description = payload.get(1).copied().unwrap_or(0);
    handshake_err(
        conn,
        &format!("peer sent alert (description {description})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_body_shape() {
        let body = build_client_hello_body(&[0u8; 32]);
        // 2 (version) + 32 (random) + 1 (sid len) + 2 (suites len) + 4 (suites)
        // + 1 (comp len) + 1 (comp) = 43
        assert_eq!(body.len(), 43);
        assert_eq!(&body[0..2], &[3, 1]);
        assert_eq!(body[34], 0); // no session id
        assert_eq!(&body[35..37], &4u16.to_be_bytes());
        assert_eq!(&body[37..39], &SUITE_RSA_RC4_MD5.to_be_bytes());
        assert_eq!(&body[39..41], &SUITE_RSA_RC4_SHA.to_be_bytes());
    }

    #[test]
    fn cursor_rejects_truncation() {
        let mut c = ByteReader::new(&[1, 2, 3]);
        assert!(c.take(2).is_ok());
        assert!(c.take(2).is_err());
    }

    #[test]
    fn u24_roundtrip() {
        assert_eq!(u24(put_u24(0x0012_3456)), 0x0012_3456);
    }
}
