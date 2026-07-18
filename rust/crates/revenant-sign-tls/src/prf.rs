//! The TLS 1.0 pseudo-random function (RFC 2246 section 5).
//!
//! `PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR P_SHA-1(S2, label + seed)`
//! where the secret is split into two halves `S1`, `S2` (overlapping by one byte
//! when its length is odd). This is the function used to derive the master
//! secret, expand the key block, and compute the Finished `verify_data`.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

/// One HMAC over `data` keyed by `secret`.
fn hmac<M: Mac + KeyInit>(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <M as Mac>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// `P_hash` data-expansion function (RFC 2246 section 5).
///
/// `P_hash(secret, seed) = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) || ...`
/// where `A(0) = seed` and `A(i) = HMAC(secret, A(i-1))`, truncated to `out_len`.
fn p_hash<M: Mac + KeyInit>(secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(out_len);
    let mut a = hmac::<M>(secret, seed); // A(1)
    while result.len() < out_len {
        let mut mac = <M as Mac>::new_from_slice(secret).expect("HMAC accepts keys of any length");
        mac.update(&a);
        mac.update(seed);
        result.extend_from_slice(&mac.finalize().into_bytes());
        a = hmac::<M>(secret, &a); // A(i+1)
    }
    result.truncate(out_len);
    result
}

/// Compute `out_len` bytes of `PRF(secret, label, seed)`.
///
/// `label` and `seed` are concatenated exactly as the spec requires; callers
/// pass the ASCII label (e.g. `b"master secret"`) and the random seed.
#[must_use]
pub(crate) fn prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    // Split the secret into two halves. For an odd length the halves share the
    // middle byte (RFC 2246 section 5): each half is ceil(len/2) bytes long.
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let md5 = p_hash::<HmacMd5>(s1, &label_seed, out_len);
    let sha1 = p_hash::<HmacSha1>(s2, &label_seed, out_len);
    md5.iter().zip(sha1).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2202 HMAC-MD5 test case 1: key = 16x 0x0b, data = "Hi There".
    #[test]
    fn hmac_md5_rfc2202() {
        let out = hmac::<HmacMd5>(&[0x0b; 16], b"Hi There");
        assert_eq!(
            hex(&out),
            "9294727a3638bb1c13f48ef8158bfc9d",
            "HMAC-MD5 must match RFC 2202 vector 1"
        );
    }

    // RFC 2202 HMAC-SHA1 test case 1.
    #[test]
    fn hmac_sha1_rfc2202() {
        let out = hmac::<HmacSha1>(&[0x0b; 20], b"Hi There");
        assert_eq!(hex(&out), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    // PRF output length and determinism: same inputs -> same bytes, and the
    // XOR construction means output is not simply either P_hash alone.
    #[test]
    fn prf_is_deterministic_and_sized() {
        let a = prf(b"secret", b"label", b"seed", 48);
        let b = prf(b"secret", b"label", b"seed", 48);
        assert_eq!(a, b);
        assert_eq!(a.len(), 48);
        assert_ne!(a, p_hash::<HmacMd5>(b"sec", b"labelseed", 48));
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}
