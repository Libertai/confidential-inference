//! Channel binding: does the report commit to the key the peer served?
//!
//! The guest fills REPORT_DATA with `SHA-384(DOMAIN || public_key)` under a
//! domain tag per scheme (aleph-vm `aleph-tee::report_data`). Without checking
//! it, an attacker can relay a genuine report in front of its own TLS key.

use sha2::{Digest, Sha384};

use crate::{report, VerifyError};

/// Domain tag for the key-binding report. The trailing NUL is a separator, so
/// the domain can never be a prefix of the key that follows.
pub const DOMAIN_KEY: &[u8] = b"aleph-attest-tls-key-v1\x00";

/// Domain tag for a nonce-bound fresh report. The served key is mixed in, so a
/// fresh report cannot be relayed against a different channel.
pub const DOMAIN_FRESH: &[u8] = b"aleph-attest-fresh-v1\x00";

/// REPORT_DATA for a key-binding report: digest in the first 48 bytes, the
/// remaining 16 zero.
pub fn key_bound_report_data(public_key_raw: &[u8]) -> [u8; 64] {
    let mut h = Sha384::new();
    h.update(DOMAIN_KEY);
    h.update(public_key_raw);
    into_report_data(h)
}

/// REPORT_DATA for a fresh report bound to both the served key and a nonce.
pub fn fresh_report_data(public_key_raw: &[u8], nonce: &[u8]) -> [u8; 64] {
    let mut h = Sha384::new();
    h.update(DOMAIN_FRESH);
    h.update(public_key_raw);
    h.update(nonce);
    into_report_data(h)
}

fn into_report_data(h: Sha384) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..48].copy_from_slice(&h.finalize());
    out
}

/// Raw public key bytes as the guest hashes them: the contents of the
/// certificate's subjectPublicKey BIT STRING (an uncompressed EC point), not
/// the SPKI wrapper.
pub fn served_public_key(der: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| VerifyError::MalformedExtension(e.to_string()))?;
    let key = cert.public_key().subject_public_key.data.to_vec();
    if key.is_empty() {
        return Err(VerifyError::NoPublicKey);
    }
    Ok(key)
}

/// The report must commit to the key this certificate serves.
pub fn check_key_binding(der: &[u8], report_bytes: &[u8]) -> Result<(), VerifyError> {
    let key = served_public_key(der)?;
    let want = key_bound_report_data(&key);
    let got = report::report_data(report_bytes)?;
    if got == want {
        Ok(())
    } else {
        Err(VerifyError::KeyBindingMismatch)
    }
}
