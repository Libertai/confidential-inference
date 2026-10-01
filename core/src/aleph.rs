//! Reading Aleph without trusting the node that serves it.
//!
//! Two properties make that possible: a message's item hash is the SHA-256 of
//! its content, and the message is signed by its sender's Ethereum key. So a
//! client can be handed a message by anyone -- a public API, a peer, a cache --
//! and still establish that it is the one a given address published.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::VerifyError;

#[derive(Deserialize)]
pub struct Message {
    pub chain: String,
    pub sender: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub item_hash: String,
    pub item_type: String,
    pub item_content: String,
    pub signature: String,
}

/// The content is what the hash names, and the sender really signed it.
/// Returns the verified `item_content`, still as JSON text.
///
/// Only inline messages can be checked this way: a storage-backed one hashes
/// bytes that are not in the message, so its content would have to be fetched
/// and trusted separately.
pub fn verify_message(json: &str, expected_sender: Option<&str>) -> Result<String, VerifyError> {
    let message: Message =
        serde_json::from_str(json).map_err(|e| VerifyError::Aleph(e.to_string()))?;
    if message.item_type != "inline" {
        return Err(VerifyError::Aleph(format!(
            "cannot verify a {} message offline",
            message.item_type
        )));
    }

    let digest = hex(&Sha256::digest(message.item_content.as_bytes()));
    if !digest.eq_ignore_ascii_case(&message.item_hash) {
        return Err(VerifyError::Aleph(format!(
            "item hash mismatch: content hashes to {digest}"
        )));
    }

    let signer = recover_sender(&message)?;
    if !signer.eq_ignore_ascii_case(&message.sender) {
        return Err(VerifyError::Aleph(format!(
            "signed by {signer}, not by {}",
            message.sender
        )));
    }
    if let Some(expected) = expected_sender {
        if !signer.eq_ignore_ascii_case(expected) {
            return Err(VerifyError::Aleph(format!(
                "published by {signer}, not by {expected}"
            )));
        }
    }
    Ok(message.item_content)
}

/// Aleph signs the fields that identify a message rather than the content; the
/// content is covered because the item hash is one of them.
fn recover_sender(message: &Message) -> Result<String, VerifyError> {
    let buffer = format!(
        "{}\n{}\n{}\n{}",
        message.chain, message.sender, message.kind, message.item_hash
    );
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", buffer.len(), buffer);

    let sig = unhex(&message.signature)?;
    if sig.len() != 65 {
        return Err(VerifyError::Aleph(format!(
            "signature is {} bytes, expected 65",
            sig.len()
        )));
    }
    // Wallets write 27/28 here, EIP-155 chains write more; only the low bit is
    // the parity this needs.
    let recovery = RecoveryId::from_byte(if sig[64] >= 27 { sig[64] - 27 } else { sig[64] } & 1)
        .ok_or_else(|| VerifyError::Aleph("invalid recovery id".into()))?;
    let signature =
        Signature::from_slice(&sig[..64]).map_err(|e| VerifyError::Aleph(e.to_string()))?;
    let key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(prefixed.as_bytes()),
        &signature,
        recovery,
    )
    .map_err(|e| VerifyError::Aleph(format!("cannot recover a signer: {e}")))?;

    // An Ethereum address is the last 20 bytes of the keccak of the raw point.
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    Ok(format!("0x{}", hex(&hash[12..])))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, VerifyError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or_else(|| VerifyError::Aleph("signature is not hex".into()))
        })
        .collect()
}
