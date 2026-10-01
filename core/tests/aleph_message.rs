//! A real V-PROGRAM message, published by the account that runs the
//! deployments: these fail if Aleph's hashing or signing rules drift.

use confidential_inference_core::{aleph, VerifyError};

const MESSAGE: &str = include_str!("fixtures/vprogram-message.json");
const SENDER: &str = "0x238224C744F4b90b4494516e074D2676ECfC6803";

#[test]
fn a_published_message_verifies_against_its_sender() {
    let content = aleph::verify_message(MESSAGE, Some(SENDER)).expect("real message verifies");
    assert!(content.contains("\"sev_snp\""));
}

/// Rewrites the signed payload, leaving every other field of the message alone.
fn with_item_content(content: &str) -> String {
    let mut json: serde_json::Value = serde_json::from_str(MESSAGE).unwrap();
    json["item_content"] = serde_json::Value::String(content.to_string());
    json.to_string()
}

#[test]
fn content_that_does_not_hash_to_the_item_hash_is_refused() {
    let json: serde_json::Value = serde_json::from_str(MESSAGE).unwrap();
    let tampered = with_item_content(
        &json["item_content"]
            .as_str()
            .unwrap()
            .replace("sev_snp", "sev_snq"),
    );
    assert!(matches!(
        aleph::verify_message(&tampered, Some(SENDER)),
        Err(VerifyError::Aleph(e)) if e.contains("item hash mismatch")
    ));
}

#[test]
fn a_message_is_refused_when_another_address_claims_it() {
    let other = "0x0000000000000000000000000000000000000001";
    assert!(matches!(
        aleph::verify_message(MESSAGE, Some(other)),
        Err(VerifyError::Aleph(e)) if e.contains("published by")
    ));
}

#[test]
fn a_forged_signature_is_refused() {
    // Flipping a byte of r leaves a well-formed signature that recovers some
    // other key, which is the failure this has to catch.
    let json: serde_json::Value = serde_json::from_str(MESSAGE).unwrap();
    let sig = json["signature"].as_str().unwrap();
    let flipped = format!(
        "{}{}{}",
        &sig[..10],
        if &sig[10..11] == "a" { "b" } else { "a" },
        &sig[11..]
    );
    let forged = MESSAGE.replace(sig, &flipped);
    assert!(aleph::verify_message(&forged, Some(SENDER)).is_err());
}
