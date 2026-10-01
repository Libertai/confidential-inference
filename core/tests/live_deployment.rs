//! Verification against a real deployment: the certificate was captured from
//! the H200 V-PROGRAM f45e492a… and the measurements come from its published
//! message, so these tests fail if either wire format drifts.

use confidential_inference_core::{binding, chain, attestation_from_cert, check_measurement, VerifyError};

const CERT: &[u8] = include_bytes!("fixtures/ratls-cert.der");

/// Exactly how a client gets them: verify the published message, then read the
/// digests out of the content it vouched for.
fn published_measurements() -> Vec<String> {
    let verified = confidential_inference_core::aleph::verify_message(
        include_str!("fixtures/vprogram-message.json"),
        Some("0x238224C744F4b90b4494516e074D2676ECfC6803"),
    )
    .expect("the deployment's message verifies");
    let content: serde_json::Value = serde_json::from_str(&verified).unwrap();
    content["verification"]["measurements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["registers"]["launch"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn certificate_carries_an_sev_snp_report() {
    let att = attestation_from_cert(CERT).expect("extension present");
    assert_eq!(att.tee_type, "sev-snp");
    assert_eq!(att.data.len(), 1184, "SNP report size");
}

#[test]
fn live_report_matches_a_published_measurement() {
    let expected = published_measurements();
    assert_eq!(expected.len(), 2, "one digest per vcpu_type");
    let m = check_measurement(CERT, &expected).expect("live peer matches its message");
    // The host ran it on Genoa, so the EPYC-Genoa digest is the one that hits.
    assert!(m.starts_with("dd1e95158e450fc6"));
}

#[test]
fn a_digest_from_another_deployment_is_rejected() {
    let other = vec!["5390e5a19fcc8fe10e470f4af9aa4fb1".to_string() + &"0".repeat(64)];
    match check_measurement(CERT, &other) {
        Err(VerifyError::MeasurementMismatch { got }) => assert!(got.starts_with("dd1e9515")),
        other => panic!("expected mismatch, got {other:?}"),
    }
}

#[test]
fn a_certificate_without_the_extension_is_rejected() {
    // Self-signed cert with no attestation: the first 200 bytes of ours are a
    // valid DER prefix but parse fails, which is the same refusal path.
    assert!(matches!(
        attestation_from_cert(&CERT[..200]),
        Err(VerifyError::MalformedExtension(_)) | Err(VerifyError::NoAttestationExtension)
    ));
}

#[test]
fn live_report_binds_the_served_tls_key() {
    let att = attestation_from_cert(CERT).expect("live cert carries a report");
    // The guest hashes the raw EC point, so a 97-byte uncompressed P-384 key.
    let key = binding::served_public_key(CERT).expect("cert has a public key");
    assert_eq!(key.len(), 97, "uncompressed P-384 point");
    binding::check_key_binding(CERT, &att.data).expect("report commits to the served key");
}

#[test]
fn a_report_bound_to_another_key_is_rejected() {
    let att = attestation_from_cert(CERT).expect("live cert carries a report");
    // A relayed report: genuine, measured, but bound to the wrong channel.
    let mut relayed = att.data.clone();
    relayed[0x50] ^= 1;
    assert!(matches!(
        binding::check_key_binding(CERT, &relayed),
        Err(VerifyError::KeyBindingMismatch)
    ));
}

const VCEK: &[u8] = include_bytes!("fixtures/vcek.der");

#[test]
fn amd_endorses_the_live_report() {
    let att = attestation_from_cert(CERT).expect("live cert carries a report");
    let report = chain::parse_report(&att.data).expect("report parses");
    assert_eq!(chain::product(&report).unwrap(), chain::Product::Genoa);
    chain::verify_report(&report, VCEK).expect("ARK -> ASK -> VCEK -> report");
    chain::check_policy(&report).expect("debugging is disallowed");
}

#[test]
fn a_tampered_measurement_breaks_the_amd_signature() {
    let att = attestation_from_cert(CERT).expect("live cert carries a report");
    let mut forged = att.data.clone();
    forged[0x90] ^= 1;
    let report = chain::parse_report(&forged).expect("still well-formed");
    assert!(matches!(
        chain::verify_report(&report, VCEK),
        Err(VerifyError::Chain(_))
    ));
}

#[test]
fn the_vcek_url_is_the_one_that_verifies() {
    // Fixed by the chip and its firmware: a drift here means the fetch would
    // return a certificate that cannot sign this report.
    assert_eq!(
        confidential_inference_core::vcek_url(CERT).unwrap(),
        "https://kdsintf.amd.com/vcek/v1/Genoa/\
         14c20492e69ade64158ee166e26cc39ec41243ebefe10859ab7591c0707700b2\
         e1203dbd97a553288c2d931d7ee6a0118d4b677b28bc3e344995a388b7ce0787\
         ?blSPL=12&teeSPL=0&snpSPL=28&ucodeSPL=88"
    );
}

#[test]
fn full_verification_of_the_live_peer() {
    let m = confidential_inference_core::verify(CERT, VCEK, &published_measurements())
        .expect("live peer verifies end to end");
    assert!(m.starts_with("dd1e95158e450fc6"));
}

#[test]
fn a_firmware_floor_above_the_platform_is_refused() {
    let att = attestation_from_cert(CERT).expect("live cert carries a report");
    let report = chain::parse_report(&att.data).expect("report parses");
    let current = chain::TcbFloor { bootloader: 12, tee: 0, snp: 28, microcode: 88 };
    chain::check_tcb(&report, current).expect("the host meets its own TCB");
    let future = chain::TcbFloor { snp: 29, ..current };
    assert!(matches!(
        chain::check_tcb(&report, future),
        Err(VerifyError::TcbTooOld { .. })
    ));
}
