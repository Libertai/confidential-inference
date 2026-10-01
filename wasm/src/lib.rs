//! JavaScript bindings. The verification itself lives in the core crate: this
//! layer only converts types and turns errors into exceptions, so a browser
//! and a Node client run byte-for-byte the same checks.

use confidential_inference_core as core;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// What a report says about the peer, for display and debugging. Reading these
/// is not verifying them: use `verify`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportFacts {
    pub product: String,
    pub measurement: String,
    pub chip_id: String,
    pub report_data: String,
    pub debug_allowed: bool,
    pub smt_allowed: bool,
    pub reported_tcb: Tcb,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

fn js_err(e: core::VerifyError) -> JsError {
    JsError::new(&e.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The AMD Key Distribution Service URL of the VCEK that signed this peer's
/// report. The caller fetches it; the answer only changes when the host's
/// firmware does, so it is worth caching.
#[wasm_bindgen(js_name = vcekUrl)]
pub fn vcek_url(cert_der: &[u8]) -> Result<String, JsError> {
    core::vcek_url(cert_der).map_err(js_err)
}

/// Full verification. Returns the launch measurement that matched, or throws.
///
/// `expected` are the measurements the deployment published, one per vCPU type.
#[wasm_bindgen]
pub fn verify(
    cert_der: &[u8],
    vcek_der: &[u8],
    expected: Vec<String>,
) -> Result<String, JsError> {
    core::verify(cert_der, vcek_der, &expected).map_err(js_err)
}

/// Reject a platform whose firmware is older than the caller requires. Separate
/// from `verify` because the floor is policy: it has to be raised whenever AMD
/// publishes an SEV firmware advisory.
#[wasm_bindgen(js_name = checkTcb)]
pub fn check_tcb(
    cert_der: &[u8],
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
) -> Result<(), JsError> {
    let att = core::attestation_from_cert(cert_der).map_err(js_err)?;
    let report = core::chain::parse_report(&att.data).map_err(js_err)?;
    core::chain::check_tcb(
        &report,
        core::chain::TcbFloor { bootloader, tee, snp, microcode },
    )
    .map_err(js_err)
}

/// Decode the report without judging it.
#[wasm_bindgen(js_name = reportFacts)]
pub fn report_facts(cert_der: &[u8]) -> Result<JsValue, JsError> {
    let att = core::attestation_from_cert(cert_der).map_err(js_err)?;
    let r = core::chain::parse_report(&att.data).map_err(js_err)?;
    let facts = ReportFacts {
        product: core::chain::product(&r).map_err(js_err)?.as_str().to_string(),
        measurement: hex(&r.measurement),
        chip_id: hex(&r.chip_id),
        report_data: hex(&r.report_data),
        debug_allowed: r.policy.debug_allowed(),
        smt_allowed: r.policy.smt_allowed(),
        reported_tcb: Tcb {
            bootloader: r.reported_tcb.bootloader,
            tee: r.reported_tcb.tee,
            snp: r.reported_tcb.snp,
            microcode: r.reported_tcb.microcode,
        },
    };
    serde_wasm_bindgen::to_value(&facts).map_err(|e| JsError::new(&e.to_string()))
}
