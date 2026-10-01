//! Python bindings. The verification lives in the core crate: this layer only
//! converts types and raises exceptions, so Python and JavaScript run the same
//! checks rather than two implementations of them.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use confidential_inference_core as core;

create_exception!(_core, AttestationError, PyException);
create_exception!(_core, AlephError, PyException);

fn attestation_err(e: core::VerifyError) -> PyErr {
    AttestationError::new_err(e.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The AMD Key Distribution Service URL of the VCEK that signed this peer's
/// report. The caller fetches it; the answer only changes when the host's
/// firmware does, so it is worth caching.
#[pyfunction]
fn vcek_url(cert_der: &[u8]) -> PyResult<String> {
    core::vcek_url(cert_der).map_err(attestation_err)
}

/// Full verification. Returns the launch measurement that matched, or raises.
#[pyfunction]
fn verify(cert_der: &[u8], vcek_der: &[u8], expected: Vec<String>) -> PyResult<String> {
    core::verify(cert_der, vcek_der, &expected).map_err(attestation_err)
}

/// Reject a platform whose firmware is older than the caller requires.
#[pyfunction]
fn check_tcb(cert_der: &[u8], bootloader: u8, tee: u8, snp: u8, microcode: u8) -> PyResult<()> {
    let att = core::attestation_from_cert(cert_der).map_err(attestation_err)?;
    let report = core::chain::parse_report(&att.data).map_err(attestation_err)?;
    core::chain::check_tcb(
        &report,
        core::chain::TcbFloor {
            bootloader,
            tee,
            snp,
            microcode,
        },
    )
    .map_err(attestation_err)
}

/// Decode the report without judging it.
#[pyfunction]
fn report_facts(py: Python<'_>, cert_der: &[u8]) -> PyResult<Py<PyDict>> {
    let att = core::attestation_from_cert(cert_der).map_err(attestation_err)?;
    let r = core::chain::parse_report(&att.data).map_err(attestation_err)?;
    let facts = PyDict::new(py);
    facts.set_item(
        "product",
        core::chain::product(&r).map_err(attestation_err)?.as_str(),
    )?;
    facts.set_item("measurement", hex(&r.measurement))?;
    facts.set_item("chip_id", hex(&r.chip_id))?;
    facts.set_item("report_data", hex(&r.report_data))?;
    facts.set_item("debug_allowed", r.policy.debug_allowed())?;
    facts.set_item("smt_allowed", r.policy.smt_allowed())?;
    let tcb = PyDict::new(py);
    tcb.set_item("bootloader", r.reported_tcb.bootloader)?;
    tcb.set_item("tee", r.reported_tcb.tee)?;
    tcb.set_item("snp", r.reported_tcb.snp)?;
    tcb.set_item("microcode", r.reported_tcb.microcode)?;
    facts.set_item("reported_tcb", tcb)?;
    Ok(facts.into())
}

/// Establish that an Aleph message is the one `sender` published, and return
/// its verified content as JSON text.
#[pyfunction]
#[pyo3(signature = (message_json, sender=None))]
fn verify_aleph_message(message_json: &str, sender: Option<&str>) -> PyResult<String> {
    core::aleph::verify_message(message_json, sender)
        .map_err(|e| AlephError::new_err(e.to_string()))
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("AttestationError", m.py().get_type::<AttestationError>())?;
    m.add("AlephError", m.py().get_type::<AlephError>())?;
    m.add_function(wrap_pyfunction!(vcek_url, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(check_tcb, m)?)?;
    m.add_function(wrap_pyfunction!(report_facts, m)?)?;
    m.add_function(wrap_pyfunction!(verify_aleph_message, m)?)?;
    Ok(())
}
