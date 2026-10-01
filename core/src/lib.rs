//! Verification core for LibertAI confidential inference.
//!
//! Given an RA-TLS certificate and the measurements a V-PROGRAM message
//! publishes, decide whether the peer is the enclave that message describes.
//! Deliberately free of network and TLS: the host language fetches the
//! message, the AMD certificates and the certificate itself, so this crate
//! compiles to `wasm32-unknown-unknown` and can be audited on its own.

use serde::{Deserialize, Serialize};

pub mod aleph;
pub mod binding;
pub mod chain;
pub mod report;

/// OID of the X.509 extension the guest agent puts its attestation in.
pub const ATTESTATION_OID: &str = "1.3.6.1.4.1.60000.1.1";

/// What the guest embeds in the certificate: the TEE flavour plus the raw
/// signed report, hex-encoded. Field names are a cross-repo wire format,
/// shared with aleph-vm's `aleph-tee::types::AttestationReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedAttestation {
    pub tee_type: String,
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    NoAttestationExtension,
    MalformedExtension(String),
    UnsupportedTeeType(String),
    ShortReport {
        len: usize,
    },
    /// The peer is a measured enclave, but not one this release published.
    MeasurementMismatch {
        got: String,
    },
    /// The report does not commit to the key the peer served. Without this
    /// check a genuine report can be replayed in front of an attacker's key.
    KeyBindingMismatch,
    /// Certificate parsed, but carries no usable public key.
    NoPublicKey,
    /// AMD does not endorse this report: a signature, a certificate or a root
    /// did not check out.
    Chain(String),
    /// The report comes from a CPU this crate has no AMD roots for.
    UnknownProduct {
        family: u8,
        model: u8,
    },
    /// The platform runs firmware older than the caller accepts.
    TcbTooOld {
        component: String,
        got: u8,
        want: u8,
    },
    /// An Aleph message did not hold up: wrong hash, wrong signer, or
    /// malformed.
    Aleph(String),
    /// The guest policy permits host debugging, so the enclave guarantees do
    /// not hold whatever the report says.
    DebugAllowed,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoAttestationExtension => {
                write!(f, "certificate carries no attestation extension")
            }
            Self::MalformedExtension(e) => write!(f, "attestation extension is malformed: {e}"),
            Self::UnsupportedTeeType(t) => write!(f, "unsupported TEE type: {t}"),
            Self::ShortReport { len } => write!(f, "attestation report too short: {len} bytes"),
            Self::MeasurementMismatch { got } => {
                write!(
                    f,
                    "launch measurement {got} is not one this deployment published"
                )
            }
            Self::KeyBindingMismatch => {
                write!(f, "report does not bind the TLS key the peer served")
            }
            Self::NoPublicKey => write!(f, "certificate carries no public key"),
            Self::Chain(e) => write!(f, "AMD does not endorse this report: {e}"),
            Self::UnknownProduct { family, model } => {
                write!(
                    f,
                    "no AMD roots for CPU family {family:#x} model {model:#x}"
                )
            }
            Self::TcbTooOld {
                component,
                got,
                want,
            } => {
                write!(
                    f,
                    "platform {component} firmware is {got}, below the required {want}"
                )
            }
            Self::Aleph(e) => write!(f, "{e}"),
            Self::DebugAllowed => write!(f, "guest policy allows host debugging"),
        }
    }
}

/// Pull the attestation out of a DER certificate.
pub fn attestation_from_cert(der: &[u8]) -> Result<EmbeddedAttestation, VerifyError> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| VerifyError::MalformedExtension(e.to_string()))?;
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == ATTESTATION_OID)
        .ok_or(VerifyError::NoAttestationExtension)?;
    // The agent wraps the JSON in a DER OCTET STRING; serde_json is given the
    // payload from the first '{' so both framings parse.
    let raw = ext.value;
    let start = raw
        .iter()
        .position(|b| *b == b'{')
        .ok_or_else(|| VerifyError::MalformedExtension("no JSON object in extension".into()))?;
    serde_json::from_slice(&raw[start..])
        .map_err(|e| VerifyError::MalformedExtension(e.to_string()))
}

/// The launch measurement is what a V-PROGRAM message pins, so it is what a
/// client compares. `expected` is every digest the message lists (one per
/// vcpu_type); the host picks the model, so any of them is legitimate.
pub fn check_measurement(der: &[u8], expected: &[String]) -> Result<String, VerifyError> {
    let att = attestation_from_cert(der)?;
    if att.tee_type != "sev-snp" {
        return Err(VerifyError::UnsupportedTeeType(att.tee_type));
    }
    let measurement = report::launch_measurement(&att.data)?;
    if expected
        .iter()
        .any(|e| e.eq_ignore_ascii_case(&measurement))
    {
        Ok(measurement)
    } else {
        Err(VerifyError::MeasurementMismatch { got: measurement })
    }
}

/// Everything a client must establish before it sends a prompt: AMD endorses
/// the report, the guest is not debuggable, the report commits to the TLS key
/// the peer served, and the measurement is one this deployment published.
/// `vcek_der` comes from `vcek_url`; fetching is the caller's job so this
/// crate stays network-free.
pub fn verify(der: &[u8], vcek_der: &[u8], expected: &[String]) -> Result<String, VerifyError> {
    let att = attestation_from_cert(der)?;
    if att.tee_type != "sev-snp" {
        return Err(VerifyError::UnsupportedTeeType(att.tee_type));
    }
    let report = chain::parse_report(&att.data)?;
    chain::verify_report(&report, vcek_der)?;
    chain::check_policy(&report)?;
    binding::check_key_binding(der, &att.data)?;
    check_measurement(der, expected)
}

/// The VCEK `verify` needs, which the caller fetches (and may cache: it only
/// changes when the host's firmware does).
pub fn vcek_url(der: &[u8]) -> Result<String, VerifyError> {
    chain::vcek_url(&chain::parse_report(&attestation_from_cert(der)?.data)?)
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
