//! AMD signature chain: ARK → ASK → VCEK → report.
//!
//! Without this, everything else in the crate only proves that *someone*
//! produced a well-formed blob. The ARK and ASK are compiled in (AMD's
//! published roots), so a client trusts AMD, not the KDS it talks to; only the
//! per-chip VCEK is fetched, and it is self-authenticating against the ASK.
//!
//! Fetching is the caller's job: this crate stays network-free so it runs
//! unchanged in a browser, where the fetch belongs to the host anyway.

use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::Decoder;

use crate::VerifyError;

/// EPYC generation, which selects both the AMD roots and the KDS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Milan,
    Genoa,
    Turin,
}

impl Product {
    /// The name AMD uses in KDS paths and in its certificate subjects.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }

    fn roots(self) -> Result<ca::Chain, VerifyError> {
        let (ark, ask) = match self {
            Self::Milan => (builtin::milan::ark(), builtin::milan::ask()),
            Self::Genoa => (builtin::genoa::ark(), builtin::genoa::ask()),
            Self::Turin => (builtin::turin::ark(), builtin::turin::ask()),
        };
        Ok(ca::Chain {
            ark: ark.map_err(|e| VerifyError::Chain(e.to_string()))?,
            ask: ask.map_err(|e| VerifyError::Chain(e.to_string()))?,
        })
    }
}

/// Decode the 1184-byte firmware report.
pub fn parse_report(report: &[u8]) -> Result<AttestationReport, VerifyError> {
    let mut cursor = std::io::Cursor::new(report);
    AttestationReport::decode(&mut cursor, ()).map_err(|_| VerifyError::ShortReport {
        len: report.len(),
    })
}

/// Which EPYC signed this report. Version 3 reports carry CPUID directly;
/// version 2 ones predate those fields, and the only generation that can reach
/// us there is the one whose roots verify, so this reports Genoa and lets the
/// signature check be the arbiter.
pub fn product(report: &AttestationReport) -> Result<Product, VerifyError> {
    match (report.cpuid_fam_id, report.cpuid_mod_id) {
        (Some(0x19), Some(model)) => match model {
            0x00..=0x0F => Ok(Product::Milan),
            0x10..=0x1F | 0xA0..=0xAF => Ok(Product::Genoa),
            _ => Err(VerifyError::UnknownProduct { family: 0x19, model }),
        },
        (Some(0x1A), Some(0x00..=0x11)) => Ok(Product::Turin),
        (Some(family), Some(model)) => Err(VerifyError::UnknownProduct { family, model }),
        _ => Ok(Product::Genoa),
    }
}

/// URL of the VCEK that signed this report, at AMD's Key Distribution Service.
/// The VCEK is per-chip *and* per-TCB, so it changes whenever the host's
/// firmware is updated; callers should key any cache on the whole URL.
pub fn vcek_url(report: &AttestationReport) -> Result<String, VerifyError> {
    let product = product(report)?;
    let tcb = &report.reported_tcb;
    let chip: String = report.chip_id.iter().map(|b| format!("{b:02x}")).collect();
    let mut url = format!(
        "https://kdsintf.amd.com/vcek/v1/{}/{chip}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        product.as_str(),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode,
    );
    // Turin and later derive the VCEK from an FMC version too; omitting it
    // returns a certificate that does not verify the report.
    if let Some(fmc) = tcb.fmc {
        url.push_str(&format!("&fmcSPL={fmc}"));
    }
    Ok(url)
}

/// AMD endorses this report: ARK self-signs, signs the ASK, which signs the
/// caller-supplied VCEK, which signs the report body.
pub fn verify_report(report: &AttestationReport, vcek_der: &[u8]) -> Result<(), VerifyError> {
    let vek =
        Certificate::from_der(vcek_der).map_err(|e| VerifyError::Chain(e.to_string()))?;
    let chain = Chain {
        ca: product(report)?.roots()?,
        vek,
    };
    (&chain, report)
        .verify()
        .map_err(|e| VerifyError::Chain(e.to_string()))
}

/// The guest must not be debuggable: with DEBUG_ALLOWED the host can read and
/// write guest memory, which makes every other check decorative.
pub fn check_policy(report: &AttestationReport) -> Result<(), VerifyError> {
    if report.policy.debug_allowed() {
        return Err(VerifyError::DebugAllowed);
    }
    Ok(())
}

/// Minimum acceptable platform firmware, compared component-wise against the
/// TCB the VCEK was derived from.
///
/// A chip running firmware with a known escape gets a perfectly valid VCEK, so
/// the signature chain alone does not answer "is this platform patched". The
/// floor is policy, not a fact about the report: it is the caller's, and it has
/// to be raised whenever AMD publishes an SEV firmware advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbFloor {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

/// The platform is at or above the caller's firmware floor.
pub fn check_tcb(report: &AttestationReport, floor: TcbFloor) -> Result<(), VerifyError> {
    let tcb = &report.reported_tcb;
    let below = |name: &str, got: u8, want: u8| VerifyError::TcbTooOld {
        component: name.to_string(),
        got,
        want,
    };
    if tcb.bootloader < floor.bootloader {
        return Err(below("bootloader", tcb.bootloader, floor.bootloader));
    }
    if tcb.tee < floor.tee {
        return Err(below("tee", tcb.tee, floor.tee));
    }
    if tcb.snp < floor.snp {
        return Err(below("snp", tcb.snp, floor.snp));
    }
    if tcb.microcode < floor.microcode {
        return Err(below("microcode", tcb.microcode, floor.microcode));
    }
    Ok(())
}
