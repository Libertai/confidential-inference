//! Reading fields out of a raw SEV-SNP attestation report.

use crate::VerifyError;

/// Offset of MEASUREMENT in the report, per AMD's SEV Secure Nested Paging
/// ABI (table "ATTESTATION_REPORT Structure"). 48 bytes of SHA-384.
const MEASUREMENT_OFFSET: usize = 0x90;
const MEASUREMENT_LEN: usize = 48;

/// Hex launch measurement, lowercase, as the V-PROGRAM message encodes it.
pub fn launch_measurement(report: &[u8]) -> Result<String, VerifyError> {
    let end = MEASUREMENT_OFFSET + MEASUREMENT_LEN;
    if report.len() < end {
        return Err(VerifyError::ShortReport { len: report.len() });
    }
    Ok(hex::encode(&report[MEASUREMENT_OFFSET..end]))
}

/// Offset of REPORT_DATA: 64 caller-supplied bytes the platform signs verbatim.
const REPORT_DATA_OFFSET: usize = 0x50;
const REPORT_DATA_LEN: usize = 64;

/// The 64 bytes of REPORT_DATA, as signed.
pub fn report_data(report: &[u8]) -> Result<[u8; REPORT_DATA_LEN], VerifyError> {
    let end = REPORT_DATA_OFFSET + REPORT_DATA_LEN;
    if report.len() < end {
        return Err(VerifyError::ShortReport { len: report.len() });
    }
    let mut out = [0u8; REPORT_DATA_LEN];
    out.copy_from_slice(&report[REPORT_DATA_OFFSET..end]);
    Ok(out)
}
