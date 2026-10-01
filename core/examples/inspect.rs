//! Prints what a captured RA-TLS certificate attests to, and the KDS URL of
//! the VCEK needed to verify it:
//!
//!   openssl s_client -connect <host>:8443 </dev/null 2>/dev/null |
//!     openssl x509 -outform der -out cert.der
//!   cargo run -p confidential-inference-core --example inspect -- cert.der

use confidential_inference_core::{attestation_from_cert, binding, chain};

fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect <cert.der>");
    let der = std::fs::read(&path).expect("cert unreadable");
    let att = attestation_from_cert(&der).expect("no attestation in certificate");
    let report = chain::parse_report(&att.data).expect("malformed report");

    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("tee_type      {}", att.tee_type);
    println!("version       {}", report.version);
    println!("product       {:?}", chain::product(&report).unwrap());
    println!("measurement   {}", hex(&report.measurement));
    println!("report_data   {}", hex(&report.report_data));
    println!("chip_id       {}", hex(&report.chip_id));
    println!("reported_tcb  {:?}", report.reported_tcb);
    println!("policy        debug_allowed={} smt={}", report.policy.debug_allowed(), report.policy.smt_allowed());
    println!("key binding   {:?}", binding::check_key_binding(&der, &att.data));
    println!("vcek          {}", chain::vcek_url(&report).unwrap());
}
