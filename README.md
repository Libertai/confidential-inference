# confidential-inference

Client-side verification for LibertAI inference running in a confidential VM.

The server is an Aleph V-PROGRAM: an AMD SEV-SNP guest with measured boot,
serving an OpenAI-compatible API behind RA-TLS. Its TLS certificate carries an
SNP attestation report, so a client can decide *before sending a prompt* that it
is talking to the published workload and not to a host that can read it.

## Layout

- `core/` — `confidential-inference-core`, the verification itself. No network,
  no platform assumptions; builds for `wasm32-unknown-unknown`.
- `wasm/` — `wasm-bindgen` wrapper, so JavaScript runs the same checks rather
  than a second implementation of them.
- `js/` — `@libertai/confidential-inference`: discovery, an attesting
  transport, and a `fetch` to hand to the OpenAI SDK.

## What a verified connection means

`verify(cert_der, vcek_der, expected_measurements)` establishes, in order:

1. **AMD endorses the report** — ARK → ASK → VCEK → report. The ARK and ASK are
   compiled in from the `sev` crate, so trust ends at AMD, not at whoever served
   the certificate. Only the per-chip VCEK is fetched (`vcek_url`), and it is
   self-authenticating.
2. **The guest is not debuggable** — `DEBUG_ALLOWED` would let the host read
   guest memory, which makes every other check decorative.
3. **The report commits to the served TLS key** — otherwise a genuine report
   can be relayed in front of an attacker's key.
4. **The measurement is one the deployment published** — this is what ties the
   peer to a specific workload image, model and serving flags.

Firmware currency is policy rather than fact, so `chain::check_tcb` takes the
floor from the caller instead of hardcoding one that goes stale.

## Tests

`core/tests/` runs against a certificate captured from the live H200
deployment and the measurements from its published Aleph message, so the tests
fail if either wire format drifts.

    cargo test
    cargo run -p confidential-inference-core --example inspect -- cert.der
    cd js && npm run build && npm test
