# @libertai/confidential-inference

Talk to LibertAI inference running in a confidential VM, having first
established what it is.

```bash
npm install @libertai/confidential-inference openai
```

```ts
import OpenAI from "openai";
import { connect } from "@libertai/confidential-inference";

const tee = await connect({ model: "qwen3.8-27b" });
const openai = new OpenAI({ apiKey, baseURL: tee.baseURL, fetch: tee.fetch });

const answer = await openai.chat.completions.create({
  model: "qwen3.8-27b",
  messages: [{ role: "user", content: "..." }],
});
```

Requests go straight to the enclave. Nothing in between can read the prompt,
LibertAI included — an intermediary that could would defeat the point.

Pass `tee.fetch` as well as `tee.baseURL`: the default `fetch` would reach the
same address without proving anything about it.

## What a connection proves

The server is an AMD SEV-SNP guest whose TLS certificate carries a signed
attestation report. Before the first byte of a request is written, the client
establishes that:

1. **AMD endorses the report** — ARK → ASK → VCEK → report. AMD's roots are
   compiled in, so trust ends at AMD rather than at whoever served the
   certificate. Only the per-chip VCEK is fetched, and it is self-authenticating.
2. **The guest is not debuggable** — otherwise the host could read its memory
   and every other check would be decorative.
3. **The report commits to the key being served** — otherwise a genuine report
   could be relayed in front of an attacker's key.
4. **The launch measurement is one the deployment published** — this is what
   ties the peer to a specific image, model and set of serving flags.

If any of those fail the connection is refused, so a failed check means no
prompt was sent, rather than one sent and regretted.

## What it does not prove

- **That the workload deserves trust.** The measurement pins *which* image
  booted, not what it does. The manifest names the `source_commit` the images
  were built from; the point of publishing it is that anyone can rebuild them
  and check that the measurement is the one they get.
- **That the platform is patched.** A chip running vulnerable firmware still
  gets a valid VCEK. Firmware currency is policy, so it is a caller's decision:
  pass `tcbFloor` to set one, and raise it when AMD publishes an advisory.

## Discovery

`connect({ model })` reads a manifest published as a signed Aleph aggregate:

```json
{
  "source_repo": "https://github.com/libertai/...",
  "models": {
    "qwen3.8-27b": {
      "deployments": [
        { "item_hash": "f45e4…", "source_commit": "b5a6720", "status": "active" }
      ]
    }
  }
}
```

No node is trusted along the way. The manifest is verified against the
publisher's signature; each `item_hash` names a V-PROGRAM message whose content
the client re-hashes, and the measurements come from there. Which machine runs
it and at which address are hints from an untrusted scheduler — point a client
at the wrong host and attestation fails.

Revoking a deployment means deleting the V-PROGRAM, not just marking it
deprecated: a client can be served a stale manifest, but it cannot be served a
running enclave that no longer exists.

Use `connect({ itemHash })` to pin one deployment and skip discovery entirely.

## CLI

```bash
npx @libertai/confidential-inference               # what is published
npx @libertai/confidential-inference qwen3.8-27b   # verify and report
```

## Node only, for now

Verification needs the peer's certificate before any request is sent, which
needs a TLS API browsers do not expose. The verification core is compiled to
WebAssembly and runs anywhere; the transport is what is Node-specific. A browser
client needs either a local verifying proxy or a TLS stack in WASM over
WebTransport.

## Tests

`npm test` runs offline against a certificate captured from a live deployment
and the VCEK AMD issued for that chip, so no test touches the network. Setting
`LIBERTAI_ITEM_HASH` adds one that connects for real.
