# libertai-confidential-inference

Talk to LibertAI inference running in a confidential VM, having first
established what it is.

```bash
pip install libertai-confidential-inference openai
```

```python
from openai import OpenAI
from libertai_confidential import connect

tee = connect(model="qwen3.8-27b")
client = OpenAI(api_key=key, base_url=tee.base_url, http_client=tee.http_client)

answer = client.chat.completions.create(
    model="qwen3.8-27b",
    messages=[{"role": "user", "content": "..."}],
)
```

Requests go straight to the enclave. Nothing in between can read the prompt,
LibertAI included — an intermediary that could would defeat the point.

Pass `tee.http_client` as well as `tee.base_url`: an ordinary client would
reach the same address without proving anything about it.

## What a connection proves

The server is an AMD SEV-SNP guest whose TLS certificate carries a signed
attestation report. `connect` fetches that certificate on a throwaway
connection, and only once it has established all of the following does it pin
it as the sole trust anchor for the client that carries requests:

1. **AMD endorses the report** — ARK → ASK → VCEK → report. AMD's roots are
   compiled in, so trust ends at AMD rather than at whoever served the
   certificate. Only the per-chip VCEK is fetched, and it is self-authenticating.
2. **The guest is not debuggable** — otherwise the host could read its memory
   and every other check would be decorative.
3. **The report commits to the key being served** — otherwise a genuine report
   could be relayed in front of an attacker's key.
4. **The launch measurement is one the deployment published** — this is what
   ties the peer to a specific image, model and set of serving flags.

A peer that fails is never sent a prompt, and a peer that passes cannot be
swapped for another afterwards.

## What it does not prove

- **That the workload deserves trust.** The measurement pins *which* image
  booted, not what it does. The manifest names the `source_commit` the images
  were built from; the point of publishing it is that anyone can rebuild them
  and check that the measurement is the one they get.
- **That the platform is patched.** A chip running vulnerable firmware still
  gets a valid VCEK. Firmware currency is policy, so it is a caller's decision:
  pass `tcb_floor=TcbFloor(...)` to set one, and raise it when AMD publishes an
  advisory.

## Discovery

`connect(model=...)` reads a manifest published as a signed Aleph aggregate.
No node is trusted along the way: the manifest is verified against the
publisher's signature, each `item_hash` names a V-PROGRAM message whose content
the client re-hashes, and the measurements come from there. Which machine runs
it and at which address are hints from an untrusted scheduler — point a client
at the wrong host and attestation fails.

Use `connect(item_hash=...)` to pin one deployment and skip discovery entirely.

## One implementation of the checks

Hashing, signature recovery and report verification live in a Rust core shared
with the JavaScript client, so there is nothing for the two to disagree about.
