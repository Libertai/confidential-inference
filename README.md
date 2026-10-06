# confidential-inference

LibertAI runs some models inside AMD SEV-SNP virtual machines, where the
operator of the machine cannot read the requests being processed. This
repository holds the client libraries that confirm a server really is one of
those VMs before sending it anything, and the build recipe for the VM itself.

The check runs in the client, against AMD's signature chain and a measurement
published on Aleph, so it does not depend on trusting LibertAI.

## How it works

The model server is an Aleph V-PROGRAM: a SEV-SNP VM with measured boot. As the
VM starts, the CPU hashes everything that defines it (firmware, kernel, kernel
command line, and the dm-verity root hash of each disk image) into a single
value, the launch measurement. The CPU will then sign reports containing that
value, with a key AMD vouches for.

The VM serves HTTPS with a certificate it generates at boot, and embeds one of
those signed reports in the certificate. The report commits to that
certificate's public key.

So during the TLS handshake a client checks four things:

1. AMD signed the report (ARK → ASK → VCEK → report).
2. The report is bound to the key the server is actually using. Without this,
   someone could relay a real enclave's report in front of their own key.
3. The launch measurement is one this deployment published. That is what ties
   the peer to a specific model, image and set of serving flags.
4. The guest is not debuggable, which would otherwise let the host read the
   guest's memory directly.

If any of them fails the client refuses the connection, so nothing is sent.

Where the expected measurement comes from matters too. The client reads it from
the deployment's Aleph message, whose hash is the hash of its own content, and
that message is named by a manifest signed by LibertAI. The address and port
come from a scheduler the client does not trust: point it at the wrong machine
and attestation just fails.

## What's here

| | |
| --- | --- |
| `core/` | The verification itself, in Rust. No network, no platform assumptions. |
| `wasm/`, `js/`, `python/` | Bindings and clients. They wrap the same compiled core, so there is one implementation of the checks rather than one per language. |
| `deployment/` | What the enclave runs: guest init, vLLM flags, the gateway. Every input to the measurement is pinned here. |

The clients are [`@libertai/confidential-inference`](js) for Node and
[`libertai-confidential-inference`](python) for Python.

## Checking a deployment yourself

A measurement identifies an image, not its contents. To see what the image
actually holds, rebuild it from `deployment/` and compare the result against
what the deployment published. [`VERIFYING.md`](VERIFYING.md) walks through it;
you need Linux, Nix and about 75 GB of disk.

## Tests

The fixtures are a real certificate captured from the live deployment and the
real VCEK AMD issued for that chip, so the tests break if a wire format drifts.

```bash
cargo test
cd js && npm run build && npm test
cd python && maturin develop && pytest
```

To inspect a certificate by hand:

```bash
openssl s_client -connect <host>:<port> </dev/null 2>/dev/null |
  openssl x509 -outform der -out cert.der
cargo run -p confidential-inference-core --example inspect -- cert.der
```
