# @libertai/confidential-inference

A client for LibertAI models that run inside AMD SEV-SNP virtual machines, where
the operator of the machine cannot read the requests being processed. It checks
the server's attestation before sending anything.

```bash
npm install @libertai/confidential-inference openai
```

```ts
import OpenAI from "openai";
import { connect } from "@libertai/confidential-inference";

const tee = await connect({ model: "qwen3.8-27b-tee" });
const openai = new OpenAI({ apiKey, baseURL: tee.baseURL, fetch: tee.fetch });

const answer = await openai.chat.completions.create({
  model: "qwen3.8-27b-tee",
  messages: [{ role: "user", content: "..." }],
});
```

API keys come from [console.libertai.io](https://console.libertai.io). Requests
go straight to the enclave, so nothing in between can read them, LibertAI's API
included.

Pass `tee.fetch` along with `tee.baseURL`: the built-in `fetch` reaches the same
address without checking anything about it.

## connect(options)

| Option | |
| --- | --- |
| `model` | Use the active deployment for that model. |
| `itemHash` | Pin one deployment and skip discovery. |
| `tcbFloor` | Reject CPUs below a firmware version. Raise it when AMD publishes an advisory. |
| `signal` | `AbortSignal`. |
| `publisher`, `api`, `scheduler` | Override the manifest publisher and the Aleph endpoints. |

Resolves to `{ baseURL, fetch, itemHash, measurement, sourceCommit }`, or throws
if the server fails any check, in which case no request was sent.

`model` is resolved through a manifest signed by LibertAI, naming a deployment
message whose hash the client recomputes from its content. The address itself
comes from a scheduler that is not trusted: a wrong host just fails attestation.

## What gets checked

Before the first byte of a request is written:

- AMD signed the attestation report, through ARK → ASK → VCEK. Only the per-chip
  VCEK is fetched, and it is self-authenticating.
- The report is bound to the TLS key being served, so a genuine report cannot be
  replayed in front of someone else's key.
- The launch measurement is one the deployment published, which is what ties the
  server to a specific model, image and set of serving flags.
- The guest is not debuggable, which would otherwise let the host read its
  memory.

A measurement identifies which image booted, not what that image does. To check
that, rebuild it from source and compare:
[VERIFYING.md](https://github.com/Libertai/confidential-inference/blob/main/VERIFYING.md).

## Node only

Reading the certificate before any request goes out needs a TLS API that
browsers do not expose. A browser would need a local verifying proxy, or a TLS
stack in WebAssembly over WebTransport.
