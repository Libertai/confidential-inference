# libertai-confidential-inference

A client for LibertAI models that run inside AMD SEV-SNP virtual machines, where
the operator of the machine cannot read the requests being processed. It checks
the server's attestation before sending anything.

```bash
pip install libertai-confidential-inference openai
```

```python
from openai import OpenAI
from libertai_confidential import connect

tee = connect(model="qwen3.8-27b-tee")
client = OpenAI(api_key=key, base_url=tee.base_url, http_client=tee.http_client)

answer = client.chat.completions.create(
    model="qwen3.8-27b-tee",
    messages=[{"role": "user", "content": "..."}],
)
```

API keys come from [console.libertai.io](https://console.libertai.io). Requests
go straight to the enclave, so nothing in between can read them, LibertAI's API
included.

Pass `tee.http_client` along with `tee.base_url`: an ordinary client reaches the
same address without checking anything about it. It is an `httpx2.Client` when
that is installed, which is what `openai` 3.x expects, and an `httpx.Client`
otherwise. To build your own, `tee.ssl_context` is the context it is pinned to:

```python
client = httpx2.Client(verify=tee.ssl_context, timeout=600)
```

## connect(...)

| Argument | |
| --- | --- |
| `model` | Use the active deployment for that model. |
| `item_hash` | Pin one deployment and skip discovery. |
| `tcb_floor` | Reject CPUs below a firmware version. Raise it when AMD publishes an advisory. |
| `publisher`, `api`, `scheduler` | Override the manifest publisher and the Aleph endpoints. |

Returns a `ConfidentialEndpoint` with `base_url`, `http_client`, `ssl_context`,
`item_hash`, `measurement` and `source_commit`, or raises if the server fails
any check, in which case no request was sent.

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
