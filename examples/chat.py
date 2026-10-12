#!/usr/bin/env python3
"""Run one completion against LibertAI confidential inference.

    pip install libertai-confidential-inference openai
    export LIBERTAI_API_KEY=...
    python examples/chat.py

The enclave is proved before anything is sent, so a failure here means no
prompt left the machine.
"""

import os
import sys

from libertai_confidential import connect
from openai import OpenAI

MODEL = "qwen3.8-27b-tee"

key = os.environ.get("LIBERTAI_API_KEY")
if not key:
    sys.exit("set LIBERTAI_API_KEY (get one at https://console.libertai.io)")

# Resolves the model through the manifest LibertAI signed, proves the enclave
# behind it, and pins the certificate that was proved. Pass item_hash=... to
# target one deployment instead.
tee = connect(model=MODEL)

print(f"verified {MODEL}")
print(f"  endpoint    {tee.base_url}")
print(f"  deployment  {tee.item_hash}")
print(f"  measurement {tee.measurement}")
print(f"  built from  {tee.source_commit}")
print()

# Pinned to the attested certificate, so the request goes straight to the
# enclave: nothing in between can read it, LibertAI included.
client = OpenAI(api_key=key, base_url=tee.base_url, http_client=tee.http_client)

prompt = "In one sentence: what does AMD SEV-SNP protect against?"

answer = client.chat.completions.create(
    model=MODEL,
    messages=[{"role": "user", "content": prompt}],
    max_tokens=300,
    temperature=0,
)

choice = answer.choices[0]
print(f"> {prompt}")
print()
print(choice.message.content.strip())
print()
print(f"{answer.usage.prompt_tokens} prompt + {answer.usage.completion_tokens} completion tokens, {choice.finish_reason}")
