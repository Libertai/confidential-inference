#!/usr/bin/env python3
"""Publish the deployment manifest as a signed Aleph aggregate.

    python scripts/publish_manifest.py manifest.json            # check only
    python scripts/publish_manifest.py manifest.json --publish

Publishing is what makes `connect(model=...)` work, and it is the one step a
client cannot second-guess: a client checks that the manifest was signed by the
expected address, not that what it says is true. So everything checkable is
checked here first, and nothing is published unless it all holds:

  * every referenced V-PROGRAM message exists and verifies against its hash,
  * every one of them publishes a launch measurement,
  * every active deployment is reachable and proves one of those measurements.

A deployment is retired by deleting the V-PROGRAM, not by editing this file: a
client can be handed a stale manifest, but it cannot be handed a running
enclave that no longer exists.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from libertai_confidential import connect, resolve_deployment  # noqa: E402
from libertai_confidential.manifest import AGGREGATE_KEY  # noqa: E402

CCN = "https://api3.aleph.im"


def check(manifest: dict) -> list[str]:
    problems = []
    if "REPLACE-ME" in manifest.get("source_repo", ""):
        problems.append("source_repo is still a placeholder")

    for model, entry in (manifest.get("models") or {}).items():
        for deployment in entry["deployments"]:
            item_hash = deployment["item_hash"]
            label = f"{model} {item_hash[:12]}"
            try:
                resolved = resolve_deployment(item_hash)
            except Exception as e:
                problems.append(f"{label}: {e}")
                continue
            print(f"  {label}: publishes {len(resolved.measurements)} measurement(s)")

            if deployment.get("status") != "active":
                continue
            try:
                tee = connect(item_hash=item_hash)
                print(f"  {label}: verified at {tee.base_url}")
            except Exception as e:
                problems.append(f"{label}: active but not verifiable: {e}")
    return problems


async def publish(manifest: dict) -> None:
    from aleph.sdk.chains.ethereum import ETHAccount
    from aleph.sdk.client import AuthenticatedAlephHttpClient
    from aleph.sdk.conf import settings

    account = ETHAccount(Path(settings.PRIVATE_KEY_FILE).read_bytes())
    print(f"publishing as {account.get_address()}")
    async with AuthenticatedAlephHttpClient(account=account, api_server=CCN) as client:
        message, status = await client.create_aggregate(
            key=AGGREGATE_KEY, content=manifest, inline=True
        )
        print(f"{status}: {message.item_hash}")


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "manifest.json")
    manifest = json.loads(path.read_text())

    print(f"checking {path}")
    problems = check(manifest)
    if problems:
        print("\nnot publishable:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nevery deployment checks out")

    if "--publish" not in sys.argv:
        print("re-run with --publish to sign and publish it")
        return 0
    asyncio.run(publish(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
