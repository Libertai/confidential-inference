#!/usr/bin/env python3
"""Check a deployment manifest before, or after, it is published.

    python scripts/check_manifest.py                 # the published aggregate
    python scripts/check_manifest.py candidate.json  # a draft, before publishing

The manifest lives in the signed Aleph aggregate, not in this repository, so
there is one copy and it cannot drift. Publish it with the CLI:

    aleph aggregate create --key confidential-inference --content "$(cat candidate.json)"

A client checks that the manifest was signed by the expected address, not that
what it says is true, so everything checkable is checked here:

  * every `source_commit` is a commit of this repository, since a client is told
    to check it out,
  * every referenced V-PROGRAM message exists and verifies against its hash,
  * every one of them publishes a launch measurement,
  * every active deployment is reachable and proves one of those measurements.

A deployment is retired by deleting the V-PROGRAM, not by editing this file: a
client can be handed a stale manifest, but it cannot be handed a running
enclave that no longer exists.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from libertai_confidential import connect, fetch_manifest, resolve_deployment  # noqa: E402


def check(manifest: dict) -> list[str]:
    problems = []
    if "REPLACE-ME" in manifest.get("source_repo", ""):
        problems.append("source_repo is still a placeholder")

    for model, entry in (manifest.get("models") or {}).items():
        for deployment in entry["deployments"]:
            item_hash = deployment["item_hash"]
            label = f"{model} {item_hash[:12]}"

            # VERIFYING.md tells a reader to `git checkout` this, so a hash from
            # another repository fails them at the first step.
            commit = deployment.get("source_commit")
            if not commit:
                problems.append(f"{label}: no source_commit")
            elif subprocess.run(
                ["git", "-C", str(REPO), "cat-file", "-e", f"{commit}^{{commit}}"],
                capture_output=True,
            ).returncode:
                problems.append(f"{label}: source_commit {commit} is not a commit of this repository")

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


def main() -> int:
    if len(sys.argv) > 1:
        source = Path(sys.argv[1])
        manifest = json.loads(source.read_text())
        print(f"checking {source}")
    else:
        source = "the published aggregate"
        manifest = fetch_manifest()
        if manifest is None:
            print("nothing published under this key yet", file=sys.stderr)
            return 1
        print(f"checking {source}")

    problems = check(manifest)
    if problems:
        print()
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print()
    print("every deployment checks out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
