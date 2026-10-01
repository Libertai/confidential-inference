"""Audit a deployment from a terminal:

    libertai-confidential <item-hash|model>

Prints what the peer proved, so a deployment can be checked without writing a
program. It says nothing about what the workload does with a prompt -- that is
what ``source_commit`` and a rebuild are for.
"""

from __future__ import annotations

import re
import sys

from . import connect
from .manifest import fetch_manifest


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target is None:
        manifest = fetch_manifest()
        print(f"source: {manifest.get('source_repo')}")
        for model, entry in (manifest.get("models") or {}).items():
            active = sum(1 for d in entry["deployments"] if d.get("status") == "active")
            print(f"  {model}  {active} active")
        print("\npass a model or an item hash to verify one")
        return 0

    is_hash = re.fullmatch(r"[0-9a-f]{64}", target) is not None
    tee = connect(item_hash=target) if is_hash else connect(model=target)
    print(f"verified     {tee.base_url}")
    print(f"item hash    {tee.item_hash}")
    print(f"measurement  {tee.measurement}")
    if tee.source_commit:
        print(f"built from   {tee.source_commit}")
    models = tee.http_client.get(f"{tee.base_url}/models").json()["data"]
    print(f"serving      {', '.join(m['id'] for m in models)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
