"""Which deployments a publisher currently stands behind.

The manifest holds item hashes, not measurements: a measurement is already
inside the V-PROGRAM message the hash names, and a hash is content-addressed,
so repeating the digest here would only create something to disagree with. It
holds no endpoints either -- those move -- and no versions: clients take what
is active.
"""

from __future__ import annotations

from typing import Any, List, Optional

import httpx

from .aleph import DEFAULT_API, fetch_aggregate

#: Address whose signature makes a manifest LibertAI's.
DEFAULT_PUBLISHER = "0x238224C744F4b90b4494516e074D2676ECfC6803"
AGGREGATE_KEY = "confidential-inference"

__all__ = ["DEFAULT_PUBLISHER", "AGGREGATE_KEY", "fetch_manifest", "active_deployments"]


def fetch_manifest(
    *,
    publisher: str = DEFAULT_PUBLISHER,
    api: str = DEFAULT_API,
    client: Optional[httpx.Client] = None,
) -> Any:
    return fetch_aggregate(publisher, AGGREGATE_KEY, api=api, client=client)


def active_deployments(manifest: Any, model: str) -> List[Any]:
    entry = (manifest.get("models") or {}).get(model)
    if entry is None:
        known = ", ".join((manifest.get("models") or {}).keys()) or "none"
        raise LookupError(f'no model "{model}" in the manifest (published: {known})')
    active = [d for d in entry["deployments"] if d.get("status") == "active"]
    if not active:
        raise LookupError(f'every deployment of "{model}" is deprecated')
    return active
