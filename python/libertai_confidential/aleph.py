"""Fetching Aleph messages.

Deciding whether to believe them happens in the verification core, which Python
and JavaScript share, so hashing and signature rules have one implementation
rather than one per language.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from ._core import AlephError, verify_aleph_message
from ._net import new_client

DEFAULT_API = "https://api.aleph.im"

__all__ = ["AlephError", "DEFAULT_API", "verify_message", "fetch_message", "fetch_aggregate"]


def verify_message(message: Any, expected_sender: Optional[str] = None) -> Any:
    """The content is what the hash names, and the sender really signed it."""
    return json.loads(verify_aleph_message(json.dumps(message), expected_sender))


def fetch_message(
    item_hash: str,
    *,
    api: str = DEFAULT_API,
    sender: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> Any:
    """Fetch one message by hash and establish that it is what that hash names."""
    http = client or new_client()
    res = http.get(f"{api}/api/v0/messages.json", params={"hashes": item_hash})
    res.raise_for_status()
    messages = res.json().get("messages") or []
    if not messages:
        raise AlephError(f"message {item_hash} not found")
    return verify_message(messages[0], sender)


def fetch_aggregate(
    address: str,
    key: str,
    *,
    api: str = DEFAULT_API,
    client: Optional[httpx.Client] = None,
) -> Any:
    """The manifest this address published under ``key``, verified.

    Aleph merges an aggregate from every message that ever targeted the key, so
    a client that verifies signatures itself cannot use the merged view the API
    serves: the merge is the node's work, not the publisher's. Instead each
    publish carries the complete manifest and the newest signed message wins.
    The node can withhold an update but it cannot forge one, and a withheld
    update is why a deployment is revoked by deleting the V-PROGRAM rather than
    by editing this.
    """
    http = client or httpx.Client(timeout=30)
    res = http.get(
        f"{api}/api/v0/messages.json",
        params={"addresses": address, "msgType": "AGGREGATE", "pagination": 50, "page": 1},
    )
    res.raise_for_status()

    newest = None
    for message in res.json().get("messages") or []:
        try:
            content = verify_message(message, address)
        except AlephError:
            # A message we cannot verify is one we must not read, but it says
            # nothing about the others.
            continue
        if content.get("key") != key:
            continue
        when = content.get("time") or 0
        if newest is None or when > newest[0]:
            newest = (when, content.get("content"))
    if newest is None:
        raise AlephError(f'{address} published no aggregate under key "{key}"')
    return newest[1]
