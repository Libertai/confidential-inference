"""Turning a published deployment into something a client can connect to.

Only the measurements matter for trust, and they come from a message whose hash
the client recomputes. Everything else here -- which node runs it, which address
and port answer -- is a hint from an untrusted source: point the client at the
wrong machine and attestation fails, so a lie costs the liar a failed
connection, not a leaked prompt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urljoin

import httpx

from ._net import ipv6_works, new_client
from .aleph import DEFAULT_API, AlephError, fetch_message

#: Port the attest-agent listens on inside the guest; the only one open.
GUEST_PORT = 8443

DEFAULT_SCHEDULER = "https://scheduler.api.aleph.cloud"

__all__ = ["Deployment", "resolve_deployment", "DEFAULT_SCHEDULER"]


@dataclass(frozen=True)
class Deployment:
    item_hash: str
    #: Launch digests the deployment published, one per vCPU type.
    measurements: List[str]
    #: Publisher of the V-PROGRAM message.
    sender: str
    #: Origins to try, most widely reachable first.
    candidates: List[str]


def resolve_deployment(
    item_hash: str,
    *,
    api: str = DEFAULT_API,
    scheduler: str = DEFAULT_SCHEDULER,
    sender: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> Deployment:
    http = client or new_client()
    message = fetch_message(item_hash, api=api, sender=sender, client=http)

    measurements = [
        m["registers"]["launch"]
        for m in (message.get("verification") or {}).get("measurements") or []
        if isinstance(m.get("registers", {}).get("launch"), str)
    ]
    if not measurements:
        raise AlephError(f"{item_hash} publishes no launch measurement: not a confidential VM")

    return Deployment(
        item_hash=item_hash,
        measurements=measurements,
        sender=message["address"],
        candidates=[f"https://{_format(h)}:{p}" for h, p in _locate(item_hash, scheduler, http)],
    )


def _locate(item_hash: str, scheduler: str, http: httpx.Client) -> List[Tuple[str, int]]:
    """Ask the scheduler which node runs this, then that node how to reach it."""
    res = http.get(f"{scheduler}/api/v0/allocation/{item_hash}")
    if res.status_code != 200:
        raise AlephError(f"{item_hash} is not allocated to any node ({res.status_code})")
    allocation = res.json()

    endpoints: List[Tuple[str, int]] = []
    # The node forwards a host port to the guest's 8443. A client with only
    # IPv4 has no other way in, so this is tried first.
    node_url = (allocation.get("node") or {}).get("url")
    if node_url:
        try:
            listing = http.get(urljoin(node_url, "/v2/about/executions/list")).json()
            net = (listing.get(item_hash) or {}).get("networking") or {}
            mapped = (net.get("mapped_ports") or {}).get(str(GUEST_PORT)) or {}
            if net.get("host_ipv4") and mapped.get("host"):
                endpoints.append((net["host_ipv4"], int(mapped["host"])))
        except Exception:
            # The node being unreachable or terse is not fatal: IPv6 may work.
            pass
    # Offering an IPv6 address to a host that cannot route there only buys a
    # stall before the fallback.
    if allocation.get("vm_ipv6") and ipv6_works():
        endpoints.append((allocation["vm_ipv6"], GUEST_PORT))
    if not endpoints:
        raise AlephError(f"no reachable address for {item_hash}")
    return endpoints


def _format(host: str) -> str:
    return f"[{host}]" if ":" in host else host
