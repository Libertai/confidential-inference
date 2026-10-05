"""Talk to LibertAI inference running in a confidential VM, having first
established what it is.

    from openai import OpenAI
    from libertai_confidential import connect

    tee = connect(model="qwen3.8-27b")
    client = OpenAI(api_key=key, base_url=tee.base_url, http_client=tee.http_client)

The client talks to the enclave directly. Nothing in between can read the
prompt, LibertAI included: an intermediary that could would defeat the point of
running the model in a TEE at all.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Any, List, Optional

import httpx

from ._core import AlephError, AttestationError
from .aleph import DEFAULT_API, fetch_aggregate, fetch_message, verify_message
from .deployment import DEFAULT_SCHEDULER, Deployment, resolve_deployment
from .manifest import AGGREGATE_KEY, DEFAULT_PUBLISHER, active_deployments, fetch_manifest
from .transport import attested_client, attested_ssl_context, client_for
from .verify import TcbFloor, report_facts, verify_certificate

__all__ = [
    "AlephError",
    "AttestationError",
    "ConfidentialEndpoint",
    "Deployment",
    "TcbFloor",
    "connect",
    "fetch_manifest",
    "fetch_message",
    "report_facts",
    "resolve_deployment",
    "client_for",
    "verify_certificate",
]


@dataclass
class ConfidentialEndpoint:
    #: Pass to an OpenAI-compatible client; ends in ``/v1``, as they expect.
    base_url: str
    #: Pass alongside it: an ordinary client would reach the same address
    #: without proving anything about it. Typed loosely on purpose -- it is an
    #: ``httpx2.Client`` when that is installed, which is what `openai` 3.x
    #: annotates, and an ``httpx.Client`` otherwise.
    http_client: Any
    #: The context ``http_client`` is pinned to, for building your own client.
    ssl_context: ssl.SSLContext
    #: V-PROGRAM that answered.
    item_hash: str
    #: Launch measurement it proved, which is what pins the image and flags.
    measurement: str
    #: Commit the images were built from, when the manifest names one.
    source_commit: Optional[str] = None


def connect(
    *,
    model: Optional[str] = None,
    item_hash: Optional[str] = None,
    manifest: Optional[Any] = None,
    publisher: str = DEFAULT_PUBLISHER,
    api: str = DEFAULT_API,
    scheduler: str = DEFAULT_SCHEDULER,
    tcb_floor: Optional[TcbFloor] = None,
) -> ConfidentialEndpoint:
    """Find a deployment, prove what it is, and return a client-ready endpoint.

    The returned client is pinned to the certificate that was verified, so it
    cannot later be answered by a peer that was never attested.
    """
    if item_hash is not None:
        entries: List[Any] = [{"item_hash": item_hash, "status": "active"}]
    elif model is not None:
        entries = active_deployments(
            manifest if manifest is not None else fetch_manifest(publisher=publisher, api=api),
            model,
        )
    else:
        raise TypeError("connect() needs a model or an item_hash")

    failures = []
    for entry in entries:
        try:
            deployment = resolve_deployment(
                entry["item_hash"], api=api, scheduler=scheduler, sender=publisher
            )
        except Exception as e:
            failures.append(f"{entry['item_hash'][:12]}: {e}")
            continue
        for origin in deployment.candidates:
            try:
                client, context, measurement = attested_client(
                    origin, deployment.measurements, tcb_floor=tcb_floor
                )
                return ConfidentialEndpoint(
                    base_url=f"{origin}/v1",
                    http_client=client,
                    ssl_context=context,
                    item_hash=entry["item_hash"],
                    measurement=measurement,
                    source_commit=entry.get("source_commit"),
                )
            except Exception as e:
                failures.append(f"{origin}: {e}")
    raise AttestationError(
        "no deployment could be verified and reached:\n  " + "\n  ".join(failures)
    )
