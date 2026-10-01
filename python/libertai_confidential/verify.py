"""Verification, plus the one thing it deliberately cannot do: fetch.

The core is a compiled Rust library shared with the other clients; network
access belongs to the host, so the VCEK arrives as an argument.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Optional, Sequence

import httpx

from ._core import AttestationError, check_tcb, report_facts, vcek_url, verify
from ._net import new_client

__all__ = [
    "AttestationError",
    "TcbFloor",
    "report_facts",
    "verify_certificate",
    "vcek_cache_dir",
]

#: AMD asks for roughly one request per second per address, and says so with a 429.
_RETRY_DELAYS = (1.0, 3.0, 7.0)


@dataclass(frozen=True)
class TcbFloor:
    """Minimum acceptable platform firmware.

    A chip running firmware with a known escape still gets a valid VCEK, so the
    signature chain alone cannot answer "is this platform patched". The floor is
    policy, so it is the caller's, and it has to be raised whenever AMD
    publishes an SEV firmware advisory.
    """

    bootloader: int
    tee: int
    snp: int
    microcode: int


def vcek_cache_dir() -> str:
    return os.path.join(tempfile.gettempdir(), "libertai-vcek")


def _cache_path(url: str) -> str:
    name = hashlib.sha256(url.encode()).hexdigest()[:32]
    return os.path.join(vcek_cache_dir(), f"{name}.der")


def _load_vcek(url: str, client: httpx.Client) -> bytes:
    """VCEKs are public certificates whose signature is checked before use, so
    caching them on disk costs nothing and keeps a restarting process out of
    AMD's rate limit."""
    path = _cache_path(url)
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        pass

    last = ""
    for attempt in range(len(_RETRY_DELAYS) + 1):
        res = client.get(url)
        if res.status_code == 200:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f:
                    f.write(res.content)
            except OSError:
                # A read-only or full disk costs a round trip, not correctness.
                pass
            return res.content
        last = f"AMD KDS returned {res.status_code}"
        if not (res.status_code == 429 or res.status_code >= 500) or attempt >= len(_RETRY_DELAYS):
            break
        time.sleep(_RETRY_DELAYS[attempt])
    raise AttestationError(f"{last} for {url}")


def verify_certificate(
    cert_der: bytes,
    measurements: Sequence[str],
    *,
    tcb_floor: Optional[TcbFloor] = None,
    client: Optional[httpx.Client] = None,
) -> str:
    """Establish that this certificate belongs to a guest AMD endorses, that is
    not debuggable, that serves the key it attests to, and that booted one of
    the published images. Returns the measurement that matched."""
    url = vcek_url(cert_der)
    vcek = _load_vcek(url, client or new_client())
    matched = verify(cert_der, vcek, list(measurements))
    if tcb_floor is not None:
        check_tcb(
            cert_der,
            tcb_floor.bootloader,
            tcb_floor.tee,
            tcb_floor.snp,
            tcb_floor.microcode,
        )
    return matched
