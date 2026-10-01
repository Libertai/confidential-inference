"""A transport that attests before it speaks.

The guest serves a self-signed certificate, so the usual PKI check is
meaningless here. What replaces it is stronger: the certificate carries an
AMD-signed report that commits to the key being served and to the image that
booted.

The certificate is fetched and verified on a throwaway connection first, and
only then pinned as the sole trust anchor for the client that carries requests.
So a peer that fails attestation is never sent a prompt, and a peer that passes
cannot be swapped for another afterwards.
"""

from __future__ import annotations

import socket
import ssl
from typing import Optional, Sequence, Tuple
from urllib.parse import urlsplit

import httpx

from ._net import new_client
from .verify import AttestationError, TcbFloor, verify_certificate

__all__ = ["attested_ssl_context", "attested_client"]


#: How long one address may take to answer before the next candidate is tried.
#: A deployment publishes an IPv4 port mapping and an IPv6 address, and an
#: address that cannot be reached from here does not fail -- it goes quiet.
CONNECT_TIMEOUT = 8.0


def _peer_certificate(host: str, port: int, timeout: float) -> bytes:
    """Take the certificate without trusting it; judging it comes next."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        # An IP literal is not a valid SNI name, and the guest serves one
        # certificate regardless.
        server_hostname = None if _is_ip(host) else host
        with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise AttestationError(f"{host} presented no certificate")
    return der


def _is_ip(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def attested_ssl_context(
    origin: str,
    measurements: Sequence[str],
    *,
    tcb_floor: Optional[TcbFloor] = None,
    timeout: float = CONNECT_TIMEOUT,
    client: Optional[httpx.Client] = None,
) -> Tuple[ssl.SSLContext, str]:
    """Verify the peer at ``origin`` and return a context pinned to it, along
    with the launch measurement it proved."""
    parts = urlsplit(origin)
    host = parts.hostname
    if host is None:
        raise ValueError(f"no host in {origin!r}")
    der = _peer_certificate(host, parts.port or 443, timeout)
    measurement = verify_certificate(der, measurements, tcb_floor=tcb_floor, client=client)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The name in the certificate is meaningless here; the report is what
    # identifies the peer, and pinning is what holds it to this one.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
    return context, measurement


def attested_client(
    origin: str,
    measurements: Sequence[str],
    *,
    tcb_floor: Optional[TcbFloor] = None,
    timeout: float = 600.0,
    **kwargs,
) -> Tuple[httpx.Client, str]:
    """An ``httpx.Client`` that can only reach the attested peer."""
    context, measurement = attested_ssl_context(
        origin, measurements, tcb_floor=tcb_floor, client=new_client()
    )
    return httpx.Client(verify=context, timeout=timeout, **kwargs), measurement
