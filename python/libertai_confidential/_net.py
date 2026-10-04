"""Not waiting on addresses that cannot be reached.

`socket.create_connection`, and so httpx, walks resolved addresses in order and
gives each one the full connect timeout. On a host whose IPv6 is broken rather
than absent -- a route exists, nothing answers -- every request to a
dual-stacked name stalls before falling back, which is most of a minute per
call. Browsers and Node avoid this with Happy Eyeballs; the standard library
does not.

So IPv6 is tried once, against a host this client was going to contact anyway,
and the answer decides for the rest of the process.

That answer is per-process, not per-host, which is as far as a single probe can
go: a host whose AAAA record is dead while the probe host's works still costs
one connect timeout before the fallback. The timeout is therefore short enough
that the stall is a pause rather than a hang -- 10s of it was most of the cost
of a first `connect()` against a CRN with a dead AAAA.
"""

from __future__ import annotations

import socket
from typing import Optional

import httpx

_ipv6: Optional[bool] = None

#: Long enough for a working path over a slow link, short enough that a broken
#: one costs a pause rather than a timeout.
_PROBE_TIMEOUT = 2.0

#: Bounds what an address family that does not work here can cost. Every host
#: this talks to is a public API, so a TCP handshake that takes longer than this
#: is not going to succeed.
_CONNECT_TIMEOUT = 3.0


def ipv6_works(host: str = "api.aleph.im", port: int = 443) -> bool:
    """Whether IPv6 reaches `host`. Probed once, then remembered."""
    global _ipv6
    if _ipv6 is not None:
        return _ipv6
    _ipv6 = False
    if socket.has_ipv6:
        try:
            addresses = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            addresses = []
        for family, kind, proto, _canon, sockaddr in addresses[:1]:
            try:
                with socket.socket(family, kind, proto) as s:
                    s.settimeout(_PROBE_TIMEOUT)
                    s.connect(sockaddr)
                _ipv6 = True
            except OSError:
                _ipv6 = False
    return _ipv6


def new_client(*, timeout: float = 60.0, **kwargs) -> httpx.Client:
    """An httpx client that will not stall on an address family that does not
    work here."""
    if not ipv6_works():
        # Binding an IPv4 source address makes the resolver's AAAA records
        # unusable, which is what skips them.
        kwargs.setdefault("transport", httpx.HTTPTransport(local_address="0.0.0.0", retries=1))
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=_CONNECT_TIMEOUT),
        follow_redirects=True,
        **kwargs,
    )
