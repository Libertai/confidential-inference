#!/usr/bin/env python3
"""Re-capture the test fixtures from a live deployment.

    python scripts/refresh_fixtures.py <item-hash>

The offline tests verify a real certificate against a real VCEK and a real
published message, which is what makes them worth running -- and what means
they have to be re-captured whenever the deployment is replaced. The old
fixtures keep passing, since they are self-consistent, but they describe a
V-PROGRAM that no longer exists.
"""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python"))

from libertai_confidential import report_facts, resolve_deployment  # noqa: E402
from libertai_confidential._core import vcek_url  # noqa: E402

FIXTURE_DIRS = [
    REPO / "core/tests/fixtures",
    REPO / "js/test/fixtures",
    REPO / "python/tests/fixtures",
]


def peer_certificate(origin: str) -> bytes:
    host, port = origin.rsplit(":", 1)
    host = host.removeprefix("https://").strip("[]")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=20) as raw:
        with context.wrap_socket(raw) as tls:
            return tls.getpeercert(binary_form=True)


def main() -> int:
    item_hash = sys.argv[1]
    deployment = resolve_deployment(item_hash)
    print(f"resolved {item_hash[:12]}: {deployment.candidates[0]}")

    cert = peer_certificate(deployment.candidates[0])
    facts = report_facts(cert)
    if facts["measurement"] not in deployment.measurements:
        print(f"REFUSING: peer measures {facts['measurement'][:24]}, which the "
              f"message does not publish")
        return 1
    print(f"measurement {facts['measurement'][:24]}... matches the published one")

    # The VCEK is per-chip and per-firmware: a new host or a patched one needs
    # a new one, so it is fetched rather than carried over.
    url = vcek_url(cert)
    with urllib.request.urlopen(url, timeout=60) as res:
        vcek = res.read()
    print(f"vcek {len(vcek)} bytes from AMD")

    with urllib.request.urlopen(
        f"https://api.aleph.im/api/v0/messages.json?hashes={item_hash}", timeout=30
    ) as res:
        message = json.load(res)["messages"][0]

    first = FIXTURE_DIRS[0]
    (first / "ratls-cert.der").write_bytes(cert)
    (first / "vcek.der").write_bytes(vcek)
    (first / "vprogram-message.json").write_text(json.dumps(message, indent=1) + "\n")
    for other in FIXTURE_DIRS[1:]:
        for name in ("ratls-cert.der", "vcek.der", "vprogram-message.json"):
            shutil.copyfile(first / name, other / name)
        print(f"updated {other.relative_to(REPO)}")

    manifest_path = REPO / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["models"].values():
        for deployed in entry["deployments"]:
            if deployed["status"] == "active":
                deployed["item_hash"] = item_hash
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print("updated manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
