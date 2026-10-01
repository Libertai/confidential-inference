"""Opt-in: this one talks to a running deployment and to AMD.

    LIBERTAI_ITEM_HASH=<hash> pytest tests/test_live.py
"""

import os

import pytest

from libertai_confidential import connect

ITEM_HASH = os.environ.get("LIBERTAI_ITEM_HASH")

pytestmark = pytest.mark.skipif(not ITEM_HASH, reason="set LIBERTAI_ITEM_HASH to run")


def test_a_live_deployment_can_be_reached_only_once_it_is_proved():
    tee = connect(item_hash=ITEM_HASH)
    assert tee.base_url.endswith("/v1")
    assert len(tee.measurement) == 96


def test_the_enclave_refuses_an_unauthenticated_request():
    # Proof that the API-key gateway is what answers, not vLLM: verification
    # succeeded, the channel is attested, and the request is still refused.
    tee = connect(item_hash=ITEM_HASH)
    res = tee.http_client.post(
        f"{tee.base_url}/chat/completions",
        json={"model": "qwen3.8-27b", "messages": []},
    )
    assert res.status_code == 401
