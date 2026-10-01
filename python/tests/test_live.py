"""Opt-in: this one talks to a running deployment and to AMD.

    LIBERTAI_ITEM_HASH=<hash> pytest tests/test_live.py
"""

import os

import pytest

from libertai_confidential import connect

ITEM_HASH = os.environ.get("LIBERTAI_ITEM_HASH")


@pytest.mark.skipif(not ITEM_HASH, reason="set LIBERTAI_ITEM_HASH to run")
def test_a_live_deployment_can_be_reached_only_once_it_is_proved():
    tee = connect(item_hash=ITEM_HASH)
    assert tee.base_url.endswith("/v1")
    assert len(tee.measurement) == 96

    res = tee.http_client.get(f"{tee.base_url}/models")
    assert res.status_code == 200
    assert res.json()["data"]
