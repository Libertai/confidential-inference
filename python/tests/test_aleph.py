"""The message is a real one, published by the account that runs the
deployments, so these fail if Aleph's signing or hashing rules drift."""

import pytest

from libertai_confidential import AlephError
from libertai_confidential.aleph import verify_message

from .conftest import SENDER


def test_a_published_message_verifies_against_its_sender(message):
    content = verify_message(message, SENDER)
    assert content["verification"]["backend"] == "sev_snp"
    assert len(content["verification"]["measurements"]) == 2


def test_content_that_does_not_hash_to_the_item_hash_is_refused(message):
    message["item_content"] = message["item_content"].replace("sev_snp", "sev_snq")
    with pytest.raises(AlephError, match="item hash mismatch"):
        verify_message(message, SENDER)


def test_a_message_is_refused_when_another_address_claims_it(message):
    with pytest.raises(AlephError, match="published by"):
        verify_message(message, "0x0000000000000000000000000000000000000001")


def test_a_forged_signature_is_refused(message):
    # Flipping a byte of r leaves a well-formed signature that recovers some
    # other key, which is the failure this has to catch.
    sig = message["signature"]
    message["signature"] = sig[:10] + ("b" if sig[10] == "a" else "a") + sig[11:]
    with pytest.raises(AlephError):
        verify_message(message, SENDER)
