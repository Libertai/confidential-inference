"""Fixtures captured from the live H200 deployment: the RA-TLS certificate it
served and the VCEK AMD issued for that chip and firmware. Nothing here reaches
AMD -- the fixture VCEK is served from a stub cache."""

import pytest

from libertai_confidential import AttestationError, TcbFloor, report_facts, verify_certificate
from libertai_confidential import verify as verify_module


@pytest.fixture(autouse=True)
def offline_kds(monkeypatch, vcek):
    monkeypatch.setattr(verify_module, "_load_vcek", lambda url, client: vcek)


def test_the_live_certificate_verifies_against_its_published_measurements(cert, measurements):
    assert verify_certificate(cert, measurements) in measurements


def test_a_peer_running_another_image_is_refused(cert):
    with pytest.raises(AttestationError):
        verify_certificate(cert, ["00" * 48])


def test_a_platform_below_the_firmware_floor_is_refused(cert, measurements):
    tcb = report_facts(cert)["reported_tcb"]
    floor = TcbFloor(**{**tcb, "snp": tcb["snp"] + 1})
    with pytest.raises(AttestationError, match="firmware is"):
        verify_certificate(cert, measurements, tcb_floor=floor)


def test_a_report_edited_to_claim_a_published_measurement_loses_amds_signature(cert):
    # The closest thing to a real attack: take a genuine enclave's certificate
    # and rewrite the measurement to one the client accepts. The report is hex
    # inside the extension, so the edit is a single character.
    start = cert.index(b'"data":"') + len(b'"data":"')
    at = start + 0x90 * 2  # MEASUREMENT is at offset 0x90 of the report
    forged = bytearray(cert)
    forged[at] = ord("b") if forged[at] == ord("a") else ord("a")
    forged = bytes(forged)

    claimed = report_facts(forged)["measurement"]
    assert claimed != report_facts(cert)["measurement"], "the edit landed"
    with pytest.raises(AttestationError, match="AMD does not endorse"):
        verify_certificate(forged, [claimed])


def test_the_report_describes_a_non_debuggable_genoa_guest(cert):
    facts = report_facts(cert)
    assert facts["product"] == "Genoa"
    assert facts["debug_allowed"] is False
    assert len(facts["measurement"]) == 96
