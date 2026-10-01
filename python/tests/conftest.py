import json
import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SENDER = "0x238224C744F4b90b4494516e074D2676ECfC6803"


@pytest.fixture
def cert() -> bytes:
    return (FIXTURES / "ratls-cert.der").read_bytes()


@pytest.fixture
def vcek() -> bytes:
    return (FIXTURES / "vcek.der").read_bytes()


@pytest.fixture
def message() -> dict:
    return json.loads((FIXTURES / "vprogram-message.json").read_text())


@pytest.fixture
def measurements(message) -> list:
    content = json.loads(message["item_content"])
    return [m["registers"]["launch"] for m in content["verification"]["measurements"]]
