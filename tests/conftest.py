from pathlib import Path

import pytest


@pytest.fixture
def xml() -> bytes:
    return (Path(__file__).parent.parent / "examples" / "synthetic-nmap.xml").read_bytes()
