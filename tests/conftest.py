from pathlib import Path

import pytest

from vulnscan.parser import parse_file
from vulnscan.scoring import assess, load_rules

FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.xml"


@pytest.fixture(scope="session")
def scan():
    meta, hosts = parse_file(FIXTURE)
    return meta, hosts


@pytest.fixture(scope="session")
def results(scan):
    return assess(scan[1], load_rules())
