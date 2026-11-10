import json

from vulnscan.report import redact, to_json, to_markdown


def test_markdown_has_sections_and_priorities(scan, results):
    md = to_markdown(scan[0], results)
    for heading in ("## Scan details", "## Summary", "## Top priorities", "## Hosts", "## Method and limits"):
        assert heading in md
    assert "Telnet service exposed" in md
    assert md.index("192.0.2.30") < md.index("192.0.2.50")  # highest-risk host listed first


def test_json_is_valid_and_complete(scan, results):
    data = json.loads(to_json(scan[0], results))
    assert set(data) == {"meta", "summary", "hosts"}
    assert data["summary"]["Critical"] >= 2
    assert len(data["hosts"]) == 5


def test_redaction_removes_addresses_and_names(scan, results):
    meta, red = redact(scan[0], results)
    text = to_markdown(meta, red) + to_json(meta, red)
    assert "192.0.2." not in text
    assert "lab.example" not in text
    assert "host-01" in text
    # original objects are untouched
    assert results[0].host.address.startswith("192.0.2.")
