from vulnscan.scoring import all_findings, band_for, exceeds


def by_port(results, addr, port):
    host = next(r for r in results if r.host.address == addr)
    return next(f for f in host.findings if f.port == port)


def test_band_boundaries():
    assert [band_for(s) for s in (9.0, 7.0, 4.0, 2.0, 1.9)] == ["Critical", "High", "Medium", "Low", "Info"]


def test_telnet_is_critical(results):
    f = by_port(results, "192.0.2.20", 23)
    assert (f.band, f.score) == ("Critical", 9.0)
    assert f.remediation


def test_eol_apache_flagged(results):
    f = by_port(results, "192.0.2.10", 80)
    assert f.band == "High" and "2.2" in f.reasons[0]


def test_tls_wrapped_service_not_flagged_as_cleartext(results):
    f = by_port(results, "192.0.2.10", 443)
    assert f.band == "Info"


def test_cves_raise_score_to_highest_cvss(results):
    f = by_port(results, "192.0.2.30", 80)
    assert f.score == 9.8 and f.band == "Critical"
    assert f.cves == ["CVE-2021-42013", "CVE-2021-41773"]


def test_unauthenticated_datastore_is_high(results):
    assert by_port(results, "192.0.2.30", 6379).band == "High"


def test_primary_reason_is_the_one_driving_the_score(results):
    assert "CVE" in by_port(results, "192.0.2.30", 80).reasons[0]


def test_hosts_sorted_by_priority(results):
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)
    assert results[0].host.address == "192.0.2.30"  # carries the 9.8 CVE finding
    assert results[-1].host.address == "192.0.2.50"  # only SSH


def test_host_score_never_exceeds_ten(results):
    assert all(0 <= r.score <= 10 for r in results)


def test_findings_sorted_and_threshold(results):
    findings = all_findings(results)
    assert findings == sorted(findings, key=lambda f: (-f.score, f.host, f.port))
    assert exceeds(results, "Critical")
    assert exceeds(results, "Low")
