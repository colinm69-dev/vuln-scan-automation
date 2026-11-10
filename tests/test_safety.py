import pytest

from vulnscan import safety


def test_accepts_private_and_documentation_ranges():
    nets = safety.parse_targets(["192.0.2.0/24", "10.1.2.3", "172.28.0.0/24"])
    safety.validate(nets)


@pytest.mark.parametrize("bad", ["example.com", "--script=evil", "-sS", "", "999.1.1.1", "192.0.2.0/99"])
def test_rejects_hostnames_options_and_garbage(bad):
    with pytest.raises(safety.TargetError):
        safety.parse_targets([bad])


# 100.64.0.0/10 (shared address space) is not private, so it stands in for "outside the lab"
# without putting a real public address in the repo.
def test_rejects_public_ranges_by_default():
    nets = safety.parse_targets(["100.64.0.0/24"])
    with pytest.raises(safety.TargetError, match="non-private"):
        safety.validate(nets)


def test_public_allowed_only_with_flag():
    safety.validate(safety.parse_targets(["100.64.0.0/24"]), allow_public=True)


def test_rejects_oversized_target_sets():
    with pytest.raises(safety.TargetError, match="limit"):
        safety.validate(safety.parse_targets(["10.0.0.0/16"]))
    safety.validate(safety.parse_targets(["10.0.0.0/16"]), max_hosts=70000)
