import subprocess
from unittest.mock import Mock, patch

import pytest

from securityscanner.core.scope import Scope, ScopeError, canonical, resolve


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-sV",
        "127.0.0.1;id",
        "127.0.0.1\n",
        "10.0.0.0/8",
        "10.0.0.1-5",
        "https://example.test",
        "*.test",
        "127.1",
        "2130706433",
        "foo..test",
        "a.-b",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fe80::1",
        "fe80::1%eth0",
        "255.255.255.255",
        "::ffff:127.0.0.1",
        " host",
        "x" * 64 + ".test",
    ],
)
def test_invalid_targets(value):
    with pytest.raises(ScopeError):
        canonical(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.TEST.", "example.test"),
        ("127.0.0.1", "127.0.0.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("localhost", "localhost"),
    ],
)
def test_canonical(value, expected):
    assert canonical(value) == expected


def test_authorization_before_dns():
    resolver = Mock()
    with pytest.raises(ScopeError):
        Scope(["example.test"], False, resolver)
    resolver.assert_not_called()


def test_scope_denial_before_dns():
    resolver = Mock()
    scope = Scope(["allowed.test"], True, resolver)
    with pytest.raises(ScopeError):
        scope.approve(["denied.test"])
    resolver.assert_not_called()


def test_rebinding_stops():
    resolver = Mock(side_effect=[{"192.0.2.1"}, {"192.0.2.2"}])
    scope = Scope(["example.test"], True, resolver)
    assert scope.approve(["example.test"]) == {"example.test": ["192.0.2.1"]}
    with pytest.raises(ScopeError, match="DNS changed"):
        scope.revalidate("example.test")


def test_mixed_unsafe_dns_rejected():
    scope = Scope(["example.test"], True, lambda _: {"127.0.0.1", "0.0.0.0"})
    with pytest.raises(ScopeError):
        scope.approve(["example.test"])


def test_aggregate_limit():
    scope = Scope(
        ["a.test", "b.test"],
        True,
        lambda host: {
            f"192.0.2.{i}" for i in (range(1, 10) if host == "a.test" else range(10, 19))
        },
    )
    with pytest.raises(ScopeError, match="16"):
        scope.approve(["a.test", "b.test"])


@pytest.mark.parametrize("answers", [set(), {"not-an-ip"}, {f"192.0.2.{i}" for i in range(20)}])
def test_invalid_dns_answers(answers):
    scope = Scope(["a.test"], True, lambda _: answers)
    with pytest.raises(ScopeError):
        scope.approve(["a.test"])


def test_ip_resolution_uses_no_process():
    with patch("subprocess.run") as process:
        assert resolve("127.0.0.1") == {"127.0.0.1"}
        process.assert_not_called()


def test_dns_timeout():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("dns", 5)):
        with pytest.raises(ScopeError, match="DNS resolution failed"):
            resolve("example.test")
