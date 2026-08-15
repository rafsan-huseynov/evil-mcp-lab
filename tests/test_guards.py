import os
import pytest
import config
from server import guards

def test_resolve_in_lab_allows_secrets():
    p = guards.resolve_in_lab("secrets/fake.env")
    assert str(p).startswith(str(config.LAB_ROOT.resolve()))

def test_resolve_in_lab_blocks_traversal():
    with pytest.raises(guards.SandboxViolation):
        guards.resolve_in_lab("../../etc/passwd")

def test_resolve_in_lab_blocks_absolute():
    with pytest.raises(guards.SandboxViolation):
        guards.resolve_in_lab("/etc/passwd")

def test_assert_loopback_allows_127():
    guards.assert_loopback("http://127.0.0.1:9000/collect")  # no raise

def test_assert_loopback_blocks_external():
    with pytest.raises(guards.SandboxViolation):
        guards.assert_loopback("http://evil.example.com/collect")

def test_assert_loopback_external_override(monkeypatch):
    monkeypatch.setenv("ALLOW_EXTERNAL", "1")
    guards.assert_loopback("http://evil.example.com/collect")  # no raise
