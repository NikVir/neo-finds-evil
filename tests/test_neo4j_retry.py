"""Unit tests for transient-error retry-with-backoff in the Neo4j client.

Covers the deadlock-retry behaviour the parallel rebuild relies on (caveat 6),
using a pure callable + injected sleep — no real driver.
"""

from __future__ import annotations

import pytest

from forensics.neo4j_client import (
    Neo4jClient,
    _is_retryable,
    _is_timeout,
    run_with_retry,
    stats_query_timeout,
)


class _FakeNeo4jError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def test_is_retryable_on_deadlock_and_transient_codes():
    assert _is_retryable(_FakeNeo4jError("Neo.TransientError.Transaction.DeadlockDetected"))
    assert _is_retryable(_FakeNeo4jError("Neo.TransientError.General.Whatever"))


def test_not_retryable_on_constraint_violation():
    assert not _is_retryable(_FakeNeo4jError("Neo.ClientError.Schema.ConstraintValidationFailed"))
    assert not _is_retryable(ValueError("nope"))


def test_run_with_retry_succeeds_after_transient_failures():
    calls = {"n": 0}
    slept: list[float] = []

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _FakeNeo4jError("Neo.TransientError.Transaction.DeadlockDetected")
        return "ok"

    result = run_with_retry(fn, attempts=5, base_delay=0.01, sleep=slept.append)
    assert result == "ok"
    assert calls["n"] == 3
    assert slept == [0.01, 0.02]  # exponential backoff between the 2 retries


def test_run_with_retry_reraises_non_transient_immediately():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise ValueError("hard fail")

    with pytest.raises(ValueError):
        run_with_retry(fn, attempts=5, sleep=lambda _: None)
    assert calls["n"] == 1  # no retries for non-transient


def test_run_with_retry_gives_up_after_attempts():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise _FakeNeo4jError("Neo.TransientError.Transaction.DeadlockDetected")

    with pytest.raises(_FakeNeo4jError):
        run_with_retry(fn, attempts=3, base_delay=0.0, sleep=lambda _: None)
    assert calls["n"] == 3  # exactly `attempts` tries


# --- timeout guard for reporting/stats queries -----------------------------


def test_is_timeout_detects_transaction_timeout():
    assert _is_timeout(_FakeNeo4jError("Neo.ClientError.Transaction.TransactionTimedOut"))
    assert _is_timeout(Exception("the transaction has been terminated (timeout)"))
    assert not _is_timeout(_FakeNeo4jError("Neo.ClientError.Statement.SyntaxError"))


def test_stats_query_timeout_env(monkeypatch):
    monkeypatch.delenv("FORENSICS_STATS_TIMEOUT", raising=False)
    assert stats_query_timeout() == 30.0
    monkeypatch.setenv("FORENSICS_STATS_TIMEOUT", "5")
    assert stats_query_timeout() == 5.0
    monkeypatch.setenv("FORENSICS_STATS_TIMEOUT", "garbage")
    assert stats_query_timeout() == 30.0  # falls back on bad value


def _client_without_connecting(monkeypatch):
    # Neo4jClient.__init__ builds a driver but does not connect; stub it anyway.
    monkeypatch.setattr("forensics.neo4j_client.GraphDatabase.driver", lambda *a, **k: object())
    return Neo4jClient()


def test_query_guarded_ok(monkeypatch):
    client = _client_without_connecting(monkeypatch)
    monkeypatch.setattr(client, "query", lambda *a, **k: [{"c": 5}])
    rows, status = client.query_guarded("MATCH ... RETURN count(*) AS c", timeout=10)
    assert status == "ok" and rows == [{"c": 5}]


def test_query_guarded_timeout(monkeypatch):
    client = _client_without_connecting(monkeypatch)

    def boom(*a, **k):
        raise _FakeNeo4jError("Neo.ClientError.Transaction.TransactionTimedOut")

    monkeypatch.setattr(client, "query", boom)
    rows, status = client.query_guarded("MATCH ...", timeout=1)
    assert rows is None and status == "timeout"


def test_query_guarded_other_error(monkeypatch):
    client = _client_without_connecting(monkeypatch)
    monkeypatch.setattr(client, "query", lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))
    rows, status = client.query_guarded("MATCH ...")
    assert rows is None and status == "error:ValueError"
