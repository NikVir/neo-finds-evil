"""Neo4j driver wrapper and schema constraints."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

from neo4j import READ_ACCESS, GraphDatabase, Query

try:  # pragma: no cover - import shape depends on neo4j version
    from neo4j.exceptions import ServiceUnavailable, TransientError
except ImportError:  # pragma: no cover
    TransientError = ServiceUnavailable = ()  # type: ignore[assignment,misc]

# Default ceiling for reporting/stats queries (coverage report, rebuild verify).
# A stats query that exceeds this is skipped, never allowed to wedge a host or
# the rebuild. Override with FORENSICS_STATS_TIMEOUT (seconds).
_DEFAULT_STATS_TIMEOUT = 30.0


def stats_query_timeout() -> float:
    """Configured server-side timeout (seconds) for reporting/stats queries."""
    try:
        return float(os.environ.get("FORENSICS_STATS_TIMEOUT", _DEFAULT_STATS_TIMEOUT))
    except ValueError:
        return _DEFAULT_STATS_TIMEOUT


def _is_timeout(exc: BaseException) -> bool:
    """True if an exception is a (server-enforced) transaction timeout."""
    code = getattr(exc, "code", "") or ""
    return "TransactionTimedOut" in code or "timeout" in str(exc).lower()


def _is_retryable(exc: BaseException) -> bool:
    """Transient errors worth retrying: deadlocks and momentary unavailability.

    Parallel rebuild workers MERGE shared nodes (IPAddress keyed by address,
    RegistryKey for recurring infra) concurrently and can hit
    Neo.TransientError.Transaction.DeadlockDetected. Those are safe to retry.
    """
    if isinstance(exc, (TransientError, ServiceUnavailable)):
        return True
    code = getattr(exc, "code", "") or ""
    return "Transient" in code or "DeadlockDetected" in code


def run_with_retry(
    fn: Callable[[], Any],
    *,
    attempts: int = 5,
    base_delay: float = 0.1,
    sleep: Callable[[float], None] = time.sleep,
    is_retryable: Callable[[BaseException], bool] = _is_retryable,
) -> Any:
    """Call ``fn`` with exponential backoff on transient errors.

    Re-raises immediately on non-transient errors or after the last attempt.
    ``sleep`` is injectable for tests.
    """
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised unless retryable
            if i == attempts - 1 or not is_retryable(exc):
                raise
            sleep(base_delay * (2**i))
    return None  # unreachable


SCHEMA_STATEMENTS = [
    "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
    "CREATE CONSTRAINT host_hostname IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE",
    "CREATE CONSTRAINT process_id IF NOT EXISTS FOR (p:Process) REQUIRE p.id IS UNIQUE",
    "CREATE CONSTRAINT event_id IF NOT EXISTS FOR (e:WindowsEvent) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT ip_id IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.id IS UNIQUE",
    "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE",
    "CREATE CONSTRAINT file_id IF NOT EXISTS FOR (f:File) REQUIRE f.id IS UNIQUE",
    "CREATE CONSTRAINT user_sid IF NOT EXISTS FOR (u:UserAccount) REQUIRE u.sid IS UNIQUE",
    "CREATE INDEX event_time IF NOT EXISTS FOR (e:WindowsEvent) ON (e.timestamp)",
    "CREATE INDEX process_name IF NOT EXISTS FOR (p:Process) ON (p.name)",
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
    "CREATE CONSTRAINT media_id IF NOT EXISTS FOR (m:MediaAsset) REQUIRE m.id IS UNIQUE",
    "CREATE CONSTRAINT geo_id IF NOT EXISTS FOR (g:GeoLocation) REQUIRE g.id IS UNIQUE",
    "CREATE CONSTRAINT usb_id IF NOT EXISTS FOR (u:USBDevice) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
    "CREATE CONSTRAINT registry_key_id IF NOT EXISTS FOR (r:RegistryKey) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:WindowsService) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT script_block_id IF NOT EXISTS FOR (s:ScriptBlock) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT wmi_id IF NOT EXISTS FOR (w:WmiBinding) REQUIRE w.id IS UNIQUE",
    "CREATE INDEX event_guid IF NOT EXISTS FOR (e:WindowsEvent) ON (e.processGuid)",
]


class Neo4jClient:
    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> None:
        self.uri = uri or os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
        self.user = user or os.environ.get("NEO4J_USER", "neo4j")
        self.password = password or os.environ.get("NEO4J_PASSWORD", "forensics123")
        self.database = database or os.environ.get("NEO4J_DATABASE", "neo4j")
        self._max_retries = int(os.environ.get("NEO4J_MAX_RETRIES", "5"))
        self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    def close(self) -> None:
        self._driver.close()

    def _session(self):
        return self._driver.session(database=self.database)

    def ensure_schema(self) -> None:
        def _do() -> None:
            with self._session() as session:
                for stmt in SCHEMA_STATEMENTS:
                    session.run(stmt)

        run_with_retry(_do, attempts=self._max_retries)

    def run(self, query: str, parameters: dict[str, Any] | None = None) -> None:
        def _do() -> None:
            with self._session() as session:
                session.run(query, parameters or {})

        run_with_retry(_do, attempts=self._max_retries)

    def run_batched(self, query: str, rows: list[dict[str, Any]], param_key: str = "rows") -> int:
        if not rows:
            return 0

        def _do() -> None:
            with self._session() as session:
                session.run(query, {param_key: rows})

        run_with_retry(_do, attempts=self._max_retries)
        return len(rows)

    def query(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        # A `timeout` sets a server-enforced transaction timeout; the server
        # aborts the query and raises rather than letting it run unbounded.
        q: str | Query = Query(cypher, timeout=timeout) if timeout is not None else cypher
        with self._session() as session:
            result = session.run(q, parameters or {})
            return [dict(rec) for rec in result]

    def read_query(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
        max_rows: int | None = None,
    ) -> list[dict[str, Any]]:
        """Run a query in an explicit READ transaction with a server-side timeout.

        Driver-level read-only guarantee: the session is opened in READ access
        mode, so any write clause is rejected by the server (raises ClientError)
        regardless of the text. The access mode IS the enforced boundary — do
        not weaken it; the live regression test in tests/test_mcp_server.py
        (test_live_read_access_backstop_rejects_real_write) fails if it is
        removed. Used by the read-only MCP server's escape-hatch tool.

        ``max_rows`` bounds *consumption*, not just the returned list: the
        cursor is read lazily and abandoned after ``max_rows`` records, so a
        query carrying a huge user-supplied LIMIT cannot force this process to
        materialize the full result before the caller's cap is applied.
        """
        with (
            self._driver.session(
                database=self.database, default_access_mode=READ_ACCESS
            ) as session,
            session.begin_transaction(timeout=timeout) as tx,
        ):
            result = tx.run(cypher, parameters or {})
            if max_rows is None:
                return [dict(rec) for rec in result]
            rows: list[dict[str, Any]] = []
            for rec in result:
                rows.append(dict(rec))
                if len(rows) >= max_rows:
                    break
            return rows

    def query_guarded(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> tuple[list[dict[str, Any]] | None, str]:
        """Read query that never raises. Returns ``(rows, status)``.

        ``status`` is ``"ok"``, ``"timeout"``, or ``"error:<ExcType>"``. Use for
        reporting/stats queries so a slow or broken one is skipped (with the
        reason recorded) instead of failing a host or the whole rebuild.
        """
        try:
            return self.query(cypher, parameters, timeout=timeout), "ok"
        except Exception as exc:  # noqa: BLE001 - guard: report, do not propagate
            return None, "timeout" if _is_timeout(exc) else f"error:{type(exc).__name__}"

    def host_has_events(self, hostname: str) -> bool:
        rows = self.query(
            """
            MATCH (e:WindowsEvent)-[:REPORTED]->(h:Host {hostname: $hostname})
            RETURN count(e) AS c LIMIT 1
            """,
            {"hostname": hostname},
        )
        return bool(rows and int(rows[0].get("c") or 0) > 0)
