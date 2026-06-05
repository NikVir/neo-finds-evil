"""Neo4j client factory for case-scoped databases."""

from __future__ import annotations

from forensics.case import CaseManifest
from forensics.neo4j_client import Neo4jClient


def client_for_case(case: CaseManifest) -> Neo4jClient:
    return Neo4jClient(
        uri=case.neo4j_uri(),
        database=case.neo4j_database(),
    )
