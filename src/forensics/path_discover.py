"""Run multi-strategy path discovery against graph File nodes."""

from __future__ import annotations

from typing import Any

from forensics.case import CaseManifest
from forensics.discovery import discovery_from_case, match_score
from forensics.neo4j_client import Neo4jClient


def run_path_discover(
    case: CaseManifest,
    *,
    min_score: float = 0.4,
    limit: int = 200,
    client: Neo4jClient | None = None,
) -> dict[str, Any]:
    own = client is None
    c = client or Neo4jClient()
    try:
        rows = c.query(
            """
            MATCH (f:File)
            WHERE f.path IS NOT NULL
            RETURN f.id AS id, f.path AS path, f.source AS source,
                   f.sensitive AS sensitive
            LIMIT 50000
            """
        )
        hits: list[dict[str, Any]] = []
        for r in rows:
            path = str(r.get("path") or "")
            score = match_score(path, case)
            if score >= min_score:
                hits.append(
                    {
                        "id": r.get("id"),
                        "path": path,
                        "score": round(score, 3),
                        "source": r.get("source"),
                        "sensitive": r.get("sensitive"),
                    }
                )
        hits.sort(key=lambda x: x["score"], reverse=True)
        hits = hits[:limit]
        total = len(rows)
        cataloged = sum(1 for r in rows if r.get("source") == "filestat")
        return {
            "query": "path_discover",
            "total_files": total,
            "catalog_coverage_pct": round(100.0 * cataloged / total, 1) if total else 0.0,
            "min_score": min_score,
            "hit_count": len(hits),
            "rows": hits,
            "discovery_config": discovery_from_case(case).__dict__,
        }
    finally:
        if own:
            c.close()
