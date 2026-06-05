"""Tag File nodes with sensitive=true from case patterns."""

from __future__ import annotations

from forensics.case import CaseManifest
from forensics.neo4j_client import Neo4jClient
from forensics.discovery import match_score
from forensics.sensitive import path_matches_sensitive


def tag_sensitive_files(case: CaseManifest, client: Neo4jClient) -> int:
    """Mark existing File nodes whose path matches case sensitive patterns."""
    if not case.sensitive_paths and not case.sensitive_extensions:
        return 0
    rows = client.query(
        """
        MATCH (f:File)
        WHERE f.path IS NOT NULL
        RETURN f.id AS id, f.path AS path
        LIMIT 10000
        """
    )

    def _sensitive(path: str) -> bool:
        if path_matches_sensitive(path, case.sensitive_paths, case.sensitive_extensions):
            return True
        low = path.lower()
        for k in case.filename_keywords:
            kw = k.lower()
            if len(kw) <= 3:
                continue  # skip HEA etc. — too many false positives (e.g. SecurityHealth)
            if kw in low:
                return True
        return False

    scored: list[dict] = []
    for r in rows:
        path = str(r.get("path") or "")
        score = match_score(path, case)
        if _sensitive(path) or score >= 0.4:
            scored.append({"id": r["id"], "score": round(score, 3)})

    if not scored:
        return 0
    for i in range(0, len(scored), 500):
        chunk = scored[i : i + 500]
        client.run(
            """
            UNWIND $rows AS row
            MATCH (f:File {id: row.id})
            SET f.sensitive = true, f.sensitiveScore = row.score
            """,
            {"rows": chunk},
        )
    return len(scored)
