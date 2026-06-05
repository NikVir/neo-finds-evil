"""Record investigation findings as Neo4j Finding nodes."""

from __future__ import annotations

from typing import Any

from forensics.neo4j_client import Neo4jClient


def record_finding(
    *,
    case_id: str,
    hypothesis_id: str,
    verdict: str,
    confidence: str,
    step_id: str,
    summary: str = "",
    client: Neo4jClient | None = None,
) -> dict[str, Any]:
    finding_id = f"{case_id}:{step_id}:{hypothesis_id}"
    own = client is None
    c = client or Neo4jClient()
    try:
        c.run(
            """
            MERGE (f:Finding {id: $id})
            SET f.caseId = $case_id, f.hypothesisId = $hypothesis_id,
                f.verdict = $verdict, f.confidence = $confidence,
                f.stepId = $step_id, f.summary = $summary
            """,
            {
                "id": finding_id,
                "case_id": case_id,
                "hypothesis_id": hypothesis_id,
                "verdict": verdict,
                "confidence": confidence,
                "step_id": step_id,
                "summary": summary,
            },
        )
        return {"finding_id": finding_id, "recorded": True}
    finally:
        if own:
            c.close()
