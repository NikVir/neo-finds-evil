"""Run psort with json_line output (requires -w on current Plaso builds)."""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path


def iter_psort_jsonl(
    plaso_path: Path,
    filter_expr: str,
    *,
    limit: int | None = None,
    output_path: Path | None = None,
) -> Iterator[str]:
    """Yield JSONL lines from psort; uses -w because json_line requires an output file."""
    if not plaso_path.exists():
        return

    out = output_path
    cleanup = False
    if out is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        out = Path(tmp.name)
        cleanup = True

    subprocess.run(
        [
            "psort.py",
            "-q",
            "-o",
            "json_line",
            "-w",
            str(out),
            str(plaso_path),
            filter_expr,
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    if not out.exists() or out.stat().st_size == 0:
        if cleanup:
            out.unlink(missing_ok=True)
        return

    count = 0
    with out.open() as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            yield line
            count += 1
            if limit is not None and count >= limit:
                break

    if cleanup:
        out.unlink(missing_ok=True)
