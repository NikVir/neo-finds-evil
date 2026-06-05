"""Ingest batch buffer: normalize → batch → spill (not investigation or agent memory)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

_BATCH_NUM_RE = re.compile(r"_batch_(\d+)\.jsonl$")


def _batch_sort_key(path: Path) -> tuple[int, str]:
    m = _BATCH_NUM_RE.search(path.name)
    return (int(m.group(1)), path.name) if m else (0, path.name)


class IngestCache:
    """Per-record normalize; in-memory batch; spill files when batch overflows."""

    def __init__(
        self,
        spill_dir: Path,
        hostname: str,
        artifact: str,
        batch_size: int = 2000,
        spill_threshold: int = 10000,
        *,
        clear_spill: bool = True,
    ) -> None:
        self.spill_dir = spill_dir
        self.hostname = hostname
        self.artifact = artifact
        self.batch_size = batch_size
        self.spill_threshold = spill_threshold
        self._l2: list[dict[str, Any]] = []
        self._spill_index = 0
        self.spill_dir.mkdir(parents=True, exist_ok=True)
        if clear_spill:
            self.clear_spill()

    def clear_spill(self) -> None:
        pattern = f"{self.hostname}_{self.artifact}_batch_*.jsonl"
        for spill_file in self.spill_dir.glob(pattern):
            spill_file.unlink(missing_ok=True)
        self._spill_index = 0

    def add(self, record: dict[str, Any]) -> None:
        self._l2.append(record)
        if len(self._l2) >= self.spill_threshold:
            self._spill()

    def iter_batches(self) -> Iterator[list[dict[str, Any]]]:
        while self._l2:
            batch = self._l2[: self.batch_size]
            del self._l2[: self.batch_size]
            yield batch
        spill_pattern = f"{self.hostname}_{self.artifact}_batch_*.jsonl"
        for spill_file in sorted(self.spill_dir.glob(spill_pattern), key=_batch_sort_key):
            batch: list[dict[str, Any]] = []
            with spill_file.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    batch.append(json.loads(line))
                    if len(batch) >= self.batch_size:
                        yield batch
                        batch = []
            if batch:
                yield batch
            spill_file.unlink(missing_ok=True)

    def _spill(self) -> None:
        path = self.spill_dir / f"{self.hostname}_{self.artifact}_batch_{self._spill_index}.jsonl"
        self._spill_index += 1
        with path.open("w") as fh:
            for rec in self._l2:
                fh.write(json.dumps(rec) + "\n")
        self._l2.clear()

    def flush(self) -> None:
        if self._l2:
            self._spill()


def stream_ndjson(
    path: Path, normalize: Callable[[dict[str, Any]], dict[str, Any]] | None = None
) -> Iterator[dict[str, Any]]:
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            yield normalize(obj) if normalize else obj
