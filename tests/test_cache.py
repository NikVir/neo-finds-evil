"""Tests for ingest spill cache."""

from __future__ import annotations

from pathlib import Path

from forensics.cache import IngestCache, _batch_sort_key


def test_batch_sort_key_natural_order() -> None:
    paths = [
        Path("Host_bulk_batch_2.jsonl"),
        Path("Host_bulk_batch_10.jsonl"),
        Path("Host_bulk_batch_1.jsonl"),
    ]
    assert [p.name for p in sorted(paths, key=_batch_sort_key)] == [
        "Host_bulk_batch_1.jsonl",
        "Host_bulk_batch_2.jsonl",
        "Host_bulk_batch_10.jsonl",
    ]


def test_clear_spill_on_init(tmp_path: Path) -> None:
    spill = tmp_path / "cache"
    spill.mkdir()
    stale = spill / "Rocba_evtx_batch_0.jsonl"
    stale.write_text('{"id": "x"}\n')
    cache = IngestCache(spill, "Rocba", "evtx", clear_spill=True)
    assert not stale.exists()
    cache.add({"id": "a"})
    cache.flush()
    spill_files = list(spill.glob("Rocba_evtx_batch_*.jsonl"))
    assert len(spill_files) == 1


def test_iter_batches_natural_spill_order(tmp_path: Path) -> None:
    spill = tmp_path / "cache"
    spill.mkdir()
    (spill / "Host_bulk_batch_10.jsonl").write_text('{"n": 10}\n')
    (spill / "Host_bulk_batch_2.jsonl").write_text('{"n": 2}\n')
    cache = IngestCache(spill, "Host", "bulk", batch_size=1, clear_spill=False)
    values = [batch[0]["n"] for batch in cache.iter_batches()]
    assert values == [2, 10]
