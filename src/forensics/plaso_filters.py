"""Plaso psort filter expressions for artifact export (probe on SIFT with pinfo.py -v)."""

from __future__ import annotations

# Confirmed via pinfo on SIFT lab stores: windows:prefetch:* and appcompat/shim parsers.
PREFETCH_FILTER = 'data_type contains "prefetch"'
SHIMCACHE_FILTER = 'data_type contains "appcompat" or data_type contains "shimcache"'
