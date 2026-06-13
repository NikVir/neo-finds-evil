#!/usr/bin/env python3
"""
export_token_usage.py — sanitized per-turn token accounting for a Claude Code session.

The FIND EVIL! rules ask single-agent submissions for "tool execution logs with
timestamps and token usage." The MCP audit log (docs/execution-logs/mcp-audit-sample.log)
already carries timestamps + tool execution; this script adds the token-usage view.

It reads a Claude Code session transcript (JSON-lines) and emits, for every assistant
turn, ONLY: turn index, timestamp, model, and the token counts from the usage block.
No message text, no tool arguments, no tool results, no file contents, no memory — the
output is a low-sensitivity execution record safe to publish.

Transcripts live at: ~/.claude/projects/<project-slug>/<session-uuid>.jsonl

Usage:
    python3 tools/export_token_usage.py <transcript.jsonl> \\
        --jsonl docs/execution-logs/token-usage-sample.jsonl \\
        --md    docs/execution-logs/token-usage-sample.md

    # or, to discover available transcripts:
    python3 tools/export_token_usage.py
"""
import argparse
import glob
import json
import os
import sys

# Only these fields ever leave this script. Nothing else from the transcript is read out.
WHITELIST = ("input_tokens", "cache_creation_input_tokens",
             "cache_read_input_tokens", "output_tokens")


def discover():
    pattern = os.path.expanduser("~/.claude/projects/*/*.jsonl")
    hits = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    if not hits:
        print("No Claude Code transcripts found under ~/.claude/projects/.")
        print("Pass the transcript path explicitly:")
        print("  python3 tools/export_token_usage.py /path/to/<session-uuid>.jsonl")
        return
    print("Claude Code transcripts (most recent first):")
    for h in hits:
        print(f"  {h}")
    print("\nRe-run with the one you want, e.g.:")
    print(f"  python3 tools/export_token_usage.py {hits[0]} \\")
    print("      --jsonl docs/execution-logs/token-usage-sample.jsonl \\")
    print("      --md    docs/execution-logs/token-usage-sample.md")


def extract(path):
    turns = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip non-JSON lines defensively
            msg = entry.get("message") or {}
            is_assistant = (entry.get("type") == "assistant"
                            or msg.get("role") == "assistant")
            usage = msg.get("usage") or entry.get("usage")
            if not (is_assistant and isinstance(usage, dict)):
                continue
            rec = {"turn": len(turns) + 1,
                   "timestamp": entry.get("timestamp") or msg.get("timestamp", ""),
                   "model": msg.get("model", "")}
            for k in WHITELIST:
                rec[k] = int(usage.get(k, 0) or 0)
            turns.append(rec)
    return turns


def write_jsonl(turns, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for rec in turns:
            fh.write(json.dumps(rec) + "\n")


def write_md(turns, path):
    tot = {k: sum(t[k] for t in turns) for k in WHITELIST}
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Per-turn token usage (sanitized)\n\n")
        fh.write("Token counts for each assistant turn of the session, extracted from the "
                 "Claude Code transcript by `tools/export_token_usage.py`. Content is elided; "
                 "only timestamps, model, and token counts are recorded.\n\n")
        fh.write("| Turn | Timestamp | Model | Input | Cache read | Cache create | Output |\n")
        fh.write("|---|---|---|---|---|---|---|\n")
        for t in turns:
            fh.write(f"| {t['turn']} | {t['timestamp']} | {t['model']} | "
                     f"{t['input_tokens']:,} | {t['cache_read_input_tokens']:,} | "
                     f"{t['cache_creation_input_tokens']:,} | {t['output_tokens']:,} |\n")
        fh.write(f"| **Total** | {len(turns)} turns | | "
                 f"**{tot['input_tokens']:,}** | **{tot['cache_read_input_tokens']:,}** | "
                 f"**{tot['cache_creation_input_tokens']:,}** | **{tot['output_tokens']:,}** |\n")


def main():
    ap = argparse.ArgumentParser(description="Export sanitized per-turn token usage from a "
                                             "Claude Code transcript.")
    ap.add_argument("transcript", nargs="?", help="Path to the session .jsonl transcript")
    ap.add_argument("--jsonl", default="docs/execution-logs/token-usage-sample.jsonl",
                    help="Sanitized JSON-lines output path")
    ap.add_argument("--md", default="docs/execution-logs/token-usage-sample.md",
                    help="Markdown summary output path")
    args = ap.parse_args()

    if not args.transcript:
        discover()
        return

    if not os.path.isfile(args.transcript):
        sys.exit(f"Transcript not found: {args.transcript}")

    turns = extract(args.transcript)
    if not turns:
        sys.exit("No assistant turns with usage blocks found — is this a Claude Code transcript?")

    write_jsonl(turns, args.jsonl)
    write_md(turns, args.md)

    tot = {k: sum(t[k] for t in turns) for k in WHITELIST}
    print(f"Assistant turns: {len(turns)}")
    print(f"  input_tokens          {tot['input_tokens']:,}")
    print(f"  cache_read_input      {tot['cache_read_input_tokens']:,}")
    print(f"  cache_creation_input  {tot['cache_creation_input_tokens']:,}")
    print(f"  output_tokens         {tot['output_tokens']:,}")
    print(f"Wrote {args.jsonl} and {args.md}")


if __name__ == "__main__":
    main()
