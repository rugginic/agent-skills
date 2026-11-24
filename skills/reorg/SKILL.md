---
name: reorg
description: Organize, rename, file, deduplicate, or audit files in local folders, NAS mounts, or Google Drive remotes using the bundled scripts/reorg.py CLI. Use for folder cleanup, inbox filing, batch renaming, duplicate quarantine, or undoing an in-place reorg run.
license: MIT
compatibility: Requires Python 3.10+ and PyYAML; optional pdftotext for PDFs and rclone for Google Drive remotes.
metadata:
  author: rugginic
  version: "3.0.0"
---

# /reorg

Run the bundled CLI at `scripts/reorg.py` (relative to this `SKILL.md` directory): `python3 <skill-dir>/scripts/reorg.py <audit|extract|plan|validate|apply|undo>`.

Split mechanics, orchestration, and judgment cleanly:
- **CLI (`scripts/reorg.py`)** owns all deterministic mechanics: metadata audits, bounded extraction, credential filtering, path safety, collision handling, drift checks, writes, verification, journaling, and undo.
- **Main thread (orchestrator only):** coordinates phases, owns the owner conversation and approval gate, aggregates subagent outputs, and runs deterministic CLI commands. The orchestrator does not execute bulk or routing subtasks itself.
- **Cheap subagents (e.g., Haiku / Luna / Terra):** execute every bulk or routing subtask — reading extracted batches, inspecting `vision_required` files, proposing renames, and deciding file/folder routing.

Never permanently delete files. Never read files flagged `credential_skipped` or unpack `archive_skipped`.

## Workflow

1. **Audit first (metadata only).**
   Run `python3 <skill-dir>/scripts/reorg.py audit <path>` (add `--hash` for exact duplicates, `--rules <path>` when the user provides a taxonomy/rules YAML — see `references/rules.example.yaml`).
   Report counts, largest folders/files, empty folders, deep-nesting hotspots, duplicates, and any unsupported Drive native objects (e.g., My Maps, Forms). Agree with the owner on scope, layout, and write mode (in-place move default vs `--copy`, or inbox filing via `--into <dest>`) before reading content.

2. **Extract only when filenames/folders are insufficient.**
   Run `python3 <skill-dir>/scripts/reorg.py extract <path>` on the agreed scope (bounded by default to depth 3 and 100 files; widen flags only when the owner asks).
   - `credential_skipped`: keep untouched in place or route strictly by filename; never inspect content.
   - `archive_skipped`: route as an opaque file; never unpack.
   - `vision_required` (images / scanned PDFs): delegate to a cheap vision-capable subagent only when needed for naming or routing.

3. **Delegate all bulk and routing subtasks to cheap subagents.**
   Never read batches or decide per-file names/placements in the orchestrator thread. Split extracted items (or filename lists when content extraction was skipped) into bounded batches and dispatch cheap subagents (e.g., Haiku / Luna / Terra) to emit `source -> target` proposals (`JSON`, `YAML`, or `TSV`) with `confidence` (`high|medium|low`) and a concise `reason`.
   Dispatch a second-check cheap subagent **only on `low` confidence items** (or ambiguous routing). Keep clear `high`/`medium` items single-pass.

4. **Build and validate the plan.**
   Merge subagent proposals and run `python3 <skill-dir>/scripts/reorg.py plan <source> --proposals <file>` (combine with `--into <dest>`, `--dedupe` for `_Duplicates/` quarantine, `--rules <path>`, or `--mode copy` as appropriate).
   Verify every item is accounted for. Show the owner the generated review table, collision suffixes (`_2`, `_3`), unsupported native flags, and resulting tree preview.

5. **Owner approval gate.**
   Obtain explicit owner approval of the concrete plan and write mode before running `apply`. Audit or planning authorization does not authorize writes. If files or rules changed after planning, re-run `validate <plan>` or regenerate `plan`.

6. **Apply and verify.**
   Run `python3 <skill-dir>/scripts/reorg.py apply <plan>` (pass `--copy` only when additive copy was approved).
   Report verified counts, any warnings, and the saved JSONL journal path.

7. **Undo (when requested).**
   Run `python3 <skill-dir>/scripts/reorg.py undo <journal.jsonl>` to deterministically reverse an applied in-place move run. (Undo verifies destination integrity, refuses to overwrite modified or conflicting files, and never deletes files.)
