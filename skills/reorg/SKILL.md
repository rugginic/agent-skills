---
name: reorg
description: Organize, rename, file, deduplicate, or audit files in local folders, NAS mounts, or Google Drive remotes using the bundled scripts/reorg.py CLI. Use for folder cleanup, inbox filing, batch renaming, duplicate quarantine, or undoing an in-place reorg run.
license: MIT
compatibility: Requires Python 3.10+ and PyYAML; optional pdftotext for PDFs and rclone for Google Drive remotes.
metadata:
  author: rugginic
  version: "3.1.0"
---

# /reorg

CLI: `python3 <skill-dir>/scripts/reorg.py <audit|extract|plan|validate|apply|undo>`, where `<skill-dir>` is the folder holding this `SKILL.md` (usually `~/.agents/skills/reorg`).

Roles:
- **CLI** owns mechanics: audit, bounded extraction, credential filtering, path safety, collisions, drift checks, writes, verification, journal, undo. It also rejects plans that stamp generic words onto many names.
- **Main thread** owns the owner conversation, the folder layout (step 3), merging, the consistency pass, and the approval gate. It does not name or route individual files.
- **Cheap subagents** (Haiku / Luna / Terra / Flash) name and route files in small batches, and inspect images.

Never permanently delete files. Never read files flagged `credential_skipped` or unpack `archive_skipped`.

## Defaults (bare invocation)

`/reorg` with no arguments: target = current workspace folder; goal = full cleanup (real renames, exact-duplicate quarantine to `_Duplicates/`, restructure); mode = in-place move. Do not ask anything up front. Run steps 1-6 and stop at the approval gate (step 7). Anything the owner says ("only dedupe", a path, `--copy`, a rules file, a layout hint) overrides these defaults.

## Naming rules (give these verbatim to every naming subagent)

- Pattern: `YYYY-MM-DD_Type_Counterparty_Detail.ext`. Drop parts that are unknown. No spaces. Write in the language the documents use.
- Date = the document's own date (from content, else from the filename). Never the file's modification time.
- Keep reference numbers: invoice no., quote no., protocol no., transfer ID.
- A rename must add real information taken from the content. **If you learn nothing new, keep the original filename unchanged.** An unchanged name is a correct answer.
- Never prepend or append the folder name or a category word (`Foto_IMG_8117.jpg`, `Preventivo_Preventivo-37.pdf`, `Documento_Fiscale_FATT_12.pdf` are all wrong). The folder already says it. The CLI rejects these.
- Phone/camera names (`IMG_1234`, `PXL_…`, `IMG-…-WA…`, hashes): keep them unless vision gives a specific subject, then `YYYY-MM-DD_Subject_NN`.
- Same document type = same pattern across the whole tree.

## Workflow

1. **Audit (metadata only).** `reorg.py audit <path> --hash` (add `--rules <file>` if the owner gave one; format in `references/rules.example.yaml`). Note counts, existing folders, duplicates, unsupported Drive objects.

2. **Extract.** `reorg.py extract <path> --max-files 0 --output <tmp>/extract.json` for the agreed scope. `credential_skipped`: route by filename only. `archive_skipped`: opaque file. `vision_required`: step 4.

3. **Design the layout once, before any per-file work (main thread).** From the audit tree and a skim of extract summaries, define the target folders:
   - Keep existing folders that carry meaning (e.g. a permits folder stays a permits folder). Do not merge distinct categories into a generic bucket (`Documents`, `Misc`, `Technical`).
   - Write one line per folder saying exactly what belongs there, separating look-alike types: quote vs invoice vs payment receipt vs bank statement vs datasheet/brochure vs permit/filing vs photo vs plan/render vs working spreadsheet.
   - Save it as `<tmp>/layout.yaml` with `allowed_roots: [...]` (plus `max_depth` if useful), and put the definitions as comments. Pass `--rules <tmp>/layout.yaml` to `plan` so the CLI enforces it.

4. **Name and route in batches (subagents).** Batches of **≤30 files**, grouped by current folder. Each brief contains: the layout with its definitions, the naming rules above, the batch's extracted text, and the output format, a TSV with columns `source  target  confidence  reason`. Route by **content, not by the file's current folder name**. Images and scans whose names say nothing: send them to a vision-capable subagent in batches of ≤20. Run a second subagent only on `low` confidence rows.

5. **Consistency pass.** Merge all TSVs. Give the full `source → target` list (no content) to one cheap subagent and ask for rows that: break the naming pattern, name or file the same type differently, sit in the wrong folder per the definitions, or only add generic words. Fix those rows.

6. **Plan.** `reorg.py plan <path> --proposals <merged.tsv> --dedupe --rules <tmp>/layout.yaml --output <tmp>/plan.json`, then `reorg.py validate <tmp>/plan.json --tree`. If `plan` reports `Cosmetic renames rejected`, fix the listed rows (real name or original name) and re-run. Use `--allow-cosmetic` only when the owner asked for prefixes.

7. **Approval gate. Show, don't link.** In the chat, paste:
   - the resulting tree with file counts per folder;
   - **every** rename, grouped by target folder, as `old → new`, plus the number of files kept with their name unchanged;
   - the duplicates going to `_Duplicates/`, and any low-confidence rows.

   A link to a JSON or plan file does not count as showing the plan. Wait for explicit approval of this plan and the write mode. If files changed since planning, re-run `validate`.

8. **Apply.** `reorg.py apply <tmp>/plan.json` (add `--copy` only if additive copy was approved). Report verified counts, warnings, and the journal path.

9. **Undo (when asked).** `reorg.py undo <journal.jsonl>` reverses an in-place run. It verifies integrity, refuses conflicts, and never deletes.
