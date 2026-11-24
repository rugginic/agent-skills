# agent-skills

Reusable, harness-agnostic skills following the open [Agent Skills](https://agentskills.io/) standard (`SKILL.md`). Compatible with **Claude Code**, **Codex**, **OpenCode**, **Pi**, **Antigravity**, and other `SKILL.md`-compatible coding agents.

## Available Skills

| Skill | Description | Path |
| --- | --- | --- |
| [`reorg`](skills/reorg/SKILL.md) | Organize, rename, file, deduplicate, audit, or undo file reorganizations across local folders, NAS mounts, and Google Drive remotes — with a deterministic zero-delete Python CLI (`scripts/reorg.py`) and an orchestrator + cheap-subagent workflow. | `skills/reorg/` |

## Installation

### Cross-harness (`npx skills`)

Works across Claude Code, Codex, OpenCode, Pi, Antigravity, Cursor, and more:

```bash
# Install all skills globally
npx skills add rugginic/agent-skills -g

# Or install a single skill
npx skills add rugginic/agent-skills --skill reorg -g

# Update installed skills later
npx skills update
```

### Claude Code Native Marketplace

```text
/plugin marketplace add rugginic/agent-skills
/plugin install reorg@rugginic-agent-skills
```

### Manual Clone

```bash
git clone https://github.com/rugginic/agent-skills.git
ln -s "$PWD/agent-skills/skills/reorg" ~/.agents/skills/reorg
```

## Skill Requirements (`reorg`)

- Python 3.10+ with `PyYAML` (`pip install pyyaml`)
- Optional: `pdftotext` (Poppler) for PDF text extraction
- Optional: `rclone` with a configured Google Drive remote for `gdrive:...` targets (uses rclone OAuth tokens to talk directly to Google Drive v3 API)

## Repository Structure

```text
.
├── .claude-plugin/
│   └── marketplace.json        # Claude Code native marketplace manifest
├── .github/workflows/
│   └── test.yml                # Automated CI test suite
└── skills/
    └── <skill-name>/
        ├── SKILL.md            # Frontmatter metadata + agent workflow
        ├── scripts/            # Deterministic helper scripts/CLIs
        ├── references/         # Optional progressive-disclosure reference files
        └── tests/              # Self-contained tests
```

## Running Tests

```bash
python3 -B skills/reorg/tests/test_reorg.py -v
```

## License

[MIT](LICENSE)
