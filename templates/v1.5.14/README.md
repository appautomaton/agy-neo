# `templates/v1.5.14/`: The Whole `agy` v1.5.14 CLI System Prompt

The CLI system prompt, section by section, in the order the model receives it (`agy v1.5.14`). Google's text is not in this repo: `python3 capture_prompt.py --binary ~/.local/bin/agy.v1.5.14.orig` writes the rendered prompt, the tool schemas and every template to `stock/` here, which git ignores. [`system_prompts/`](./system_prompts/) holds only the templates we change, which `patch_agy.py --apply` writes into the binary. `patch_agy.py` uses this directory only for a binary that reports `v1.5.14`.

| # | Section | Source | Status | Chars sent (stock → now) |
| ---: | :--- | :--- | :--- | ---: |
| 1 | `identity` | `identity.tmpl` | Google's, unchanged | 272 |
| 2 | `artifacts` | [`artifacts.tmpl`](./system_prompts/artifacts.tmpl) | **Removed** (empty file) | 3,684 → 0 |
| 3 | `conversation_transcript` | `conversation_transcript.tmpl` | Google's, unchanged (override retired; upstream slimmed `1,915 → 441`) | 441 |
| 4 | `guidelines` | [`guidelines.tmpl`](./system_prompts/guidelines.tmpl) | **Removed** (empty file) | 1,067 → 0 |
| 5 | `work_efficiently` | Go | read-only | 949 |
| 6 | `communication_style` | [`communication_style.tmpl`](./system_prompts/communication_style.tmpl) | **Rewritten** | 462 → 123 |
| 7 | `slash_commands` | [`slash_commands.tmpl`](./system_prompts/slash_commands.tmpl) | **Removed** (empty file) | 1,492 → 0 |
| 8 | `messaging` | Go | read-only | 851 |
| 9 | `mcp_servers` | Go + your MCP config | read-only | 796 |
| 10 | `subagents` | Go + agent config | read-only | 2,042 |
| 11 | `skills` | [`skills.tmpl`](./system_prompts/skills.tmpl) + skill list | **Rewritten** (omits the SKILL.md lecture and `agy-customizations` / `antigravity-guide`; keeps `run-workflow`, `swarm_monitor`, `swarm_pane`) | 3,140 → 1,284 |
| 12 | `user_rules` | Go + your `AGENTS.md` | read-only | 1,493 |
| 13 | `user_information` | Go + session | read-only | 424 |
| | **Total** | | | **17,536 → 9,008** |

Upstream `v1.5.14` slims `conversation_transcript.tmpl` from `1,885` to `411` raw bytes (`1,915 → 441` rendered chars) by dropping the `# File Format` JSONL field catalog, retiring our override. The other 5 changed templates are byte for byte those of `v1.5.13`. Upstream also trims `mcp_servers` boilerplate (`-275` chars), advertises the new `swarm_pane` skill (`+332` chars), and guards the `swarm` tool description against unprompted calls (`+336` chars in `tools.json`).

`ephemeral_message`, `function_call`, `persistent_context`, `test_funcmap` and `helpers/async_termination_rule` are system prompt templates the CLI never renders; they stay Google's.

## Editing

1. Edit a file in `system_prompts/`. Keep every `{{ }}` action: they are Go `text/template` code that `agy` runs each turn, and the text must fit the original slot (`patch_agy.py` reports the limit).
2. Add or update its `reason` in [`prompt_overrides.json`](./prompt_overrides.json), with the `stock_sha256` of Google's original: `python3 prompt_templates.py <name> --digest --binary ~/.local/bin/agy.v1.5.14.orig`.
3. `python3 patch_agy.py --apply`, then `python3 capture_prompt.py` to see the prompt the model now receives (`.cache/system-prompt/v<ver>/PROMPT.md`; diff it against `stock/PROMPT.md`).

An empty file removes its section; deleting the file and its entry restores Google's. Patching from the clean backup stops unless each changed template's original in the binary still has its `stock_sha256`, and unless every changed file has a `reason`.

After an `agy` upgrade there is no `templates/v<new>/`, so patching stops. `python3 probe_agy.py rehearse` creates it when Google's originals under our changes are unchanged, and otherwise dumps them to `stock/` for review. Diff the old and new `stock/PROMPT.md` as well: an experiment's default can change what the same templates render.
