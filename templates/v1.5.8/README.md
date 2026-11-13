# `templates/v1.5.8/`: The Whole `agy` v1.5.8 CLI System Prompt

The CLI system prompt, section by section, in the order the model receives it (`agy v1.5.8`). Google's text is not in this repo: `python3 capture_prompt.py --binary ~/.local/bin/agy.v1.5.8.orig` writes the rendered prompt, the tool schemas and every template to `stock/` here, which git ignores. [`system_prompts/`](./system_prompts/) holds only the templates we change, which `patch_agy.py --apply` writes into the binary. `patch_agy.py` uses this directory only for a binary that reports `v1.5.8`.

| # | Section | Source | Status | Chars sent (stock → now) |
| ---: | :--- | :--- | :--- | ---: |
| 1 | `identity` | `identity.tmpl` | Google's, unchanged | 272 |
| 2 | `artifacts` | [`artifacts.tmpl`](./system_prompts/artifacts.tmpl) | **Removed** (empty file) | 3,684 → 0 |
| 3 | `conversation_transcript` | [`conversation_transcript.tmpl`](./system_prompts/conversation_transcript.tmpl) | **Rewritten** | 1,915 → 429 |
| 4 | `guidelines` | [`guidelines.tmpl`](./system_prompts/guidelines.tmpl) | **Removed** (empty file) | 1,067 → 0 |
| 5 | `communication_style` | [`communication_style.tmpl`](./system_prompts/communication_style.tmpl) | **Rewritten** | 462 → 123 |
| 6 | `slash_commands` | [`slash_commands.tmpl`](./system_prompts/slash_commands.tmpl) | **Removed** (empty file) | 1,492 → 0 |
| 7 | `messaging` | Go | read-only | 851 |
| 8 | `mcp_servers` | Go + your MCP config | read-only | 1,071 |
| 9 | `subagents` | Go + agent config | read-only | 2,042 |
| 10 | `skills` | [`skills.tmpl`](./system_prompts/skills.tmpl) + skill list | **Rewritten** (omits the SKILL.md lecture and the two stock guides; keeps `swarm` and `swarm_monitor`) | 2,632 → 776 |
| 11 | `user_rules` | Go + your `AGENTS.md` | read-only | 1,493 |
| 12 | `user_information` | Go + session | read-only | 424 |
| | **Total** | | | **17,788 → 7,774** |

The 16 templates, the 16 tool schemas and the rendered prompt are byte for byte those of `v1.5.7`, so `system_prompts/` and `prompt_overrides.json` carry over unchanged. The `generic-system-prompt` experiment that `v1.5.7` turned on stays on: `identity` is Google's and follows it, and `guidelines` stays an empty file, since the one rule our rewrite kept is gone from the stock text (see [`v1.5.7`](../v1.5.7/README.md)).

`ephemeral_message`, `function_call`, `persistent_context`, `test_funcmap` and `helpers/async_termination_rule` are system prompt templates the CLI never renders; they stay Google's.

## Editing

1. Edit a file in `system_prompts/`. Keep every `{{ }}` action: they are Go `text/template` code that `agy` runs each turn, and the text must fit the original slot (`patch_agy.py` reports the limit).
2. Add or update its `reason` in [`prompt_overrides.json`](./prompt_overrides.json), with the `stock_sha256` of Google's original: `python3 prompt_templates.py <name> --digest --binary ~/.local/bin/agy.v1.5.8.orig`.
3. `python3 patch_agy.py --apply`, then `python3 capture_prompt.py` to see the prompt the model now receives (`.cache/system-prompt/v<ver>/PROMPT.md`; diff it against `stock/PROMPT.md`).

An empty file removes its section; deleting the file and its entry restores Google's. Patching from the clean backup stops unless each changed template's original in the binary still has its `stock_sha256`, and unless every changed file has a `reason`.

After an `agy` upgrade there is no `templates/v<new>/`, so patching stops. `python3 probe_agy.py rehearse` creates it when Google's originals under our changes are unchanged, and otherwise dumps them to `stock/` for review. Diff the old and new `stock/PROMPT.md` as well: an experiment's default can change what the same templates render.
