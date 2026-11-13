# `agy` CLI System Prompt: How It Is Built and How to Change It

Findings behind [`templates/`](../templates/). Per-version data lives there: `templates/v<ver>/system_prompts/` holds the templates we change, each with its reason and the digest of Google's original in `prompt_overrides.json`; `capture_prompt.py` writes everything Google ships for a release to `templates/v<ver>/stock/` (the rendered prompt in `PROMPT.md`, tool schemas, all 16 template sources), locally, since git ignores it; and `templates/v<ver>/README.md` maps each section to its source, status and size. Verified against `agy v1.5.3` with [`capture_prompt.py`](../capture_prompt.py).

## 1. Assembly

- **Order and sources.** The system instruction is 12 tagged sections. Seven come from `embed.FS` templates (`jetski/prompt/template_provider/templates/system_prompts/*.tmpl`, Go `text/template`). Five are built in Go code (`mixins.(*<Name>Section).Content`): `messaging`, `mcp_servers`, `subagents`, `user_rules` and `user_information`. Of the stock 17,499 chars, about 5,000 are Go string literals and about 4,000 are your own configuration (rules, MCP servers, session values).
- **Empty sections vanish.** A template that renders to nothing drops its whole section, tag included.
- **Templates the CLI never renders:** `function_call`, `ephemeral_message`, `persistent_context`, `test_funcmap`. `step_strings/` templates format tool results, not the system prompt.
- **Modes and slash commands live in the user turn.** `--mode plan` leaves the system instruction byte-identical; `/plan` expands a 3.9K `<PLAN>` block inside `ADDITIONAL_METADATA`, and that block relies on the artifact concept (`implementation_plan.md` with `ArtifactMetadata`). The model cannot trigger slash commands itself.
- **MCP tools are lazy.** `mcp_servers` lists them and `call_mcp_tool` invokes them. When `agy` cannot write `<appDataDir>/mcp/` (for example, under a sandbox), it eager-loads every MCP tool as a native schema (`chrome-devtools` alone adds 32 tools, ~33K chars). `capture_prompt.py` isolates the app data dir for that reason.
- **Tool schemas are lean** (descriptions 3.6K of 16.6K). Two behaviors need a guardrail in the prompt: `edit_file` replaces every occurrence of `Target`, and `ArtifactMetadata` must be omitted for workspace files.
- **The CLI and `--hub` share the binary**, so every template change applies to both. Keep branches such as `GetSupportsLatexRendering`, which only the hub's Web UI takes.

## 2. Control Surfaces

| Surface | Reaches | Limits |
| :--- | :--- | :--- |
| Template slot override (`templates/v<ver>/system_prompts/`, applied by `patch_agy.py`) | Any template section, all dynamic sections kept | Must fit the original slot; must keep every `{{ }}` action valid. Cannot reach Go sections. |
| `mainAgent` agent.md + `agy --agent <name>` | The whole system instruction | `excludeDefaultComponents: true` drops all 12 sections, dynamic ones included; without it the body only replaces `identity`. It is a bool, with no per-section switch. The body is sent verbatim (no template helpers). Omitting `tools:` loses the core tools. `--settings` has no `agent` key, so a wrapper must add `--agent`. |
| Hooks | Nothing in the system prompt | `hooks.(*HookMixinWrapper).GetSystemPrompt` is a 16-byte delegate. |
| Go string literals | `messaging`, `subagents` repeats, `mcp_servers` frame | Needs per-literal binary edits (text plus the length immediate in code). Not done: about 1,300 chars for a more fragile patch class. |

## 3. Decisions (v1.5.3)

- **Removed** `artifacts` (Web-UI-only formatting; pushes reports into files) and `slash_commands` (promotes commands the model cannot run).
- **Rewritten** `conversation_transcript` (keeps the log path, truncation rule and when to read: only when a compaction summary omits needed detail, or to review subagents), `guidelines` (drops the sandbox-bypass and CAPTCHA lectures; keeps comment preservation), `communication_style` (drops the `Be concise` truncation bias and redundant clarification rule; keeps markdown, links, and hub branches) and `skills` (drops the SKILL.md anatomy lecture and the two stock builtin guides; the section disappears when no user skills exist).
- **Kept** `identity` (wrapped in `LINT.ThenChange(...abuse.pi:antigravity_identity)`; the Google OAuth backend may check it).
- **Not reachable by templates:** the no-polling guidance repeated in `messaging`, `subagents` and three tool descriptions; the `user_rules` preamble, which gives `AGENTS.md` its authority, stays by choice.
