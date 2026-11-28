# `agy` CLI System Prompt: How It Is Built and How to Change It

Findings behind [`templates/`](../templates/). Per-version data lives there: `templates/v<ver>/system_prompts/` holds the templates we change, each with its reason and the digest of Google's original in `prompt_overrides.json`; `capture_prompt.py` writes everything Google ships for a release to `templates/v<ver>/stock/` (the rendered prompt in `PROMPT.md`, tool schemas, all 16 template sources), locally, since git ignores it; and `templates/v<ver>/README.md` maps each section to its source, status and size. Verified against `agy v1.5.19` with [`capture_prompt.py`](../capture_prompt.py).

## 1. Assembly

- **Order and sources.** Stock `agy` defines 13 tagged sections: seven from `embed.FS` templates (`jetski/prompt/template_provider/templates/system_prompts/*.tmpl`, Go `text/template`) and six built in Go code (`mixins.(*<Name>Section).Content`): `work_efficiently`, `messaging`, `mcp_servers`, `subagents`, `user_rules` and `user_information`. In `v1.5.19`, upstream added `language_server.newWorkEfficientlyDisableFactory` (`AGY_CLI_WORK_EFFICIENTLY`), which suppresses `<work_efficiently>` (`949` chars) in default non-OAuth CLI sessions (`17,411` chars / 12 sections) while keeping it available when enabled by `AGY_CLI_WORK_EFFICIENTLY=true` or OAuth Mendel flags (`18,400` chars / 13 sections).
- **Empty sections vanish.** A template that renders to nothing—or a Go mixin whose `ShouldInclude` returns `false`—drops its whole section, tag included.
- **Templates the CLI never renders:** `function_call`, `ephemeral_message`, `persistent_context`, `test_funcmap`, `helpers/async_termination_rule`. `step_strings/` templates format tool results, not the system prompt.
- **Modes and slash commands live in the user turn.** `--mode plan` leaves the system instruction byte-identical; `/plan` expands a `<PLAN>` block inside `ADDITIONAL_METADATA`, and that block relies on the artifact concept (`implementation_plan.md` with `ArtifactMetadata`). The model cannot trigger slash commands itself.
- **MCP tools are lazy.** `mcp_servers` lists them and `call_mcp_tool` invokes them. When `agy` cannot write `<appDataDir>/mcp/` (for example, under a sandbox), it eager-loads every MCP tool as a native schema (`chrome-devtools` alone adds 32 tools, ~33K chars). `capture_prompt.py` isolates the app data dir for that reason.
- **Tool schemas are lean** (`26.6K` chars across 18 tools stock; `27.3K` chars with our `subagent-models` explicit model enum unlock). Two behaviors need a guardrail in the prompt: `edit_file` replaces every occurrence of `Target`, and `ArtifactMetadata` must be omitted for workspace files.
- **The CLI and `--hub` share the binary**, so every template and mixin change applies to both. Keep branches such as `GetSupportsLatexRendering`, which only the hub's Web UI takes.

## 2. Control Surfaces

| Surface | Reaches | Limits |
| :--- | :--- | :--- |
| Template slot override (`templates/v<ver>/system_prompts/`, applied by `patch_agy.py`) | Any template section; all dynamic sections kept | Must fit the original slot; must keep every `{{ }}` action valid. Cannot reach Go sections. |
| Binary mixin/prehook patch (`work-efficiently` group in `patch_agy.py`) | Go-generated `work_efficiently` section & reminder prehook | Cleanly suppresses `<work_efficiently>` (`ShouldInclude → false`) and single-tool-turn reminders (`newWorkEfficientlyReminderHook.func1 → (nil, nil)`) in all auth modes (OAuth & Gateway). |
| `mainAgent` agent.md + `agy --agent <name>` | The whole system instruction | `excludeDefaultComponents: true` drops all default sections, dynamic ones included; without it the body only replaces `identity`. Body is sent verbatim (no template helpers). Omitting `tools:` loses core tools. **`v1.5.17+` OAuth warning**: `--agent` wraps requests in `customAgentModelAPI` (`RequestType: "custom_agent"`), incurring a **`4×` OAuth quota penalty** ([`subagents-and-models.md` §4](./subagents-and-models.md#4-v1517-customagentmodelapi-4-oauth-quota-penalty-issue-1890)). |
| Hooks | Nothing in the system prompt | `hooks.(*HookMixinWrapper).GetSystemPrompt` is a 16-byte delegate. |
| Go string literals | `messaging`, `subagents` repeats, `mcp_servers` frame | Needs per-literal binary edits (text plus length immediate in code). Not done: fragile for minor savings. |

## 3. Decisions (`v1.5.19`)

- **Removed (templates)** `artifacts` (Web-UI-only formatting; pushes reports into files), `guidelines` (drops the sandbox-bypass and CAPTCHA lectures; upstream's `generic-system-prompt` default already dropped comment preservation in `v1.5.7`), and `slash_commands` (promotes commands the model cannot run).
- **Removed (Go mixin + prehook, `work-efficiently` binary group)** `work_efficiently` (`mixins.(*WorkEfficientlySection).ShouldInclude → false`) and its single-tool-turn `<SYSTEM_MESSAGE> Reminder: work efficiently...` injector (`prehooks.newWorkEfficientlyReminderHook.func1 → (nil, nil)`), keeping batching discipline in user rules without repeated boilerplate or mid-conversation nags in either OAuth or Gateway sessions.
- **Rewritten (templates)** `communication_style` (drops the `Be concise` truncation bias and redundant clarification rule; keeps markdown, links, and hub branches) and `skills` (drops the `SKILL.md` anatomy lecture and the two stock builtin guides `agy-customizations` / `antigravity-guide`; keeps `conversations`, `run-workflow`, and the swarm skills; omits the section when no other skill exists).
- **Kept stock** `identity` (wrapped in `LINT.ThenChange(...abuse.pi:antigravity_identity)`; the Google OAuth backend may check it) and `conversation_transcript` (override retired in `v1.5.14` after upstream slimmed it from `1,885` to `411` bytes).
- **Not patched:** the no-polling guidance repeated in `messaging`, `subagents`, and tool descriptions; the `user_rules` preamble, which gives `AGENTS.md` its authority, stays by choice.
- **Result (`v1.5.19`):** `17,411` chars (`12` sections, default CLI) / `18,400` chars (`13` sections with `work_efficiently` active under OAuth or `AGY_CLI_WORK_EFFICIENTLY=true`) → **`8,883` chars** (`9` sections) patched; see [`templates/v1.5.19/README.md`](../templates/v1.5.19/README.md).
