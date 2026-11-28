# Subagent Dispatch, Custom `agent.md` Schema & Model Tier Resolution

Verified against `agy v1.5.19` (`darwin/arm64`) via `__lrodata_gopcln` disassembly of `google3/third_party/jetski/cortex`, `google3/third_party/jetski/cortex/modelutils`, `google3/third_party/oneharness/internal/tools`, `google3/third_party/jetski/models/geminimodels`, and `google3/third_party/jetski/admin_controls`.

---

## 1. Subagent Dispatch & Three-Level Definition Hierarchy

### 1.1 `invoke_subagent` Runtime Parameters
`InvokeSubagentTool.launch` (`0x1023fd120`) delegates to `subagentResolver.resolve` (`0x10241ce20`), which locates the target agent (`findAgentByName`), validates and resolves the requested model (`resolveModel` @ `0x10241d800`), folds parent cascade config into the agent spec (`foldSubagentConfig` @ `0x10241dd20`), and launches an asynchronous subagent conversation (`launchSubagent` @ `0x1023fe800`).

| Parameter | Allowed Values | Behavior |
| :--- | :--- | :--- |
| **`TypeName`** | `'self'` \| `'research'` \| `'image-generator'` \| `<custom>` | Selects built-in, session-defined, or disk-persisted agent spec. |
| **`Role`** | 2–5 word title | Instance label; multiple concurrent subagents can share `TypeName` with distinct `conversationId` and `Role`. |
| **`Model`** | `'inherit'` (default) \| `'flash_lite'` \| `'flash'` \| `'pro'` \| explicit dropdown model (`subagent-models` patch) | Validated against `InvokeSubagentToolConfig.ModelOptions.Options` (§2.2–§2.3). |
| **`Workspace`** | `'inherit'` (default) \| `'branch'` \| `'share'` | `'inherit'`: shared parent workspace. `'branch'`: full isolated clone. `'share'`: shared repo store with independent worktree/branch (`git worktree` / `hg share`). |

### 1.2 Built-in Subagents (`customizations/builtin/agents.AllAgentsWithConfig` @ `0x101729df0`)
- **`self`** (`SelfSpecFromCascadeConfig`): Inherits parent tools, system prompt, and model in a fresh context window.
- **`research`**: Read-only sandbox (`view_file`, `search_web`, read-only `run_command`; no write tools, no external network).
- **`image-generator`**: Invokes `gemini-3.1-flash-image` and returns saved media paths.

### 1.3 Session-Scoped Dynamic Subagents (`define_subagent`)
`DefineSubagentSubHandler.Handle` validates `Name` (rejecting `..` path traversal) and writes a Markdown `agent.md` file into the active conversation's artifact directory (`<appDataDir>/brain/<conversation-id>/`).
- **Capability switches**: `EnableWriteTools` (file edits + `run_command`), `EnableMCPTools`, `EnableSubagentTools` (recursive subagent spawning).
- **Quota billing**: Runs as a standard `"agent"` trajectory (`1×` OAuth quota; see §4).

### 1.4 Persistent Disk-Defined Agents (`agent.md` & `agents.json`)
`agy` discovers custom agents from `.agents/agents/<name>/agent.md` (or `.agents/agents/*.md`) in the workspace and `~/.gemini/config/agents/<name>/agent.md` globally (plus external paths declared in `agents.json`), parsed by `customizations.ParseAgentScriptItemFromMarkdown` (`0x1017ac3d0`).

> **Warning (`v1.5.17+` OAuth `4×` quota penalty)**: Disk-defined custom agents launched via `agy --agent <name>` or `invoke_subagent` are wrapped in `cortex.(*customAgentModelAPI)` and billed at **`4×` OAuth quota** (`RequestType: "custom_agent"`). See §4 before defining disk agents for OAuth sessions.

**Supported YAML Frontmatter Fields (`customizations` Go struct tags)**:
```yaml
---
mainAgent: false                   # Can be launched as top-level `agy --agent <name>`
subagent: true                     # Exposed in Available subagents for `invoke_subagent`
hidden: false                      # Hide from `/agents` UI list
disabled: false                    # Disable ingestion
model: gemini-4-neon-xhigh         # Default model when invoked with `Model: 'inherit'` (validated against ModelOptions)
inheritCustomizations: true        # Single switch for skills, rules, plugins, subagents, MCP
inheritMcp: true                   # Granular MCP inheritance override
commandExecutionPolicy: auto       # Terminal auto-execution policy override
tools: []                          # Explicit tool allowlist
enabledTools: []                   # Additional enabled tools
disabledTools: []                  # Blocked tools
skills: []                         # Scoped skills
rules: []                          # Scoped rules
hooks: {}                          # Scoped lifecycle hooks
mcpServers: {}                     # Scoped MCP server specs
---
# System Prompt
Your instructions here...
```

---

## 2. Model Tier Resolution, `ModelOptions` Validation & Explicit Dropdown Unlock

When `invoke_subagent` (or `run_workflow` / internal utility calls) requests a model tier or named model, `cortex.(*CascadeManager).populatePlatformModels` (`0x102587970`) fetches the active catalog via `modelutils.FetchAvailableModels` (`0x101771dd0`) and builds both `ModelTierConfig` (`modelutils.ModelTierConfigFromTieredConfig` @ `0x101773140`) and `InvokeSubagentToolConfig.ModelOptions` (`modelutils.SubagentModelsFromAvailableModels` @ `0x101772640`).

### 2.1 OAuth vs. Gateway Model Tiers (`v1.5.19`)

| Tier | Google OAuth (Cloud Code `FetchAvailableModels`) | Enterprise Gateway / `GEMINI_API_KEY` (`geminimodels.Catalog` @ `0x101851380`) | `hub-wrapper.sh` Gateway Default (`AGY_LLM_GATEWAY_TIER_*`) |
| :--- | :--- | :--- | :--- |
| **`flash_lite`** | **`gemini-3.5-flash-lite`** | `gemini-3.1-flash-lite-preview` | `gemini-4-hydrogen-high` |
| **`flash`** | **`gemini-4-hydrogen-tiered-high`** | `gemini-3.8-flash-medium` | `gemini-4-neon-xhigh` |
| **`pro`** | **`gemini-4-hydrogen-tiered-xhigh`** | `gemini-4-argon-high` | `gemini-4-carbon-high` |

Additional static slots in `geminimodels.Catalog()` (`v1.5.19: 0x101851380`):
- `DefaultAgentModelId`: `gemini-3.1-pro-low`
- `CommandModelIds` / `TabModelIds`: `gemini-3.1-flash-lite-preview`
- `ImageGenerationModelIds`: `gemini-3.1-flash-image`
- **Offline OAuth fallback** (`codeassistclient.buildDefaultAvailableModels` @ `0x101f136c0`): if remote catalog fetch fails completely under OAuth, fallback tiers are `flash_lite` = `gemini-3.1-flash-lite-preview`, `flash` = `gemini-3.7-flash-medium`, `pro` = `gemini-3.1-pro-low-thinking`.

> **CLIProxyAPI (`localhost:5233`) routing note**: Without `AGY_LLM_GATEWAY_TIER_FLASH_LITE` (which `hub-wrapper.sh` sets to `gemini-4-hydrogen-high`), `geminimodels.Catalog()` routes conversation title generation and `flash_lite` subagents to `gemini-3.1-flash-lite-preview`. If bypassing `hub-wrapper.sh` with `--settings '{"modelProvider":"gemini"}'`, alias `gemini-3.1-flash-lite-preview` in CLIProxyAPI or set `AGY_LLM_GATEWAY_TIER_FLASH_LITE`.

### 2.2 `v1.5.18+` `ModelOptions` Validation on `invoke_subagent` and `agent.md`
In `v1.5.18+`, `tools.subagentResolver.resolveModel` (`0x10241d800`) validates the requested model—whether passed via `invoke_subagent`'s `Model` argument **or** declared via `model:` in an `agent.md` frontmatter—through `tools.findNamedModel` (`0x1023fe610`) against `InvokeSubagentToolConfig.ModelOptions.Options` (case-insensitive `strings.EqualFold`) before calling `modelutils.ResolveCatalogModel` (`0x101771820`).

If the requested model is absent from `ModelOptions.Options` (and is not `inherit`), `resolveModel` rejects the launch (or forces `inherit` when `AlwaysInheritModel` is set). Under stock Google OAuth, `ModelOptions.Options` only exposes the three tier aliases (`flash_lite`, `flash`, `pro`) plus `inherit`, so specifying an explicit model such as `gemini-4-neon-xhigh` or `Gemini 4 Neon (XHigh)` fails validation on both `invoke_subagent` and `agent.md`.

### 2.3 Binary Unlock: `subagent-models` Group (`patch_agy.py`)
Inside `cortex.(*CascadeManager).populatePlatformModels` (`v1.5.19: 0x102587970`, `v1.5.18: 0x1025614a0`), upstream looks up the `"enable-subagent-dropdown-models"` experiment flag via `runtime.mapaccess2_faststr`:
- **True branch (`+0x204`)**: Passes the full `*FetchAvailableModelsResponse` (`[sp, #0x50]`) to `modelutils.SubagentModelsFromAvailableModels`, populating `ModelOptions.Options` with `inherit`, the three tier aliases, **and** every available dropdown model (such as `Gemini 4 Neon (Low..XHigh)`, `Gemini 4 Carbon (Low..High)`, `Gemini 4 Hydrogen (Low..XHigh)`, and `Gemini 4 Argon (Low..High)`).
- **False branch (`+0x210`, stock default)**: Constructs a stripped `FetchAvailableModelsResponse` containing only `TieredModelIds`, hiding every explicit dropdown model.

Our `subagent-models` patch group (`1` site, `4B` at `populatePlatformModels + 0x1d0`) replaces `tbz w1, #0, false_branch` with `b true_branch`, unlocking explicit dropdown model selection for `invoke_subagent`, `agent.md`, and `run_workflow` across both Google OAuth and Gateway sessions.

---

## 3. Configuration File Hierarchy & Overrides

`agy` maintains **two distinct JSON configuration schemas**:

| Config File | Go Parser / Struct | Purpose & Model Controls |
| :--- | :--- | :--- |
| **`~/.gemini/antigravity-cli/settings.json`** | `cli/types.CliSetting` | TUI session state: `"model"`, `"contextWindow"`, `"agentMode"`, `"toolPermission"`, `"modelProvider"`, `"customModels"`. **Does not** configure `TieredModelConfig`. |
| **`~/.gemini/config/config.json`** (and `/Library/Application Support/Antigravity/admin_settings.json`) | `admincontrols.AdminSettings` | Governance, gateway, and tier overrides: `models.tiers.{flashLite, flash, pro}`, `models.list`, `gateway`, `proxy`, `userSettings`. |

### Where Tiers Apply & Which Source Wins
- **Gateway sessions only.** `admincontrols.(*TieredModelConfig).ApplyToProto` has one caller, `gateway.applyConfiguredModelTiers`, reached only from `gateway.(*AuthProvider).GetModelCatalog`. Under Google OAuth, the catalog and tiers come from Cloud Code and local `models.tiers` files are ignored.
- **Precedence.** `loadEffectiveSettings` calls `MergeSettings(admin, env, user)`, applying `~/.gemini/config/config.json`, then `AGY_LLM_GATEWAY_TIER_*`, then `admin_settings.json`; each later source overwrites the tiers it sets. Because `hub-wrapper.sh` exports all three `AGY_LLM_GATEWAY_TIER_*` variables, it takes precedence over `config.json` unless overridden via the environment or `admin_settings.json`.

### Ways to Override Subagent Models
1. **Explicit model via `invoke_subagent` / `run_workflow` (All auth modes with `subagent-models` patch)**: Pass a dropdown model name/ID (e.g. `Gemini 4 Neon (XHigh)` / `gemini-4-neon-xhigh`) or a tier alias (`flash_lite`, `flash`, `pro`).
2. **Gateway Tier Env Vars**:
   - `AGY_LLM_GATEWAY_TIER_FLASH_LITE`
   - `AGY_LLM_GATEWAY_TIER_FLASH`
   - `AGY_LLM_GATEWAY_TIER_PRO`
3. **Gateway `config.json` Tier Map (`admincontrols.TieredModelConfig`)**:
   ```json
   {
     "models": {
       "tiers": {
         "flashLite": "gemini-4-hydrogen-high",
         "flash": "gemini-4-neon-xhigh",
         "pro": "gemini-4-carbon-high"
       }
     }
   }
   ```
4. **Per-agent `agent.md` frontmatter**: Set `model:` in `.agents/agents/<name>/agent.md` (subject to `ModelOptions` validation in §2.2 and the `4×` OAuth quota caveat in §4).

---

## 4. `v1.5.17+` `customAgentModelAPI` `4×` OAuth Quota Penalty (Issue #1890)

Starting in `v1.5.17`, `cortex.(*CascadeManager).makeAgentExecutorOpts` (`v1.5.19: 0x1025880a0`) calls `cortex.isCustomAgentTrajectory` (`0x102598f00`). When it returns `true`, the trajectory's `ModelAPI` is wrapped in `cortex.(*customAgentModelAPI)`.

In `cortex.(*customAgentModelAPI).Generate` (`0x102599190`), every request whose `RequestType` (`+0x78`) is `"agent"` is cloned with `RequestType` rewritten to **`"custom_agent"`** before hitting Cloud Code. Under Google OAuth, Cloud Code meters `"custom_agent"` traffic at **`4×` quota** relative to standard `"agent"` requests:

| Dispatch Surface | `isCustomAgentTrajectory` | `RequestType` | OAuth Quota Multiplier |
| :--- | :---: | :--- | :---: |
| Top-level `agy` (default) | `false` | `"agent"` | **`1×`** |
| Built-in subagents (`self`, `research`, `image-generator`) | `false` | `"agent"` | **`1×`** |
| Session-dynamic `define_subagent` | `false` | `"agent"` | **`1×`** |
| `/swarm` coordinator & workers | `false` | `"agent"` | **`1×`** |
| Disk `.agents/agents/*.md` / `~/.gemini/config/agents/*.md` (`invoke_subagent`) | **`true`** | **`"custom_agent"`** | **`4×`** |
| Top-level `agy --agent <name>` | **`true`** | **`"custom_agent"`** | **`4×`** |

**Practical guidance for OAuth sessions**: Prefer built-in `self`/`research`, session-scoped `define_subagent`, or `/swarm` over disk `.agents/agents/*.md` or `--agent <name>` whenever OAuth quota matters. Enterprise Gateway / `CLIProxyAPI` sessions are unaffected by Cloud Code's `"custom_agent"` multiplier.
