# Subagent Dispatch, Custom `agent.md` Schema & Model Tier Resolution

Verified against `agy v1.5.1` (`darwin/arm64`) via `__lrodata_gopcln` disassembly of `google3/third_party/jetski/cortex/handlers`, `google3/third_party/oneharness/internal/tools`, `google3/third_party/jetski/models/geminimodels`, and `google3/third_party/jetski/admin_controls`.

---

## 1. Subagent Dispatch & Three-Level Definition Hierarchy

### 1.1 `invoke_subagent` Runtime Parameters
`InvokeSubagentTool.launch` (`0x10134f6e0`) resolves the target agent (`findAgentByName`), resolves the requested model tier (`resolveModel`), folds parent cascade config into the agent spec (`foldSubagentConfig` $\rightarrow$ `config.FoldCascadeConfigIntoAgent`), and spawns an asynchronous subagent conversation.

| Parameter | Allowed Values | Behavior |
| :--- | :--- | :--- |
| **`TypeName`** | `'self'` \| `'research'` \| `'image-generator'` \| `<custom>` | Selects built-in, session-defined, or disk-persisted agent spec. |
| **`Role`** | 2–5 word title | Instance label; multiple concurrent subagents can share `TypeName` with distinct `conversationId` and `Role`. |
| **`Model`** | `'inherit'` (default) \| `'flash_lite'` \| `'flash'` \| `'pro'` | Model tier override resolved against `TieredModelConfig`. |
| **`Workspace`** | `'inherit'` (default) \| `'branch'` \| `'share'` | `'inherit'`: shared parent workspace. `'branch'`: full isolated clone (`CreateForkedWorkspaces`). `'share'`: shared repo store with independent worktree/branch (`git worktree` / `hg share`). |

### 1.2 Built-in Subagents (`customizations/builtin/agents.AllAgentsWithConfig` @ `0x1015f3b70`)
- **`self`** (`SelfSpecFromCascadeConfig`): Inherits parent tools, system prompt, and model in a fresh context window.
- **`research`**: Read-only sandbox (`view_file`, `search_web`, read-only `run_command`; no write tools, no external network).
- **`image-generator`**: Invokes `gemini-3.1-flash-image` (`0x1017e12e8`) and returns saved media paths.

### 1.3 Session-Scoped Dynamic Subagents (`define_subagent`)
`DefineSubagentSubHandler.Handle` validates `Name` (rejecting `..` path traversal) and writes a Markdown `agent.md` file into the active conversation's artifact directory (`<appDataDir>/brain/<conversation-id>/`).
- **Capability switches**: `EnableWriteTools` (file edits + `run_command`), `EnableMCPTools`, `EnableSubagentTools` (recursive subagent spawning).

### 1.4 Persistent Disk-Defined Agents (`agent.md` & `agents.json`)
`agy` (`v1.1.6+`) discovers custom agents from `.agents/agents/<name>/agent.md` (or `.agents/agents/*.md`) in the workspace and `~/.gemini/config/agents/<name>/agent.md` globally (plus external paths declared in `agents.json`).

**Supported YAML Frontmatter Fields (`customizations` Go struct tags)**:
```yaml
---
mainAgent: false                   # Can be launched as top-level `agy --agent <name>`
subagent: true                     # Exposed in Available subagents for `invoke_subagent`
hidden: false                      # Hide from `/agents` UI list
disabled: false                    # Disable ingestion
model: gemini-3.8-flash-high       # Default model when invoked with `Model: 'inherit'`
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

## 2. Default Model Tiers (`flash_lite`, `flash`, `pro`)

When `invoke_subagent` (or internal monitors/title generation) requests a model tier, `modelutils.SubagentModelsFromTieredConfig` resolves the tier against `FetchAvailableModelsResponse.tiered_model_ids` (`TieredModelConfig`).

### 2.1 `geminimodels.Catalog()` (`0x1017e0a00` — Active Under `GEMINI_API_KEY` / `"modelProvider": "gemini"`)
When running with `GEMINI_API_KEY` and `--settings '{"modelProvider":"gemini"}'`, `CodeAssistClient.fetchAvailableModels` bypasses remote CloudCode catalog discovery and returns the static `geminimodels.Catalog()`:

| Tier / Slot | Hardcoded Model ID | Instruction VA (`v1.5.1`) | Notes |
| :--- | :--- | :--- | :--- |
| **`pro`** (`TieredModelConfig.Pro`) | **`gemini-4-argon-high`** | `0x1017e13dc` | Default 4.0 Pro/Argon tier |
| **`flash`** (`TieredModelConfig.Flash`) | **`gemini-3.8-flash-medium`** | `0x1017e1390` | Default 3.8 Flash tier |
| **`flash_lite`** (`TieredModelConfig.FlashLite`) | **`gemini-3.1-flash-lite-preview`** | `0x1017e1344` | Used by `flash_lite` subagents, `conversation_title.go`, and `sir_flash_lite` monitor |
| **`DefaultAgentModelId`** | `gemini-3.1-pro-low` | `0x1017e1278` | Fallback when no session model is selected |
| **`CommandModelIds` / `TabModelIds`** | `gemini-3.1-flash-lite-preview` | `0x1017e129c` | Inline command/tab completion model |
| **`ImageGenerationModelIds`** | `gemini-3.1-flash-image` | `0x1017e12e8` | Backing model for `image-generator` subagent |

> **Offline Fallback (`codeassistclient.buildDefaultAvailableModels` @ `0x101b74830`)**: If OAuth mode is active and remote catalog fetch fails completely, fallback tiers are `flash_lite` = `gemini-3.1-flash-lite-preview`, `flash` = `gemini-3.7-flash-medium`, `pro` = `gemini-3.1-pro-low-thinking`.

### 2.2 `CLIProxyAPI` (`localhost:5233`) Routing Pitfall & Fix
Because `geminimodels.Catalog()` hardcodes `flash_lite` to `gemini-3.1-flash-lite-preview`:
- Every conversation start (`conversation_title.go:203`) and every `run_command` pre-check (`llm_monitor.go:712` `sir_flash_lite`) sends a request for `model: "gemini-3.1-flash-lite-preview"`.
- If `CLIProxyAPI` does not route `gemini-3.1-flash-lite-preview`, it returns `400 Bad Request: unknown provider for model gemini-3.1-flash-lite-preview` ( forcing `severe_internal_risks_agy` to re-run on `MODEL_TIER_FLASH` and breaking auto-titles).
- **Fix**: Alias `gemini-3.1-flash-lite-preview` $\rightarrow$ `gemini-3.8-flash-low` in `CLIProxyAPI` (or avoid `Model: 'flash_lite'` in `invoke_subagent`).

---

## 3. Configuration File Hierarchy & Overrides

`agy` maintains **two distinct JSON configuration schemas** that must not be confused:

| Config File | Go Parser / Struct | Purpose & Model Controls |
| :--- | :--- | :--- |
| **`~/.gemini/antigravity-cli/settings.json`** | `cli/types.CliSetting` | TUI session state: `"model"`, `"contextWindow"`, `"agentMode"`, `"toolPermission"`, `"modelProvider"`, `"customModels"`. **Does not** configure `TieredModelConfig`. |
| **`~/.gemini/config/config.json`** (and `/Library/Application Support/Antigravity/admin_settings.json`) | `admincontrols.AdminSettings` (`loadUserConfigSettings` @ `0x1015526a0`) | Governance, gateway, and tier overrides: `models.tiers.{flashLite, flash, pro}`, `models.list`, `gateway`, `proxy`, `userSettings`. |

### Where Tiers Apply, and Which Source Wins (`v1.5.8`)
- **Gateway sessions only.** `admincontrols.(*TieredModelConfig).ApplyToProto` has one caller, `gateway.applyConfiguredModelTiers`, reached only from `gateway.(*AuthProvider).GetModelCatalog`. Under OAuth the catalog, tiers included, comes from Cloud Code, and `models.tiers` in any local file is ignored; changing OAuth tiers would take a binary patch on that path.
- **Precedence.** `loadEffectiveSettings` calls `MergeSettings(admin, env, user)`, which applies `user settings` (`~/.gemini/config/config.json`), then `environment` (`AGY_LLM_GATEWAY_TIER_*`), then `admin_settings.json`; each later source overwrites the tiers it sets (`mergeTiers`). So the admin file beats the environment, which beats `config.json`. `hub-wrapper.sh` always exports all three tier variables (its defaults fill any unset one), so under the wrapper a `models.tiers` in `config.json` never takes effect.

### Ways to Override Subagent Models
1. **Per-Subagent Type (Works in all auth modes)**: Set `model: <model-id>` in `~/.gemini/config/agents/<name>/agent.md` (or `.agents/agents/<name>/agent.md`) and invoke with default `Model: 'inherit'`.
2. **Gateway Tier Env Vars (`admincontrols.ParseEnvOverrides` @ `0x1015507e0`)**:
   - `AGY_LLM_GATEWAY_TIER_FLASH_LITE`
   - `AGY_LLM_GATEWAY_TIER_FLASH`
   - `AGY_LLM_GATEWAY_TIER_PRO`
3. **Gateway `config.json` Tier Map (`admincontrols.TieredModelConfig`)**:
   ```json
   {
     "models": {
       "tiers": {
         "flashLite": "gemini-3.8-flash-low",
         "flash": "gemini-3.8-flash-high",
         "pro": "gemini-4-argon-high"
       }
     }
   }
   ```
