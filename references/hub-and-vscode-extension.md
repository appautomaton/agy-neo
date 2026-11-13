# `agy --hub`, VS Code Extension (`1.11.0`) & Local Gateway Routing

Verified against `agy v1.5.1` (`darwin/arm64`, embedded Language Server `v2.29.0`) and VS Code extension `google.google-antigravity-1.11.0` (`~/.vscode/extensions/google.google-antigravity-1.11.0/extension.js`).

---

## 1. Three-Surface Architecture (Single Binary, Two Runtime Modes)

`agy` CLI and `agy --hub` are entrypoints inside the same Mach-O binary (`~/.gemini/bin/agy` / `~/.local/bin/agy`). The VS Code extension is a thin TypeScript host that spawns `agy --hub`.

| Surface | Entrypoint / Process | App Data Dir (`--app_data_dir`) | Runtime Settings File | Shared Customizations |
| :--- | :--- | :--- | :--- | :--- |
| **`agy` CLI** (`jetbox`) | `agy` (`main.main` $\rightarrow$ TUI / `--print` / `acp`) | `~/.gemini/antigravity-cli/` | `~/.gemini/antigravity-cli/settings.json` | `~/.gemini/config/` (`mcp_config.json`, `config.json`, `plugins`, `skills`, `agents`), `<repo>/.agents/`, `AGENTS.md`, `GEMINI.md` |
| **`agy --hub`** (`agyhub`) | `AGY_ENABLE_HUB=1 agy --hub` (`main.runHubServer` @ `0x102ecae30`) | `~/.gemini/antigravity/` (default when `--app_data_dir=antigravity`) | `~/.gemini/antigravity/settings.json` + `~/.gemini/config/config.json` | Same as above |
| **VS Code Extension** (`1.11.0`) | `extension.js` (`spawnAndWaitForPort` L22997) spawns `~/.gemini/bin/agy --hub` | Passes `--app_data_dir=antigravity` (`~/.gemini/antigravity/`) | VS Code `settings.json` (`antigravity.*`) + `~/.gemini/config/config.json` | Same as above |

### 1.1 Hidden Flags Stripped from `--help` (`main.hideFlagsForExternal` @ `0x102ec6e40`)
`agy` registers internal flags in `main.registerHubFlags` (`0x102ecaae0`) and `language_server` flag sets, then hides them from external `--help` unless internal env gates are set:
- `--hub` (requires `AGY_ENABLE_HUB=1` or VS Code host env): Starts embedded Language Server (`v2.29.0`) and serves the Antigravity 2.0 Web UI bundle over HTTP + gRPC.
- `--hub-port=<int>`: Loopback HTTP port for the Hub server (`0` = ephemeral port).
- `--app_data_dir=<name>`: Subdirectory under `~/.gemini/` (`antigravity-cli` by default in CLI; `antigravity` when passed by VS Code extension).
- `--csrf_token=<uuid>`: CSRF token required by the Webview/browser bridge.
- `--cloud_code_endpoint=<url>`: Overrides upstream `https://daily-cloudcode-pa.googleapis.com` (`v1internal` protocol).
- `--settings=<json-or-path>`: Ephemeral per-session JSON overrides for `<app_data_dir>/settings.json` (highest precedence, never saved to disk).

### 1.2 VS Code Extension (`1.11.0`) Binary Verification & Spawn Flow
1. **Binary path (`yb()`)**: Uses `~/.gemini/bin/agy` and caches `{version, size, mtimeMs, ino}` in `~/.gemini/bin/agy.version.json` (`Va.BINARY_SIDECAR_FILENAME`, L22834).
2. **Version check (`Gb()` L22844)**: Runs `~/.gemini/bin/agy --version` and requires `>= 1.1.11` (skips download if installed version `>=` remote manifest `1.5.1`, preserving patched binaries).
3. **Environment construction (`dd()` / `buildServerEnvironment` L22949)**: Inherits `process.env` and injects `AGY_ENABLE_HUB="1"`, `ANTIGRAVITY_VSCODE_HOST="1"`, `ANTIGRAVITY_AUTH_SUCCESS_APP="vscode"`, and system CA bundle paths.
4. **Process spawn (`spawnAndWaitForPort` L22997)**:
   ```text
   ~/.gemini/bin/agy --hub --hub-port=<port> --app_data_dir=antigravity --csrf_token=<uuid> --add-dir=<workspace> [...antigravity.serverArgs]
   ```
5. **External server override (`getEffectiveServerUrl`)**: Checks `process.env.ANTIGRAVITY_SERVER_URL` or undocumented VS Code setting `"antigravity.serverUrl"` before using the internally spawned process URL.

---

## 2. Backend Auth & Model Routing Internals (`CreateLanguageServerAndServe` $\rightarrow$ `setUpClients`)

### 2.1 Why `--hub` Ignores `modelProvider: "gemini"` but Honors `AGY_LLM_GATEWAY_*`
1. In `main.main` (`0x102ecec1c`), when `--hub` is active, `main.configureHeadlessServer` (`0x102ecad30`) sets `cfg.IsHub = true` (`offset +0x410`).
2. Even if `main.applyModelBackendSelection` (`0x102ecb710`) sets `cfg.ModelAPIClientType = 1` (`"gemini"`, `offset +0x248`), `language_server.CreateLanguageServerAndServe` (`0x1027b7030`) explicitly checks `cfg.IsHub` **before** `cfg.ModelAPIClientType`:
   ```arm64
   1027b7030: ldrb w3, [x6, #0x410]         ; w3 = cfg.IsHub
   1027b7034: tbz  w3, #0x0, 0x1027b7044    ; if !IsHub, check ModelAPIClientType (+0x248)
   1027b7038: mov  x3, xzr                  ; IsHub == 1 -> skip GeminiAPIKeyAuthProvider!
   1027b7040: b    0x1027b7118
   ```
3. However, inside `language_server.setUpClients` (`0x1027b0ef0`), **before** falling back to `AntigravityHubAuthProvider` (`daily-cloudcode-pa.googleapis.com`), `agy` checks `adminSettings.Gateway.Enabled` (`0x1027b1040`–`0x1027b1068`):
   ```arm64
   1027b1040: ldr  x5, [x2, #0x18]          ; adminSettings.Gateway
   1027b1050: ldrb w5, [x5]                 ; *Gateway.Enabled
   1027b1068: tbnz w5, #0x0, 0x1027b120c    ; -> gateway.NewAuthProviderFromSettings!
   ```
4. Exporting `AGY_LLM_GATEWAY_URL`, `AGY_LLM_GATEWAY_API_KEY`, and `AGY_LLM_GATEWAY_WIRE_PROTOCOL="genai"` triggers `admincontrols.ParseEnvOverrides` (`0x1015507e0`) to set `Gateway.Enabled = true`, routing `--hub` directly to `127.0.0.1:5233` with zero `daily-cloudcode-pa.googleapis.com` calls (cutting Hub startup time from ~610ms to ~39ms).

### 2.2 The Three `ModelProvider` Implementations & Account Info (`GetUserStatus`)

| Provider Struct | VA (`v1.5.1`) | Active When | Upstream Wire Protocol | Account / Quota UI (`GetUserStatus` & `GetAuthStatus`) |
| :--- | :--- | :--- | :--- | :--- |
| **`CCPAModelProvider`** | `0x102080aa0` | Default Google OAuth (`jetski-standalone-oauth-token`) | `v1internal` (`daily-cloudcode-pa.googleapis.com/v1internal:*`) | Calls `loadCodeAssist`; populates Google email, Code Assist tier, and cloud quota gauge. |
| **`GeminiModelProvider`** | `0x102081420` | `modelProvider: "gemini"` + `GEMINI_API_KEY` | Standard Gemini API (`/v1beta/models/<id>:streamGenerateContent` on `GOOGLE_GEMINI_BASE_URL`) | Allocates a zeroed 40-byte `UserStatus` struct (`0x102081438`) and returns immediately. `Server.GetAuthStatus` (`0x10275ba30`) reports `AUTH_MODE_GEMINI_API_KEY` (`signedIn = true`, credential label `"Gemini API key"`, no email/tier/quota UI). |
| **`GatewayModelProvider`** | `0x1020814b0` | `gateway.enabled: true` in `~/.gemini/config/config.json` or `AGY_LLM_GATEWAY_URL` | `wireProtocol`: `"genai"` or `"openai"` (`AdminSettings.Validate` @ `0x10154fd68`) | Uses `GatewayAuthClient.GetAuthStatus` (`0x1022cf1d0`, `AUTH_MODE_ENTERPRISE_GATEWAY`). |

---

## 3. Routing `agy` CLI & VS Code Extension Through Local `CLIProxyAPI` (`127.0.0.1:5233`)

### Pattern 1: On-Demand CLI Session (Leaves Default OAuth Untouched)
```zsh
GEMINI_API_KEY="local-cpa-key-123" \
GOOGLE_GEMINI_BASE_URL="http://127.0.0.1:5233" \
agy --settings '{"modelProvider":"gemini"}'
```
- Uses `--settings` (in-memory only), so `~/.gemini/antigravity-cli/settings.json` is never modified and normal `agy` invocations continue using Google OAuth.

- **Carbon (`v1.5.5`)**: this pattern lists the static `geminimodels.Catalog()`, which has no Carbon. Through the `agy` alias (`hub-wrapper.sh`), a `modelProvider: "gemini"` session also gets the Pattern 2 gateway settings: the picker comes from `AGY_LLM_GATEWAY_MODELS`, while requests still go to `GOOGLE_GEMINI_BASE_URL` (verified by pointing `AGY_LLM_GATEWAY_URL` at a dead port), so `cache_relay.py` keeps relaying them. Through `v1.5.6`, Carbon IDs reached CLIProxyAPI as `gemini-4-carbon` + `thinkingLevel` only with `patch_agy.py` Sites #38–#40; `v1.5.7` maps Carbon itself. `AGY_LOCAL_GATEWAY=off` restores the static catalog.
- **Hydrogen (`v1.5.7`)**: that release knows Hydrogen only from Cloud Code, so without `patch_agy.py` Sites #55a–#55p a gateway session treats `gemini-4-hydrogen-*` as a custom model: its raw ID in `/model`, no effort gauge, and `thinkingBudget: 4096` on the wire, which CLIProxyAPI honors, so xhigh thinks like high. With them it is built in: `Gemini 4 Hydrogen` with a low–xhigh gauge and the Context row, sent as `gemini-4-hydrogen` + `thinkingLevel` (`XHIGH` for xhigh; CLIProxyAPI rejects agy's own `EXTRA_HIGH`). `settings.json` `customModels` cannot stand in: their `thinkingLevel` stops at high, and gateway sessions ignore them. `v1.5.8` ships Hydrogen as a built-in that lists and sends the same, so the sites retire there.

### Pattern 2: VS Code Extension via `~/.gemini/bin/agy` Hub Wrapper (`hub-wrapper.sh`)
Because the VS Code extension always spawns `~/.gemini/bin/agy --hub ...` while interactive terminal sessions invoke `~/.local/bin/agy`, installing [`hub-wrapper.sh`](../hub-wrapper.sh) at `~/.gemini/bin/agy` routes **only** `--hub` (VS Code) to `127.0.0.1:5233` (auto-sourcing `CPA_API_KEY` from `~/.gemini/agy-gateway.env`) while keeping `agy --version`, `patch_agy.py`, and CLI sessions untouched. The script is the source of truth; install it with `python3 patch_agy.py --apply`, which writes the repo's path into the copy (a plain `cp` leaves the placeholder, and the copy runs without the cache relay). Under `--hub` it sets:

| Variable | Value | Effect |
| :--- | :--- | :--- |
| `AGY_LLM_GATEWAY_URL` / `_API_KEY` / `_WIRE_PROTOCOL` | `127.0.0.1:5233` / `$CPA_API_KEY` / `genai` | Enables `GatewayModelProvider`; no `daily-cloudcode-pa` calls. |
| `AGY_LLM_GATEWAY_MODELS` | `gemini-4-carbon-{low,medium,high}`, `gemini-4-argon-{low,medium,high}`, `gemini-4-hydrogen-{low,medium,high,xhigh}`, `gemini-3.8-flash-{medium,high}` | Model resolution switches from Tier 3 (gateway discovery, 37 custom models, 5 dropped at the 32-placeholder cap) to **Tier 1 (inline `models.list`)**. |
| `AGY_LLM_GATEWAY_TIER_FLASH_LITE` / `_FLASH` / `_PRO` | `gemini-4-hydrogen-low` / `gemini-4-hydrogen-high` / `gemini-4-carbon-medium` | Background tiers: titles and command safety checks, then subagents. |

Verified 2026-11-05 by calling `GetCascadeModelConfigData` on a throwaway hub: all five resolve as built-in, non-custom configs (`Gemini 4 Argon (Low|Medium|High)` = `M419|M418|M417`, `Gemini 3.8 Flash (Medium|High)` = `M319|M318`).

### 3.1 Effort Grouping & Wire Format
- The Web UI (`main.js`, embedded zip in the binary) groups models into an effort submenu only when `!isCustom`, the label matches `^(.*?)\s*\((low|medium|high|xhigh|max)( thinking)?\)$`, and at least two efforts share a base. Gateway-discovered models are always custom, so they render flat.
- On the wire, the hub sends the **base** model (`gemini-4-argon`) with `generationConfig.thinkingConfig.thinkingLevel` (`LOW`/`MEDIUM`/`HIGH`). `CLIProxyAPI` therefore needs only base IDs; it rejects hyphenated variants such as `gemini-4-argon-low` (`400 unknown provider`), but accepts `gemini-4-argon(low)`.

### 3.2 Context Window Under `--hub`
- Every hub generation records `ContextWindowMetadata.max_context_tokens = 256000` (`gen_metadata` path `.1.9.10.4` in `~/.gemini/antigravity/conversations/*.db`). `patch_agy.py` touches only `cli/*` and does not affect the hub.
- The Web UI ships a context-window submenu, but it is double-gated: options come from the server experiment `context-window-options` (never delivered via gateway), and the `EffortRow` slot read through `Cz().contextWindow` is provided by no bundle in this build.

### Pattern 3: Native `~/.gemini/config/config.json` Gateway / Env Overrides (`admincontrols`)
`admincontrols.loadEffectiveSettings` (`0x101552a50`) merges `/Library/Application Support/Antigravity/admin_settings.json`, `~/.gemini/config/config.json`, and `AGY_LLM_GATEWAY_*` env vars (`ParseEnvOverrides` @ `0x1015507e0`):
- Supported env overrides: `AGY_LLM_GATEWAY_URL`, `AGY_LLM_GATEWAY_WIRE_PROTOCOL` (`"genai"` | `"openai"`), `AGY_LLM_GATEWAY_API_KEY`, `AGY_LLM_GATEWAY_HEADERS`, `AGY_LLM_GATEWAY_MODELS`, `AGY_LLM_GATEWAY_TIER_FLASH_LITE`, `AGY_LLM_GATEWAY_TIER_FLASH`, `AGY_LLM_GATEWAY_TIER_PRO`, `AGY_LLM_GATEWAY_PROXY_URL`.
- Or pass `--cloud_code_endpoint=http://127.0.0.1:5233` in VS Code `"antigravity.serverArgs"` when the upstream proxy exposes `/v1internal:*` endpoints.
