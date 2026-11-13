#!/bin/zsh
# Antigravity Hub wrapper for VS Code extension (google.google-antigravity)
# Routes --hub sessions through local CLIProxyAPI (127.0.0.1:5233) while delegating
# all binary execution to the single patched Mach-O binary at ~/.local/bin/agy.

# Never let a background update replace the patched binary. Extension-spawned processes
# do not reliably inherit ~/.zshrc. The updater accepts only the exact string "true".
export AGY_CLI_DISABLE_AUTO_UPDATE=true

agy_bin=$HOME/.local/bin/agy

# Local gateway settings (CLIProxyAPI). The picker is pinned to built-in catalog IDs: known IDs
# keep their "(Low|Medium|High|XHigh)" labels, so the UI groups them into effort gauges, and on
# the wire agy sends the base model plus thinkingConfig.thinkingLevel, which CLIProxyAPI routes.
# Hydrogen IDs are built in from agy v1.5.8. v1.5.7 knew Hydrogen from Cloud Code alone and needed
# patch_agy.py Sites #55a-#55p, or it sent a custom model capped at a 4096-token thinking budget.
use_local_gateway() {
  local gateway_env=$HOME/.gemini/agy-gateway.env  # CPA_API_KEY, plus an override for any default below
  if [[ -f $gateway_env ]]; then
    source $gateway_env 2>/dev/null
  fi
  export GEMINI_API_KEY="${GEMINI_API_KEY:-$CPA_API_KEY}"
  export GOOGLE_GEMINI_BASE_URL="${GOOGLE_GEMINI_BASE_URL:-http://127.0.0.1:5233}"
  export AGY_LLM_GATEWAY_URL="${AGY_LLM_GATEWAY_URL:-http://127.0.0.1:5233}"
  export AGY_LLM_GATEWAY_API_KEY="${AGY_LLM_GATEWAY_API_KEY:-$GEMINI_API_KEY}"
  export AGY_LLM_GATEWAY_WIRE_PROTOCOL="${AGY_LLM_GATEWAY_WIRE_PROTOCOL:-genai}"
  export AGY_LLM_GATEWAY_MODELS="${AGY_LLM_GATEWAY_MODELS:-gemini-4-carbon-low,gemini-4-carbon-medium,gemini-4-carbon-high,gemini-4-argon-low,gemini-4-argon-medium,gemini-4-argon-high,gemini-4-hydrogen-low,gemini-4-hydrogen-medium,gemini-4-hydrogen-high,gemini-4-hydrogen-xhigh,gemini-3.8-flash-medium,gemini-3.8-flash-high}"
  # Background tiers: titles and command safety checks (flash_lite), subagents (flash, pro).
  export AGY_LLM_GATEWAY_TIER_FLASH_LITE="${AGY_LLM_GATEWAY_TIER_FLASH_LITE:-gemini-4-hydrogen-low}"
  export AGY_LLM_GATEWAY_TIER_FLASH="${AGY_LLM_GATEWAY_TIER_FLASH:-gemini-4-hydrogen-high}"
  export AGY_LLM_GATEWAY_TIER_PRO="${AGY_LLM_GATEWAY_TIER_PRO:-gemini-4-carbon-medium}"
}

# --hub (VS Code extension) and opted-in ACP sessions run entirely on the local gateway.
if [[ "$*" == *"--hub"* || ( "${1:-}" == "acp" && "${AGY_ACP_GATEWAY:-0}" == "1" ) ]]; then
  use_local_gateway
  if [[ "${1:-}" == "acp" ]]; then
    exec $agy_bin "$@"
  fi
  exec $agy_bin --settings='{"modelProvider":"gemini"}' "$@"
fi

# A session started with --settings '{"modelProvider":"gemini"}' would otherwise list the static
# geminimodels.Catalog(), which has no Carbon. The gateway settings replace it with
# AGY_LLM_GATEWAY_MODELS; requests still go to GOOGLE_GEMINI_BASE_URL, so the relay below keeps
# serving them. AGY_LOCAL_GATEWAY=off keeps the static catalog.
gemini_provider_re='"modelProvider"[[:space:]]*:[[:space:]]*"gemini"'
if [[ "$*" =~ $gemini_provider_re && "${AGY_LOCAL_GATEWAY:-}" != off ]]; then
  use_local_gateway
fi

# Interactive and ACP sessions send Cloud Code traffic through a per-process loopback relay
# that keeps an idle session's implicit prompt cache warm (cache_relay.py in this repo). Both read
# CLOUD_CODE_URL. With modelProvider "gemini", GOOGLE_GEMINI_BASE_URL (CPA) is relayed too.
# Print mode, other subcommands, AGY_CACHE_RELAY=off, and any relay failure use direct endpoints.
# patch_agy.py --apply writes the repo's path here when it installs this file; the source keeps
# the placeholder, so a copy installed by hand runs without the relay.
relay_py=@AGY_NEO_REPO@/cache_relay.py
if [[ "${AGY_CACHE_RELAY:-}" != off && -r $relay_py && ( $# -eq 0 || "$1" == -* || "$1" == "acp" ) ]] &&
   (( ! ${argv[(I)(-p|--print|--prompt|--login|--help|-h)(|=*)]} )); then
  # A nested agy inherits its parent's relay as GOOGLE_GEMINI_BASE_URL; chain to the original.
  gemini_upstream=${GOOGLE_GEMINI_BASE_URL:-}
  [[ -n $gemini_upstream && $gemini_upstream == "${AGY_CACHE_RELAY:-}" ]] && gemini_upstream=${AGY_GEMINI_UPSTREAM:-}
  relay_args=(--parent $$)
  [[ -n $gemini_upstream ]] && relay_args+=(--gemini-upstream "$gemini_upstream")
  exec {relay_fd}< <(exec python3 -I $relay_py $relay_args 2>>/tmp/agy_cache_relay.log)
  read -t 3 -u $relay_fd relay_port
  exec {relay_fd}<&-
  if [[ "${relay_port:-}" == <-> ]]; then
    export AGY_CACHE_RELAY="http://127.0.0.1:$relay_port"
    if [[ -n $gemini_upstream ]]; then
      export AGY_GEMINI_UPSTREAM=$gemini_upstream GOOGLE_GEMINI_BASE_URL=$AGY_CACHE_RELAY
    fi
    CLOUD_CODE_URL="$AGY_CACHE_RELAY" exec $agy_bin "$@"
  fi
fi

exec $agy_bin "$@"
