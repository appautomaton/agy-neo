#!/bin/zsh
# Antigravity wrapper (~/.gemini/bin/agy): unified local CLIProxyAPI gateway routing
# and native prompt-cache keepalive policy for both CLI and VS Code (--hub) sessions.

# Never let a background update replace the patched binary. Extension-spawned processes
# do not reliably inherit ~/.zshrc. The updater accepts only the exact string "true".
export AGY_CLI_DISABLE_AUTO_UPDATE=true

agy_bin=$HOME/.local/bin/agy

# Load policy from agy-neo.conf: native keepalive (AGY_CACHE_MAX_TOUCHES) and
# auto-compaction threshold (AGY_CLI_AUTO_COMPACT_OVERRIDE).
() {
  local neo_conf=${AGY_NEO_CONFIG:-$HOME/.gemini/antigravity-cli/agy-neo.conf}
  local CACHE_KEEPALIVE=on CACHE_TTL=5m CACHE_MAX_TOUCHES=4 AUTO_COMPACT_WINDOW=512K
  [[ -r $neo_conf ]] && source $neo_conf 2>/dev/null
  local gate=${AGY_CACHE_KEEPALIVE:-$CACHE_KEEPALIVE}
  if [[ "${gate:l}" == (0|false|off|no) ]]; then
    export AGY_CACHE_MAX_TOUCHES=0
  else
    export AGY_CACHE_MAX_TOUCHES="${AGY_CACHE_MAX_TOUCHES:-$CACHE_MAX_TOUCHES}"
  fi
  if [[ -z "${AGY_CLI_AUTO_COMPACT_OVERRIDE+x}" ]]; then
    local win=${AUTO_COMPACT_WINDOW:-}
    if [[ -n "$win" && "${win:l}" != (0|false|off|no|default) ]]; then
      export AGY_CLI_AUTO_COMPACT_OVERRIDE="$win"
    fi
  fi
}

# Preserve macOS Keychain OAuth when SSH_* variables leak into a Keychain-capable session
# (e.g., a local Aqua tmux server attached over SSH, where update-environment injects
# SSH_CONNECTION into new panes, or an SSH session with an explicitly unlocked login keychain).
# SSH_AUTH_SOCK is intentionally left intact so forwarded SSH agents keep working.
if [[ -n "${SSH_TTY:-}${SSH_CLIENT:-}${SSH_CONNECTION:-}" ]]; then
  if [[ "$(/bin/launchctl managername 2>/dev/null)" == "Aqua" ]] ||
     /usr/bin/security show-keychain-info "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1; then
    unset SSH_TTY SSH_CLIENT SSH_CONNECTION
  fi
fi

# Local gateway settings (CLIProxyAPI). Built-in catalog IDs keep "(Low|Medium|High|XHigh)"
# labels for effort gauges and send base model + thinkingConfig.thinkingLevel on the wire.
# Routing via AGY_LLM_GATEWAY_* keeps sessions on modelapiccpa -> buildGatewayHTTPRequest,
# unifying local gateway sessions with Google's native 4m30s prompt-cache keepalive engine.
use_local_gateway() {
  local gateway_env=$HOME/.gemini/agy-gateway.env
  if [[ -f $gateway_env ]]; then
    source $gateway_env 2>/dev/null
  fi
  export GEMINI_API_KEY="${GEMINI_API_KEY:-${CPA_API_KEY:-}}"
  export GOOGLE_GEMINI_BASE_URL="${GOOGLE_GEMINI_BASE_URL:-http://127.0.0.1:5233}"
  export AGY_LLM_GATEWAY_URL="${AGY_LLM_GATEWAY_URL:-$GOOGLE_GEMINI_BASE_URL}"
  export AGY_LLM_GATEWAY_API_KEY="${AGY_LLM_GATEWAY_API_KEY:-$GEMINI_API_KEY}"
  export AGY_LLM_GATEWAY_WIRE_PROTOCOL="${AGY_LLM_GATEWAY_WIRE_PROTOCOL:-genai}"
  export AGY_LLM_GATEWAY_MODELS="${AGY_LLM_GATEWAY_MODELS:-gemini-4-neon-low,gemini-4-neon-medium,gemini-4-neon-high,gemini-4-neon-xhigh,gemini-4-carbon-low,gemini-4-carbon-medium,gemini-4-carbon-high,gemini-4-argon-low,gemini-4-argon-medium,gemini-4-argon-high,gemini-4-hydrogen-low,gemini-4-hydrogen-medium,gemini-4-hydrogen-high,gemini-4-hydrogen-xhigh,gemini-3.8-flash-medium,gemini-3.8-flash-high}"
  # Background tiers: titles and command safety checks (flash_lite), subagents (flash, pro).
  export AGY_LLM_GATEWAY_TIER_FLASH_LITE="${AGY_LLM_GATEWAY_TIER_FLASH_LITE:-gemini-4-hydrogen-high}"
  export AGY_LLM_GATEWAY_TIER_FLASH="${AGY_LLM_GATEWAY_TIER_FLASH:-gemini-4-neon-xhigh}"
  export AGY_LLM_GATEWAY_TIER_PRO="${AGY_LLM_GATEWAY_TIER_PRO:-gemini-4-carbon-high}"
}

# --hub (VS Code extension), opted-in ACP sessions, and explicit AGY_LOCAL_GATEWAY=on|1 sessions
# run directly on the local gateway through modelapiccpa.
if [[ "$*" == *"--hub"* || ( "${1:-}" == "acp" && "${AGY_ACP_GATEWAY:-0}" == "1" ) || "${AGY_LOCAL_GATEWAY:l}" == (1|true|on|yes) ]]; then
  use_local_gateway
  exec $agy_bin "$@"
fi

# `--settings '{"modelProvider":"gemini"}'` CLI gateway selector: clear modelProvider so agy stays
# on modelapiccpa (preserving native keepalive + AGY_LLM_GATEWAY_MODELS) instead of switching to the
# static geminiapi client. Set AGY_LOCAL_GATEWAY=off to keep raw geminiapi behavior.
gemini_provider_re='"modelProvider"[[:space:]]*:[[:space:]]*"gemini"'
if [[ "$*" =~ $gemini_provider_re && "${AGY_LOCAL_GATEWAY:l}" != (0|false|off|no) ]]; then
  use_local_gateway
  typeset -a rewritten_args=()
  local arg
  for arg in "$@"; do
    if [[ "$arg" =~ $gemini_provider_re ]]; then
      arg="$(printf '%s' "$arg" | sed -E 's/"modelProvider"[[:space:]]*:[[:space:]]*"gemini"/"modelProvider":""/g')"
    fi
    rewritten_args+=("$arg")
  done
  exec $agy_bin "${rewritten_args[@]}"
fi

exec $agy_bin "$@"
