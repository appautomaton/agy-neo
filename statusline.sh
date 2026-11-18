#!/bin/zsh
# Antigravity CLI Pastel Spectrum Powerline Bar (Atomic Per-Metric Color Blocks + Adaptive Dark/Light)
# Design: Semantic Mode×Sandbox Posture + Periodic Model Shorthand + Dynamic Git Worktree Tracking
# Performance: 1x jq process, 0-fork zstat steady-state worktree/theme cache (~13ms render)
emulate -L zsh
setopt PIPE_FAIL NO_UNSET
zmodload zsh/datetime
zmodload -F zsh/stat b:zstat

[[ -z "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" ]] && export LC_CTYPE="en_US.UTF-8"
export LC_NUMERIC=C
local NOW=$EPOCHREALTIME
integer NOW_SEC=${EPOCHSECONDS:-${NOW%.*}}

# ─── 1. Single-Pass jq Extraction (ASCII \x1f Unit Separator) ─────────────────
local SESSION_ID STATE CYCLE_MODE PERM_MODE MODEL_ID MODEL_DISPLAY EFFORT CWD TRANSCRIPT_PATH BRANCH DIRTY SBX_ON USED_PCT TOT_IN TOT_OUT CUR_IN CUR_OUT CACHE_READ EXCEEDS_200K COST_USD SUB_USD QUOTA_PCT SUB_TOT SUB_RUN TASKS ARTIFACTS PENDING_IN CONFIRM_PENDING CACHE_PACKED

jq -r '
  [
    (.session_id // .conversation_id // "default" | tostring),
    (.agent_state // "idle" | tostring),
    (.cycle_mode // .execution_mode // "-" | tostring),
    (.permission_mode // "-" | tostring),
    (.model.id // "-" | tostring),
    (.model.display_name // "-" | tostring),
    (.model.effort // "-" | tostring),
    (([.workspace.current_dir, .cwd, .workspace.project_dir] | map(select(type == "string" and length > 0)) | .[0]) // "" | tostring),
    (.transcript_path // "" | tostring),
    (.vcs.branch // .vcs.client // "" | tostring),
    (if .vcs.dirty == true then "true" else "false" end),
    (if .sandbox.enabled == true then "true" else "false" end),
    (
      ((.context_window.current_usage.input_tokens // 0 | tonumber? // 0) + (.context_window.current_usage.cache_read_input_tokens // 0 | tonumber? // 0)) as $real_in |
      (.context_window.context_window_size // 0 | tonumber? // 0) as $win_sz |
      if ($real_in > 0 and $win_sz > 0) then
        ($real_in * 100.0 / $win_sz)
      else
        (.context_window.used_percentage // 0 | tonumber? // 0)
      end
    ),
    (.context_window.total_input_tokens // 0 | tonumber? // 0),
    (.context_window.total_output_tokens // 0 | tonumber? // 0),
    (.context_window.current_usage.input_tokens // 0 | tonumber? // 0),
    (.context_window.current_usage.output_tokens // 0 | tonumber? // 0),
    (.context_window.current_usage.cache_read_input_tokens // 0 | tonumber? // 0),
    (if .exceeds_200k_tokens == true then "true" else "false" end),
    (if (.cost | type) == "object" then (.cost.total_usd // 0) elif (.cost | type) == "number" then .cost else 0 end | tonumber? // 0),
    (if (.cost | type) == "object" then (.cost.subagent_usd // 0) else 0 end | tonumber? // 0),
    (
      if (.quota | type) == "object" and (.quota | length) > 0 then
        ([.quota | to_entries[] | select(.value.disabled != true and .value.remaining_fraction != null) | .value.remaining_fraction] | if length > 0 then (min * 100 | round) else -1 end)
      else -1 end
    ),
    (if (.subagents | type) == "array" then (.subagents | length) else 0 end),
    (if (.subagents | type) == "array" then ([.subagents[] | select(.status == "running" or .status == "working" or .status == "thinking")] | length) else 0 end),
    (.task_count // 0 | tonumber? // 0),
    (.artifact_count // 0 | tonumber? // 0),
    (.pending_input_count // 0 | tonumber? // 0),
    (if .tool_confirmation_pending == true then "true" else "false" end),
    (.cache_keepalive // 0 | tonumber? // 0)
  ] | map(tostring) | join("\u001f")
' 2>/dev/null | IFS=$'\x1f' read -r \
  SESSION_ID STATE CYCLE_MODE PERM_MODE MODEL_ID MODEL_DISPLAY EFFORT CWD TRANSCRIPT_PATH BRANCH DIRTY SBX_ON \
  USED_PCT TOT_IN TOT_OUT CUR_IN CUR_OUT CACHE_READ EXCEEDS_200K \
  COST_USD SUB_USD QUOTA_PCT \
  SUB_TOT SUB_RUN TASKS ARTIFACTS PENDING_IN CONFIRM_PENDING CACHE_PACKED || exit 0

[[ -z "${SESSION_ID:-}" ]] && exit 0
[[ "$CYCLE_MODE" == "-" ]]    && CYCLE_MODE=""
[[ "$PERM_MODE" == "-" ]]     && PERM_MODE=""
[[ "$MODEL_ID" == "-" ]]      && MODEL_ID=""
[[ "$MODEL_DISPLAY" == "-" ]] && MODEL_DISPLAY=""
[[ "$EFFORT" == "-" ]]        && EFFORT=""

# Upstream StatusLineData omits settings.toolPermission; read it in-process (0 forks).
if [[ -z "$PERM_MODE" ]]; then
  local SETTINGS_FILE="${HOME}/.gemini/antigravity-cli/settings.json"
  if [[ -r "$SETTINGS_FILE" ]]; then
    local _SLINE=""
    while IFS= read -r _SLINE; do
      if [[ "$_SLINE" == *'"toolPermission"'* && "$_SLINE" =~ '"toolPermission"[[:space:]]*:[[:space:]]*"([^"]+)"' ]]; then
        PERM_MODE="${match[1]}"
        break
      fi
    done < "$SETTINGS_FILE"
  fi
fi

# ─── 2. Stateful TPS & Cache TTL Engine ───────────────────────────────────────
local STATE_FILE="/tmp/agy_telemetry_${SESSION_ID//[^a-zA-Z0-9_-]/_}.dat"
local CONV_DB="${HOME}/.gemini/antigravity-cli/conversations/${SESSION_ID}.db"
local PREV_STATE="idle" START_TIME=$NOW BASE_OUT=$TOT_OUT LAST_TPS="--" STEP_LAT="--" LAST_DELTA=0 CACHE_TS=0

if [[ -f "$STATE_FILE" ]]; then
  local _SL_TAIL=""
  read -r PREV_STATE START_TIME BASE_OUT LAST_TPS STEP_LAT LAST_DELTA _SL_TAIL < "$STATE_FILE" 2>/dev/null || true
  CACHE_TS="${_SL_TAIL##* }"
  [[ "$START_TIME" == <->* ]]      || START_TIME=$NOW
  [[ "$BASE_OUT" == <-> ]]         || BASE_OUT=$TOT_OUT
  [[ "$LAST_DELTA" == <-> ]]       || LAST_DELTA=0
  [[ "${CACHE_TS:-}" == <-> ]]     || CACHE_TS=0
else
  # Avoid counting historical session tokens as a single-step delta on cold start
  BASE_OUT=$TOT_OUT
fi

if (( TOT_OUT < BASE_OUT )); then
  BASE_OUT=$TOT_OUT
elif [[ "$PREV_STATE" == "idle" && "$STATE" != "idle" ]]; then
  START_TIME=$NOW
  BASE_OUT=$TOT_OUT
elif [[ "$PREV_STATE" == "idle" && "$STATE" == "idle" ]] && (( BASE_OUT == 0 && TOT_OUT > 0 )); then
  BASE_OUT=$TOT_OUT
fi

integer DELTA_OUT=$(( TOT_OUT - BASE_OUT ))
if (( DELTA_OUT > 0 )); then
  # Clamp multi-step / resumed jumps to latest step's CUR_OUT when available
  if (( CUR_OUT > 0 && DELTA_OUT > CUR_OUT && PREV_STATE == "idle" )); then
    DELTA_OUT=$CUR_OUT
  fi
  float DT=$(( NOW - START_TIME ))
  (( DT < 0.05 )) && DT=0.05
  float TPS=$(( DELTA_OUT / DT ))
  if (( TPS >= 100 )); then
    printf -v LAST_TPS "%.0f" $TPS
  else
    printf -v LAST_TPS "%.1f" $TPS
  fi
  printf -v STEP_LAT "%.1fs" $DT
  LAST_DELTA=$DELTA_OUT
  START_TIME=$NOW
  BASE_OUT=$TOT_OUT
  CACHE_TS=$NOW_SEC
elif [[ "$CONFIRM_PENDING" == "true" ]]; then
  # Pause step timer while waiting on user tool confirmation
  START_TIME=$NOW
elif [[ "$STATE" != "idle" ]]; then
  # Keep cache TTL anchored while streaming/working; countdown starts once idle
  CACHE_TS=$NOW_SEC
fi

# Initialize CACHE_TS once on cold start of an existing conversation (0 forks)
if (( CACHE_TS == 0 && TOT_OUT > 0 )); then
  if [[ -r "$CONV_DB" ]]; then
    local -a DB_MTIME=()
    if zstat -A DB_MTIME +mtime "$CONV_DB" 2>/dev/null && [[ "${DB_MTIME[1]:-}" == <-> ]]; then
      CACHE_TS=${DB_MTIME[1]}
    fi
  fi
  (( CACHE_TS == 0 )) && CACHE_TS=$NOW_SEC
fi

# Native modelapiccpa.(*keepAlives) in-process telemetry packed into 52-bit StatusLineData.CacheKeepalive:
# bits 0..33 = refreshedAt Unix seconds, bits 34..41 = touches sent, bits 42..49 = pings left,
# bits 50..51 = state (1=live, 2=exhausted after final touch, 3=failed/cold).
# Excludes non-main subagent turns, so long tool or subagent runs count down truthfully from prefill.
integer KA_PACKED=0 KA_STATE=0 KA_LEFT=0 KA_TOUCHES=0 KA_TS=0
[[ "${CACHE_PACKED:-}" == <-> ]] && KA_PACKED=$CACHE_PACKED
if (( KA_PACKED > 0 )); then
  KA_TS=$(( KA_PACKED & 0x3ffffffff ))
  KA_TOUCHES=$(( (KA_PACKED >> 34) & 0xff ))
  KA_LEFT=$(( (KA_PACKED >> 42) & 0xff ))
  KA_STATE=$(( (KA_PACKED >> 50) & 0x3 ))
  (( KA_TS > 0 )) && CACHE_TS=$KA_TS
fi

print -r -- "$STATE $START_TIME $BASE_OUT $LAST_TPS $STEP_LAT $LAST_DELTA $CACHE_TS" >| "$STATE_FILE" 2>/dev/null || true

# ─── 3. Adaptive Dark/Light Mode Detection (5s Cache TTL) ─────────────────────
local THEME_MODE="${AGY_THEME:-}"
if [[ -z "$THEME_MODE" && -n "${COLORFGBG:-}" ]]; then
  local BG_CODE="${COLORFGBG##*;}"
  if [[ "$BG_CODE" == <-> ]] && (( BG_CODE >= 7 )); then
    THEME_MODE="light"
  else
    THEME_MODE="dark"
  fi
fi

if [[ -z "$THEME_MODE" ]]; then
  local THEME_CACHE="/tmp/agy_theme_mode.dat"
  local CACHED_TS=0 CACHED_MODE=""
  if [[ -f "$THEME_CACHE" ]]; then
    read -r CACHED_TS CACHED_MODE < "$THEME_CACHE" 2>/dev/null || true
  fi
  if [[ "$CACHED_TS" == <-> ]] && (( NOW_SEC - CACHED_TS < 5 )) && [[ -n "$CACHED_MODE" ]]; then
    THEME_MODE="$CACHED_MODE"
  else
    if /usr/bin/defaults read -g AppleInterfaceStyle >/dev/null 2>&1; then
      THEME_MODE="dark"
    else
      THEME_MODE="light"
    fi
    print -r -- "$NOW_SEC $THEME_MODE" >| "$THEME_CACHE" 2>/dev/null || true
  fi
fi

# ─── 4. 10-Shade Adaptive Pastel Spectrum & Nerd Font v3 Glyphs ───────────────
local P_INK P_MAUVE P_LAVENDER P_SAPPHIRE P_SKY P_TEAL P_MINT P_YELLOW P_PEACH P_PINK P_FLAMINGO P_ROSE
if [[ "$THEME_MODE" == "light" ]]; then
  # Light Mode: Sunlit Watercolor Sorbet Spectrum (richer pastel saturation for white/cream terminals)
  P_INK="24;25;38"          # #181926 Deep Espresso Ink
  P_MAUVE="196;155;248"     # #C49BF8 Pastel Lilac
  P_LAVENDER="150;172;255"  # #96ACFF Pastel Periwinkle
  P_SAPPHIRE="108;192;242"  # #6CC0F2 Pastel Sapphire
  P_SKY="116;212;238"       # #74D4EE Pastel Sky
  P_TEAL="108;218;198"      # #6CDAC6 Pastel Aqua Teal
  P_MINT="132;222;150"      # #84DE96 Pastel Matcha Mint
  P_YELLOW="246;214;132"    # #F6D684 Pastel Lemon Butter
  P_PEACH="250;174;122"     # #FAAE7A Pastel Apricot Peach
  P_PINK="244;158;206"      # #F49ECE Pastel Blush Pink
  P_FLAMINGO="244;166;178"  # #F4A6B2 Pastel Flamingo
  P_ROSE="240;118;142"      # #F0768E Pastel Coral Rose
else
  # Dark Mode: Catppuccin Mocha Luminous Pastel Spectrum
  P_INK="17;17;27"          # #11111B Deep Crust Ink
  P_MAUVE="203;166;247"     # #CBA6F7 Pastel Mauve
  P_LAVENDER="180;190;254"  # #B4BEFE Pastel Lavender
  P_SAPPHIRE="116;199;236"  # #74C7EC Pastel Sapphire
  P_SKY="137;220;235"       # #89DCEB Pastel Sky
  P_TEAL="148;226;213"      # #94E2D5 Pastel Teal
  P_MINT="166;227;161"      # #A6E3A1 Pastel Mint
  P_YELLOW="249;226;175"    # #F9E2AF Pastel Buttercream
  P_PEACH="250;179;135"     # #FAB387 Pastel Peach
  P_PINK="245;194;231"      # #F5C2E7 Pastel Pink
  P_FLAMINGO="242;205;205"  # #F2CDCD Pastel Flamingo
  P_ROSE="243;139;168"      # #F38BA8 Pastel Rose
fi

local R=$'\033[0m' B=$'\033[1m' NB=$'\033[22m'
local FG_INK=$'\033[38;2;'"${P_INK}m"

# Nerd Font v3 Powerline & BMP Glyphs (Zero Emojis)
local PL_RIGHT=$'\ue0b0'      # nf-pl-left_hard_divider ()
local NF_ALERT=$'\uf071'      # nf-fa-warning (Confirmation pending)
local NF_COMPASS=$'\uf14e'    # nf-fa-compass (Plan: read-only)
local NF_BAN=$'\uf05e'        # nf-fa-ban (Strict: ask on every tool)
local NF_ASK=$'\uf059'        # nf-fa-question_circle (Default request-review)
local NF_EDIT=$'\uf040'       # nf-fa-pencil (Accept-edits)
local NF_AUTO=$'\uf04b'       # nf-fa-play (Auto / proceed-in-sandbox)
local NF_TURBO=$'\uf04e'      # nf-fa-forward (Always-proceed)
local NF_FORK=$'\uf126'       # nf-fa-code_fork (Best-of-N)
local NF_BRANCH=$'\ue0a0'     # nf-pl-branch
local NF_WORKTREE=$'\uf1bb'   # nf-fa-tree (Linked Git worktree)
local NF_BOLT=$'\uf0e7'       # nf-fa-bolt (TPS)
local NF_CLOCK=$'\uf017'      # nf-fa-clock_o (Cache TTL)
local NF_CHIP=$'\uf2db'       # nf-fa-microchip (Context window)
local NF_DB=$'\uf1c0'         # nf-fa-database (Prompt cache)
local NF_SUB=$'\uf0e8'        # nf-fa-sitemap (Subagents)
local NF_GEAR=$'\uf013'       # nf-fa-gear (Background tasks)
local NF_FILE=$'\uf1c9'       # nf-fa-file_code_o (Artifacts)
local NF_INBOX=$'\uf01c'      # nf-fa-inbox (Queued inputs)

local -a SEG_BG=()
local -a SEG_TXT=()

# ─── 5. Atomic Block 1: Semantic Posture (Mode Glyph × Sandbox/Approval Color)
# Shape encodes active mode (updates on every Shift+Tab); color encodes execution boundary:
#   Sky = read-only plan | Mauve = human-gated host | Sapphire/Teal = sandboxed
#   Mint = auto-edits (commands gated/sandboxed) | Peach = unsandboxed host auto-execution
if [[ "$CONFIRM_PENDING" == "true" ]]; then
  SEG_BG+=("$P_ROSE")
  SEG_TXT+=("${B}${NF_ALERT}${NB}")
fi

local MODE_GLYPH="$NF_ASK"
local MODE_BG="$P_MAUVE"
local CM="${CYCLE_MODE:l}" PM="${PERM_MODE:l}"

if [[ "$CM" == *plan* ]]; then
  MODE_GLYPH="$NF_COMPASS"
  MODE_BG="$P_SKY"
elif [[ "$PM" == strict ]]; then
  MODE_GLYPH="$NF_BAN"
  MODE_BG="$P_MAUVE"
elif [[ "$CM" == bestn ]]; then
  MODE_GLYPH="$NF_FORK"
  [[ "$SBX_ON" == "true" ]] && MODE_BG="$P_TEAL" || MODE_BG="$P_PEACH"
elif [[ "$CM" == *accept-edits* ]]; then
  MODE_GLYPH="$NF_EDIT"
  [[ "$SBX_ON" == "true" ]] && MODE_BG="$P_MINT" || MODE_BG="$P_PEACH"
elif [[ "$CM" == *auto* ]]; then
  MODE_GLYPH="$NF_AUTO"
  [[ "$SBX_ON" == "true" ]] && MODE_BG="$P_TEAL" || MODE_BG="$P_PEACH"
elif [[ "$PM" == always-proceed ]]; then
  MODE_GLYPH="$NF_TURBO"
  [[ "$SBX_ON" == "true" ]] && MODE_BG="$P_TEAL" || MODE_BG="$P_PEACH"
elif [[ "$PM" == proceed-in-sandbox ]]; then
  MODE_GLYPH="$NF_AUTO"
  [[ "$SBX_ON" == "true" ]] && MODE_BG="$P_TEAL" || MODE_BG="$P_MAUVE"
else
  MODE_GLYPH="$NF_ASK"
  [[ "$SBX_ON" == "true" ]] && MODE_BG="$P_SAPPHIRE" || MODE_BG="$P_MAUVE"
fi
SEG_BG+=("$MODE_BG")
SEG_TXT+=("$MODE_GLYPH")

# ─── 6. Atomic Block 2: Selected Model + Thinking Effort (Pastel Lavender) ────
# Periodic-table shorthand for Gemini 4 families: Carbon -> C, Argon -> Ar, Hydrogen -> H,
# paired with low | med | high | xhigh (e.g. C-med, Ar-high, H-xhigh).
local MODEL_PROBE="${MODEL_ID:l} ${MODEL_DISPLAY:l}"
local MODEL_ABBR=""
case "$MODEL_PROBE" in
  *carbon*)   MODEL_ABBR="C" ;;
  *argon*)    MODEL_ABBR="Ar" ;;
  *hydrogen*) MODEL_ABBR="H" ;;
  *)
    local RAW_M="${MODEL_ID:-${MODEL_DISPLAY:-Model}}"
    RAW_M="${${RAW_M%% · *}%% \(*\)}"
    RAW_M="${${RAW_M:l}// /-}"
    RAW_M="${RAW_M#models/}"
    RAW_M="${RAW_M#gemini-}"
    if [[ "$RAW_M" =~ '^(.*)-(xhigh|high|medium|med|low)$' ]]; then
      RAW_M="${match[1]}"
    fi
    MODEL_ABBR="${RAW_M:-model}"
    ;;
esac

local EFF_RAW="${EFFORT:l}"
if [[ -z "$EFF_RAW" && "${MODEL_DISPLAY:l}" =~ '\((xhigh|high|medium|med|low)\)' ]]; then
  EFF_RAW="${match[1]}"
elif [[ -z "$EFF_RAW" && "${MODEL_ID:l}" =~ '-(xhigh|high|medium|med|low)$' ]]; then
  EFF_RAW="${match[1]}"
fi

local EFF_ABBR=""
case "$EFF_RAW" in
  xhigh)      EFF_ABBR="xhigh" ;;
  high)       EFF_ABBR="high" ;;
  medium|med) EFF_ABBR="med" ;;
  low)        EFF_ABBR="low" ;;
esac

local MODEL_LABEL="$MODEL_ABBR"
[[ -n "$EFF_ABBR" ]] && MODEL_LABEL+="-${EFF_ABBR}"
SEG_BG+=("$P_LAVENDER")
SEG_TXT+=("${B}${MODEL_LABEL}${NB}")

# ─── 8. Optional Block: VCS Branch & Dynamic Worktree Tracking ────────────────
# Upstream agy's store.detectVCSOnDisk (0x102ec4c20) only sets .vcs.type="git"
# and pins .cwd to the startup directory. Resolve HEAD & linked worktrees in-process
# (0 forks in steady state), and follow active linked worktrees via transcript_path
# whenever its (mtime, size) advances.
local BASE_CWD="${CWD:-}"
local _GIT_ROOT="" _GIT_HEAD="" _GIT_COMMON="" _GIT_IS_WT="false"

_agy_resolve_git() {
  _GIT_ROOT="" _GIT_HEAD="" _GIT_COMMON="" _GIT_IS_WT="false"
  local S="${1:-}"
  [[ -z "$S" ]] && return 1
  [[ "$S" == "~" ]] && S="$HOME"
  [[ "$S" == "~/"* ]] && S="${HOME}/${S#~/}"
  S="${S/#\$HOME\//${HOME}/}"
  S="${S/#\$\{HOME\}\//${HOME}/}"
  [[ "$S" == *'$'* || "$S" == *'`'* || "$S" == *'*'* || "$S" == *'?'* ]] && return 1
  [[ "$S" != /* && -n "$BASE_CWD" ]] && S="${BASE_CWD}/${S}"
  while [[ -n "$S" && "$S" != "/" && ! -d "$S" ]]; do
    S="${S:h}"
  done
  [[ -d "$S" ]] || return 1
  S="${S:A}"
  local META="" GD="" CD_REL=""
  while [[ -n "$S" && "$S" != "/" ]]; do
    if [[ -d "$S/.git" ]]; then
      _GIT_ROOT="$S"
      _GIT_HEAD="$S/.git/HEAD"
      _GIT_COMMON="${S}/.git"
      _GIT_COMMON="${_GIT_COMMON:A}"
      _GIT_IS_WT="false"
      return 0
    elif [[ -f "$S/.git" ]]; then
      IFS= read -r META < "$S/.git" 2>/dev/null || true
      META="${META%$'\r'}"
      if [[ "$META" == "gitdir: "* ]]; then
        GD="${META#gitdir: }"
        [[ "$GD" != /* ]] && GD="$S/$GD"
        [[ -d "$GD" ]] || return 1
        GD="${GD:A}"
        _GIT_ROOT="$S"
        _GIT_HEAD="$GD/HEAD"
        if [[ -r "$GD/commondir" ]]; then
          IFS= read -r CD_REL < "$GD/commondir" 2>/dev/null || true
          CD_REL="${CD_REL%$'\r'}"
          if [[ -n "$CD_REL" ]]; then
            [[ "$CD_REL" != /* ]] && _GIT_COMMON="$GD/$CD_REL" || _GIT_COMMON="$CD_REL"
            _GIT_COMMON="${_GIT_COMMON:A}"
          fi
        fi
        if [[ -z "$_GIT_COMMON" ]]; then
          if [[ "$GD" == *"/worktrees/"* ]]; then
            _GIT_COMMON="${GD%/worktrees/*}"
            _GIT_COMMON="${_GIT_COMMON:A}"
          else
            _GIT_COMMON="$GD"
          fi
        fi
        [[ "$GD" == *"/worktrees/"* || "$_GIT_COMMON" != "$GD" ]] && _GIT_IS_WT="true"
        return 0
      fi
      return 1
    fi
    S="${S:h}"
  done
  return 1
}

local BASE_ROOT="" BASE_HEAD="" BASE_COMMON="" BASE_IS_WT="false"
if [[ -n "$BASE_CWD" && -d "$BASE_CWD" ]] && _agy_resolve_git "$BASE_CWD"; then
  BASE_ROOT="$_GIT_ROOT"
  BASE_HEAD="$_GIT_HEAD"
  BASE_COMMON="$_GIT_COMMON"
  BASE_IS_WT="$_GIT_IS_WT"
fi

local ACTIVE_ROOT="$BASE_ROOT" ACTIVE_HEAD="$BASE_HEAD" IS_WORKTREE="$BASE_IS_WT"
integer TRANSCRIPT_UPDATED=0
[[ -z "${TRANSCRIPT_PATH:-}" ]] && TRANSCRIPT_PATH="${HOME}/.gemini/antigravity-cli/brain/${SESSION_ID}/.system_generated/logs/transcript.jsonl"

if [[ -r "$TRANSCRIPT_PATH" ]]; then
  local -A T_STAT=()
  if zstat -H T_STAT "$TRANSCRIPT_PATH" 2>/dev/null && [[ "${T_STAT[mtime]:-}" == <-> && "${T_STAT[size]:-}" == <-> ]]; then
    local WT_CACHE="/tmp/agy_wt_${SESSION_ID//[^a-zA-Z0-9_-]/_}.dat"
    local WT_MTIME=0 WT_SIZE=0 WT_CACHED_DIR=""
    if [[ -f "$WT_CACHE" ]]; then
      IFS=$'\t' read -r WT_MTIME WT_SIZE WT_CACHED_DIR < "$WT_CACHE" 2>/dev/null || true
    fi

    local SCAN_ACTIVE="$BASE_ROOT"
    if [[ -n "$WT_CACHED_DIR" ]] && _agy_resolve_git "$WT_CACHED_DIR"; then
      if [[ -z "$BASE_COMMON" || "$_GIT_COMMON" == "$BASE_COMMON" ]]; then
        SCAN_ACTIVE="$_GIT_ROOT"
      fi
    fi

    if [[ "$WT_MTIME" != "${T_STAT[mtime]}" || "$WT_SIZE" != "${T_STAT[size]}" ]]; then
      TRANSCRIPT_UPDATED=1
      integer TAIL_BYTES=65536
      [[ "$WT_SIZE" == "0" || "$WT_SIZE" != <-> ]] && TAIL_BYTES=131072
      local EV_KIND="" EV_PAYLOAD=""
      while IFS=$'\t' read -r EV_KIND EV_PAYLOAD; do
        [[ -z "$EV_KIND" || -z "$EV_PAYLOAD" ]] && continue
        if [[ "$EV_KIND" == "CMD" ]]; then
          local -a CMD_PATHS=("${(@ps:\x1f:)EV_PAYLOAD}")
          local CP="" CMD_LAST="" CMD_WT=""
          for CP in "${CMD_PATHS[@]}"; do
            if _agy_resolve_git "$CP" && [[ -z "$BASE_COMMON" || "$_GIT_COMMON" == "$BASE_COMMON" ]]; then
              CMD_LAST="$_GIT_ROOT"
              [[ "$_GIT_IS_WT" == "true" ]] && CMD_WT="$_GIT_ROOT"
            fi
          done
          if [[ -n "$CMD_WT" ]]; then
            SCAN_ACTIVE="$CMD_WT"
          elif [[ -n "$CMD_LAST" ]]; then
            SCAN_ACTIVE="$CMD_LAST"
          fi
        else
          if _agy_resolve_git "$EV_PAYLOAD" && [[ -z "$BASE_COMMON" || "$_GIT_COMMON" == "$BASE_COMMON" ]]; then
            if [[ "$EV_KIND" == "STRONG" || "$_GIT_IS_WT" == "true" || -z "$SCAN_ACTIVE" ]]; then
              SCAN_ACTIVE="$_GIT_ROOT"
            fi
          fi
        fi
      done < <(
        /usr/bin/tail -c "$TAIL_BYTES" "$TRANSCRIPT_PATH" 2>/dev/null | jq -Rr '
          def unstr: if type == "string" then (fromjson? // .) else empty end;
          def unq:
            if startswith("\"") and endswith("\"") then .[1:-1]
            elif startswith("\u0027") and endswith("\u0027") then .[1:-1]
            else . end;
          def join_rel($base; $p):
            if ($base != null and ($p | startswith("/") | not) and ($p | startswith("~") | not) and ($p | startswith("$") | not)) then
              $base + "/" + $p
            else $p end;
          def wt_add_path:
            [ scan("(?:\"[^\"]+\"|\u0027[^\u0027]+\u0027|\\S+)") | unq ] as $toks |
            reduce range(0; $toks | length) as $i (
              {skip: false, found: null};
              if .found != null then .
              elif .skip then .skip = false
              else
                ($toks[$i]) as $t |
                if ($t == "-b" or $t == "-B" or $t == "--reason") then .skip = true
                elif ($t | startswith("-")) then .
                else .found = $t
                end
              end
            ) | .found;
          def parse_cmd($raw):
            (if ($raw | contains("<<")) then ($raw | split("\n")[0]) else $raw end) as $head |
            ($head | gsub("python3?\\s+-c\\s+(?:\u0027[^\u0027]*\u0027|\"[^\"]*\")"; "python_inline")) as $clean |
            [ $clean | splits("(?:&&|\\|\\||;|\\n)") | gsub("^\\s+|\\s+$"; "") | select(length > 0) ] as $clauses |
            (reduce $clauses[] as $cl (
              {cwd: null, out: []};
              if ($cl | test("^(?:\\(\\s*)?(?:cd|pushd)\\s+")) then
                (($cl | capture("^(?:\\(\\s*)?(?:cd|pushd)\\s+(?<p>\"[^\"]+\"|\u0027[^\u0027]+\u0027|[^\\s;&|)\"\u0027]+)") | .p) // null) as $p |
                if $p != null and ($p | unq) != "-" then
                  join_rel(.cwd; ($p | unq)) as $np |
                  .cwd = $np | .out += [$np]
                else . end
              elif ($cl | test("^(?:\\(\\s*)?(?:/usr/bin/)?(?:git|gh)\\s+")) then
                ($cl | sub("^(?:\\(\\s*)?(?:/usr/bin/)?(?<bin>git|gh)\\s+"; "")) as $g |
                (if ($g | test("^-C\\s+")) then
                  (($g | capture("^-C\\s+(?<c>\"[^\"]+\"|\u0027[^\u0027]+\u0027|\\S+)\\s+(?<rest>.*)$")) // {c: null, rest: $g})
                else {c: null, rest: $g} end) as $parsed |
                ($parsed.c | if . != null then join_rel(.cwd; unq) else null end) as $cdir |
                ($parsed.rest // "") as $rest |
                if ($rest | test("^(?:worktree|wt)\\s+add\\b")) then
                  ($rest | sub("^(?:worktree|wt)\\s+add\\s*"; "") | wt_add_path) as $wtp |
                  if $wtp != null then
                    .out += [join_rel(($cdir // .cwd); $wtp)]
                  else . end
                elif $cdir != null then
                  .out += [$cdir]
                elif (.cwd == null and ($cl | test("^(?:\\(\\s*)?(?:/usr/bin/)?git\\s+")) and ($rest | test("^(?:status|diff|log|show|add|commit|merge|rebase|checkout|switch|pull|push|reset|stash|cherry-pick|restore|clean|rm|mv|tag)\\b"))) then
                  .out += ["."]
                else . end
              else . end
            ) | .out) as $cands |
            if ($cands | length) > 0 then "CMD\t" + ($cands | join("\u001f")) else empty end;

          fromjson? | select((.tool_calls | type) == "array") |
          .tool_calls[] | .name as $n | (.args // {}) as $a |
          if ($n == "run_command") then
            ($a.CommandLine | unstr) as $cmd |
            if ($cmd | type) == "string" then parse_cmd($cmd) else empty end
          elif ($n == "edit_file" or $n == "write_file" or $n == "replace_file_content" or $n == "write_to_file" or $n == "run_workflow") then
            (($a.Path // $a.TargetFile // $a.Cwd) | unstr) as $p |
            if ($p | type) == "string" and ($p | length) > 0 then "STRONG\t" + $p else empty end
          else
            (($a.Path // $a.TargetFile // $a.AbsolutePath // $a.SearchPath // $a.SearchDirectory // $a.DirectoryPath) | unstr) as $p |
            if ($p | type) == "string" and ($p | length) > 0 then "SOFT\t" + $p else empty end
          end
        ' 2>/dev/null
      )
      print -r -- "${T_STAT[mtime]}"$'\t'"${T_STAT[size]}"$'\t'"${SCAN_ACTIVE}" >| "$WT_CACHE" 2>/dev/null || true
    fi

    if [[ -n "$SCAN_ACTIVE" ]] && _agy_resolve_git "$SCAN_ACTIVE"; then
      ACTIVE_ROOT="$_GIT_ROOT"
      ACTIVE_HEAD="$_GIT_HEAD"
      IS_WORKTREE="$_GIT_IS_WT"
    fi
  fi
fi

local VCS_DIR="${ACTIVE_ROOT:-${BASE_CWD}}"
local HEAD_FILE="$ACTIVE_HEAD"
if [[ -n "$ACTIVE_ROOT" && "$ACTIVE_ROOT" != "$BASE_ROOT" ]]; then
  BRANCH=""
  DIRTY="false"
fi

if [[ -n "$VCS_DIR" && -d "$VCS_DIR" ]]; then
  if [[ -z "$BRANCH" && -n "$HEAD_FILE" && -r "$HEAD_FILE" ]]; then
    local HEAD_CONTENT=""
    read -r HEAD_CONTENT < "$HEAD_FILE" 2>/dev/null || true
    if [[ "$HEAD_CONTENT" == "ref: refs/heads/"* ]]; then
      BRANCH="${HEAD_CONTENT#ref: refs/heads/}"
    elif [[ -n "$HEAD_CONTENT" ]]; then
      BRANCH="${HEAD_CONTENT[1,7]}"
    fi
  fi
  if [[ -n "$BRANCH" && "$DIRTY" != "true" ]]; then
    local VCS_CACHE="/tmp/agy_vcs_${SESSION_ID//[^a-zA-Z0-9_-]/_}.dat"
    local VCS_TS=0 VCS_CWD="" VCS_DIRTY="false"
    if [[ -f "$VCS_CACHE" ]]; then
      IFS=$'\t' read -r VCS_TS VCS_CWD VCS_DIRTY < "$VCS_CACHE" 2>/dev/null || true
    fi
    if (( ! TRANSCRIPT_UPDATED && DELTA_OUT == 0 )) && [[ "$VCS_TS" == <-> ]] && (( NOW_SEC - VCS_TS < 2 )) && [[ "$VCS_CWD" == "$VCS_DIR" ]]; then
      DIRTY="$VCS_DIRTY"
    else
      if [[ -n "$(/usr/bin/git -C "$VCS_DIR" --no-optional-locks status --porcelain --ignore-submodules=dirty 2>/dev/null)" ]]; then
        DIRTY="true"
      else
        DIRTY="false"
      fi
      print -r -- "${NOW_SEC}"$'\t'"${VCS_DIR}"$'\t'"${DIRTY}" >| "$VCS_CACHE" 2>/dev/null || true
    fi
  fi
fi

if [[ -n "$BRANCH" ]]; then
  local BR_SHORT="$BRANCH"
  (( ${#BR_SHORT} > 16 )) && BR_SHORT="${BR_SHORT[1,15]}…"
  local VCS_ICON="$NF_BRANCH"
  [[ "$IS_WORKTREE" == "true" ]] && VCS_ICON="${NF_WORKTREE}${NF_BRANCH}"
  if [[ "$DIRTY" == "true" ]]; then
    SEG_BG+=("$P_ROSE")
    SEG_TXT+=("${B}${VCS_ICON}${BR_SHORT}*${NB}")
  else
    SEG_BG+=("$P_SKY")
    SEG_TXT+=("${VCS_ICON}${BR_SHORT}")
  fi
fi

# ─── 9. Atomic Block 4: TPS Velocity (Pastel Teal) ────────────────────────────
SEG_BG+=("$P_TEAL")
if [[ "$LAST_TPS" != "--" ]]; then
  SEG_TXT+=("${B}${NF_BOLT} ${LAST_TPS}/s${NB}")
else
  SEG_TXT+=("${NF_BOLT} --")
fi

# ─── 10. Atomic Block 5: Context Window % (Pastel Buttercream / Peach / Rose) ─
local CTX_BG="$P_YELLOW"
if [[ "$EXCEEDS_200K" == "true" ]] || (( USED_PCT >= 80 )); then
  CTX_BG="$P_ROSE"
elif (( USED_PCT >= 50 )); then
  CTX_BG="$P_PEACH"
fi

local PCT_FMT
if (( USED_PCT >= 10 )); then
  printf -v PCT_FMT "%.0f%%" $USED_PCT
else
  printf -v PCT_FMT "%.1f%%" $USED_PCT
fi
[[ "$EXCEEDS_200K" == "true" ]] && PCT_FMT+="!200k"
SEG_BG+=("$CTX_BG")
SEG_TXT+=("${NF_CHIP} ${B}${PCT_FMT}${NB}")

# ─── 11. Atomic Block 6: Prompt Cache Hit % (Pastel Peach) ────────────────────
integer TOT_PROMPT=$(( CUR_IN + CACHE_READ ))
integer CACHE_PCT=$(( TOT_PROMPT > 0 ? (CACHE_READ * 100 / TOT_PROMPT) : 0 ))
SEG_BG+=("$P_PEACH")
SEG_TXT+=("${NF_DB} ${B}${CACHE_PCT}%${NB}")

# ─── 12. Atomic Block 7: Implicit Cache TTL Countdown & Keepalive Policy ──────
# Policy loads live from ~/.gemini/antigravity-cli/agy-neo.conf (with AGY_CACHE_* env overrides).
# Empirical agy/Gemini implicit cache cliff is 5.0 min (300s); default touch fires at 4m30s (270s).
parse_duration_sec() {
  local raw="${${1:-}:l}" fallback="${2:-0}"
  raw="${raw//[[:space:]]/}"
  if [[ "$raw" == <-> ]]; then
    REPLY=$raw
  elif [[ "$raw" == <->s ]]; then
    REPLY=${raw%s}
  elif [[ "$raw" == <->(m|min) ]]; then
    REPLY=$(( ${raw%%(m|min)} * 60 ))
  elif [[ "$raw" == <->.<->(m|min) ]]; then
    local num="${raw%%(m|min)}"
    integer sec=$(( num * 60.0 + 0.5 ))
    REPLY=$sec
  elif [[ "$raw" == <->(m|min)<->(s|) ]]; then
    local mins="${raw%%(m|min)*}" rest="${raw#*(m|min)}"
    rest="${rest%s}"
    REPLY=$(( mins * 60 + rest ))
  else
    REPLY=$fallback
  fi
}

local NEO_CONF="${AGY_NEO_CONFIG:-${HOME}/.gemini/antigravity-cli/agy-neo.conf}"
local CACHE_KEEPALIVE="on" CACHE_TTL="5m" CACHE_MAX_TOUCHES="4"
[[ -r "$NEO_CONF" ]] && source "$NEO_CONF" 2>/dev/null || true

local KEEPALIVE_RAW="${AGY_CACHE_KEEPALIVE:-$CACHE_KEEPALIVE}"
integer KEEPALIVE_ON=1
[[ "${KEEPALIVE_RAW:l}" == (0|false|off|no) ]] && KEEPALIVE_ON=0
[[ "${AGY_CACHE_MAX_TOUCHES:-$CACHE_MAX_TOUCHES}" == "0" ]] && KEEPALIVE_ON=0

integer REPLY=0
parse_duration_sec "${AGY_CACHE_TTL:-$CACHE_TTL}" 300
integer CACHE_TTL_SEC=$REPLY
(( CACHE_TTL_SEC < 30 )) && CACHE_TTL_SEC=30

if (( CACHE_TS > 0 )); then
  integer CACHE_ELAPSED=$(( NOW_SEC - CACHE_TS ))
  integer CACHE_REM=$(( CACHE_TTL_SEC - CACHE_ELAPSED ))
  # Keepalive marker: ↻ while armed, ↻n after n touches, ✗ if a touch missed cache or errored.
  local KEEP_MARK=""
  if (( KEEPALIVE_ON && KA_STATE > 0 )); then
    if (( KA_STATE == 3 )); then
      KEEP_MARK=" ✗"
    elif (( KA_STATE == 1 || (KA_STATE == 2 && KA_TOUCHES > 0) )); then
      KEEP_MARK=" ↻"
      (( KA_TOUCHES > 0 )) && KEEP_MARK+="$KA_TOUCHES"
    fi
  fi
  if (( CACHE_REM > 0 )); then
    float CACHE_MIN=$(( CACHE_REM / 60.0 ))
    local CACHE_FMT
    printf -v CACHE_FMT "%.1fm" $CACHE_MIN
    integer WARN_SEC=$(( CACHE_TTL_SEC > 90 ? 60 : CACHE_TTL_SEC / 2 ))
    if (( CACHE_REM > WARN_SEC )); then
      SEG_BG+=("$P_MINT")
    else
      SEG_BG+=("$P_YELLOW")
    fi
    SEG_TXT+=("${NF_CLOCK} ${B}${CACHE_FMT}${KEEP_MARK}${NB}")
  else
    SEG_BG+=("$P_ROSE")
    SEG_TXT+=("${NF_CLOCK} ${B}0.0m${KEEP_MARK}${NB}")
  fi
else
  SEG_BG+=("$P_MINT")
  SEG_TXT+=("${NF_CLOCK} --")
fi

# ─── 13. Optional Block 8: Spend & Quota (Pastel Pink) ────────────────────────
local S_COST_BG="$P_PINK"
local -a COST_ITEMS=()
if (( COST_USD > 0 )); then
  local COST_FMT
  if (( COST_USD >= 1.0 )); then
    printf -v COST_FMT "\$%.2f" $COST_USD
  else
    printf -v COST_FMT "\$%.3f" $COST_USD
  fi
  local COST_ITEM="${B}${COST_FMT}${NB}"
  if (( SUB_USD >= 0.005 )); then
    local SUB_FMT
    printf -v SUB_FMT "\$%.2f" $SUB_USD
    COST_ITEM+="(${NF_SUB}${SUB_FMT})"
  fi
  COST_ITEMS+=("$COST_ITEM")
fi

if (( QUOTA_PCT >= 0 )); then
  local NF_BAT=$'\uf240'
  if (( QUOTA_PCT < 15 )); then
    NF_BAT=$'\uf244'; S_COST_BG="$P_ROSE"
  elif (( QUOTA_PCT < 35 )); then
    NF_BAT=$'\uf243'
  elif (( QUOTA_PCT < 60 )); then
    NF_BAT=$'\uf242'
  elif (( QUOTA_PCT < 80 )); then
    NF_BAT=$'\uf241'
  fi
  COST_ITEMS+=("${NF_BAT} ${B}${QUOTA_PCT}%${NB}")
fi

if (( ${#COST_ITEMS} > 0 )); then
  SEG_BG+=("$S_COST_BG")
  SEG_TXT+=("${(j: :)COST_ITEMS}")
fi

# ─── 14. Optional Block 9: Async Orchestration (Pastel Flamingo) ──────────────
local -a ASYNC_ITEMS=()
if (( SUB_TOT > 0 )); then
  if (( SUB_RUN > 0 )); then
    ASYNC_ITEMS+=("${B}${NF_SUB} ${SUB_RUN}/${SUB_TOT}${NB}")
  else
    ASYNC_ITEMS+=("${NF_SUB} ${SUB_TOT}")
  fi
fi
(( TASKS > 0 ))      && ASYNC_ITEMS+=("${B}${NF_GEAR} ${TASKS}${NB}")
(( ARTIFACTS > 0 ))  && ASYNC_ITEMS+=("${NF_FILE} ${ARTIFACTS}")
(( PENDING_IN > 0 )) && ASYNC_ITEMS+=("${B}${NF_INBOX} ${PENDING_IN}${NB}")

if (( ${#ASYNC_ITEMS} > 0 )); then
  SEG_BG+=("$P_FLAMINGO")
  SEG_TXT+=("${(j: :)ASYNC_ITEMS}")
fi

# ─── 15. Powerline Ribbon Assembly (\ue0b0 Chevron Transitions) ───────────────
local OUT=""
integer N=${#SEG_BG}
for (( i = 1; i <= N; i++ )); do
  local CUR_BG="${SEG_BG[$i]}"
  local CUR_TXT="${SEG_TXT[$i]}"
  OUT+=$'\033[48;2;'"${CUR_BG}m${FG_INK}${CUR_TXT}"
  if (( i < N )); then
    local NEXT_BG="${SEG_BG[$(( i + 1 ))]}"
    OUT+=$'\033[38;2;'"${CUR_BG};48;2;${NEXT_BG}m${PL_RIGHT}"
  else
    OUT+=$'\033[49;38;2;'"${CUR_BG}m${PL_RIGHT}${R}"
  fi
done

print -r -- "$OUT"
