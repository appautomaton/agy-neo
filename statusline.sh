#!/bin/zsh
# Antigravity CLI Pastel Spectrum Powerline Bar (Atomic Per-Metric Color Blocks + Adaptive Dark/Light)
# Design: 8+ Distinct Pastel Spectrum Blocks (\ue0b0 ) + Auto Dark/Light Palette
# Performance: 1x jq process, 5s cached theme check (~0ms steady-state), 0 subshells
emulate -L zsh
setopt PIPE_FAIL NO_UNSET
zmodload zsh/datetime
zmodload -F zsh/stat b:zstat

export LC_NUMERIC=C
local NOW=$EPOCHREALTIME
integer NOW_SEC=${EPOCHSECONDS:-${NOW%.*}}

# ─── 1. Single-Pass jq Extraction (ASCII \x1f Unit Separator) ─────────────────
local SESSION_ID STATE EXEC_MODE MODEL_NAME EFFORT CWD BRANCH DIRTY SBX_ON SBX_NET USED_PCT TOT_IN TOT_OUT CUR_IN CUR_OUT CACHE_READ EXCEEDS_200K COST_USD SUB_USD QUOTA_PCT SUB_TOT SUB_RUN TASKS ARTIFACTS PENDING_IN CONFIRM_PENDING

jq -r '
  [
    (.session_id // .conversation_id // "default" | tostring),
    (.agent_state // "idle" | tostring),
    (.execution_mode // .cycle_mode // "" | tostring),
    (.model.id // .model.display_name // "Model" | tostring),
    (.model.effort // "" | tostring),
    (.cwd // .workspace.current_dir // .workspace.project_dir // "" | tostring),
    (.vcs.branch // .vcs.client // "" | tostring),
    (if .vcs.dirty == true then "true" else "false" end),
    (if .sandbox.enabled == true then "true" else "false" end),
    (if .sandbox.allow_network == true then "true" else "false" end),
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
    (if .tool_confirmation_pending == true then "true" else "false" end)
  ] | map(tostring) | join("\u001f")
' 2>/dev/null | IFS=$'\x1f' read -r \
  SESSION_ID STATE EXEC_MODE MODEL_NAME EFFORT CWD BRANCH DIRTY SBX_ON SBX_NET \
  USED_PCT TOT_IN TOT_OUT CUR_IN CUR_OUT CACHE_READ EXCEEDS_200K \
  COST_USD SUB_USD QUOTA_PCT \
  SUB_TOT SUB_RUN TASKS ARTIFACTS PENDING_IN CONFIRM_PENDING || exit 0

[[ -z "${SESSION_ID:-}" ]] && exit 0

# ─── 2. Stateful TPS, Cache TTL & Response Model Engine ───────────────────────
local STATE_FILE="/tmp/agy_telemetry_${SESSION_ID//[^a-zA-Z0-9_-]/_}.dat"
local CONV_DB="${HOME}/.gemini/antigravity-cli/conversations/${SESSION_ID}.db"
local CUR_MODEL_KEY="${MODEL_NAME// /_}"
local PREV_STATE="idle" START_TIME=$NOW BASE_OUT=$TOT_OUT LAST_TPS="--" STEP_LAT="--" LAST_DELTA=0 RESP_MODEL="" PREV_MODEL_KEY="" CACHE_TS=0

if [[ -f "$STATE_FILE" ]]; then
  read -r PREV_STATE START_TIME BASE_OUT LAST_TPS STEP_LAT LAST_DELTA RESP_MODEL PREV_MODEL_KEY CACHE_TS < "$STATE_FILE" 2>/dev/null || true
  [[ "$START_TIME" == <->* ]]      || START_TIME=$NOW
  [[ "$BASE_OUT" == <-> ]]         || BASE_OUT=$TOT_OUT
  [[ "$LAST_DELTA" == <-> ]]       || LAST_DELTA=0
  [[ "${CACHE_TS:-}" == <-> ]]     || CACHE_TS=0
  [[ "$RESP_MODEL" == "-" ]]       && RESP_MODEL=""
  if [[ -n "$PREV_MODEL_KEY" && "$PREV_MODEL_KEY" != "$CUR_MODEL_KEY" ]]; then
    RESP_MODEL=""
  fi
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

# Under cache_relay.py, the relay's record of the last real or replayed upstream request
# is authoritative: it excludes subagent traffic, so a parent waiting on a long subagent
# or tool run counts down truthfully instead of being reset on every non-idle tick.
local RELAY_FILE="/tmp/agy_cache_${SESSION_ID//[^a-zA-Z0-9_-]/_}.dat"
local RELAY_TS=0 RELAY_TOUCHES=0 RELAY_STATUS=""
if [[ -n "${AGY_CACHE_RELAY:-}" && -r "$RELAY_FILE" ]]; then
  read -r RELAY_TS RELAY_TOUCHES RELAY_STATUS < "$RELAY_FILE" 2>/dev/null || true
  [[ "$RELAY_TS" == <-> ]] && (( RELAY_TS > 0 )) && CACHE_TS=$RELAY_TS
  [[ "$RELAY_TOUCHES" == <-> ]] || RELAY_TOUCHES=0
fi

# Refresh exact upstream response model (.1.19 ResponseModelFull) on new turn completion or cache miss
if (( DELTA_OUT > 0 )) || [[ -z "$RESP_MODEL" && $TOT_OUT -gt 0 ]]; then
  if [[ -r "$CONV_DB" ]]; then
    local DB_MODEL
    DB_MODEL=$(/usr/bin/sqlite3 "$CONV_DB" "
      SELECT CAST(
        substr(
          tail,
          instr(tail, X'9A01') + 3,
          CASE
            WHEN instr(substr(tail, instr(tail, X'9A01') + 3), X'A201') > 0
            THEN instr(substr(tail, instr(tail, X'9A01') + 3), X'A201') - 1
            ELSE instr(substr(tail, instr(tail, X'9A01') + 3), X'AA01') - 1
          END
        ) AS TEXT
      )
      FROM (
        SELECT substr(data, -600) AS tail
        FROM gen_metadata
        WHERE instr(substr(data, -600), X'9A01') > 0
        ORDER BY idx DESC LIMIT 1
      );
    " 2>/dev/null) || true
    [[ -n "$DB_MODEL" ]] && RESP_MODEL="$DB_MODEL"
  fi
fi

print -r -- "$STATE $START_TIME $BASE_OUT $LAST_TPS $STEP_LAT $LAST_DELTA ${RESP_MODEL:--} $CUR_MODEL_KEY $CACHE_TS" >| "$STATE_FILE" 2>/dev/null || true

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
local NF_ALERT=$'\uf071'      # nf-fa-warning
local NF_BRANCH=$'\ue0a0'     # nf-pl-branch
local NF_WORKTREE=$'\uf1bb'   # nf-fa-tree (Linked Git worktree)
local NF_SHIELD=$'\uf132'     # nf-fa-shield (Sandbox ON)
local NF_GLOBE=$'\uf0ac'      # nf-fa-globe (Sandbox + Network)
local NF_UNLOCK=$'\uf09c'     # nf-fa-unlock (Sandbox OFF)
local NF_BOLT=$'\uf0e7'       # nf-fa-bolt (TPS)
local NF_CLOCK=$'\uf017'      # nf-fa-clock_o (Turn elapsed time)
local NF_CHIP=$'\uf2db'       # nf-fa-microchip (Context window)
local NF_DB=$'\uf1c0'         # nf-fa-database (Prompt cache)
local NF_SUB=$'\uf0e8'        # nf-fa-sitemap (Subagents)
local NF_GEAR=$'\uf013'       # nf-fa-gear (Background tasks)
local NF_FILE=$'\uf1c9'       # nf-fa-file_code_o (Artifacts)
local NF_INBOX=$'\uf01c'      # nf-fa-inbox (Queued inputs)

local -a SEG_BG=()
local -a SEG_TXT=()

# ─── 5. Atomic Block 1: Execution Mode (Pastel Mauve / Mint / Sky / Peach / Rose)
if [[ "$CONFIRM_PENDING" == "true" ]]; then
  SEG_BG+=("$P_ROSE")
  SEG_TXT+=("${B}${NF_ALERT} ACT${NB}")
fi

if [[ -n "$EXEC_MODE" ]]; then
  local MODE_BG="$P_MAUVE"
  local MODE_TXT="$EXEC_MODE"
  case "${EXEC_MODE:l}" in
    default|request-review)
      MODE_BG="$P_MAUVE"
      MODE_TXT="ask"
      ;;
    *accept-edits*)
      MODE_BG="$P_MINT"
      MODE_TXT="edits"
      ;;
    *plan*)
      MODE_BG="$P_SKY"
      MODE_TXT="plan"
      ;;
    *auto*)
      MODE_BG="$P_PEACH"
      MODE_TXT="auto"
      ;;
    *yolo*)
      MODE_BG="$P_ROSE"
      MODE_TXT="yolo"
      ;;
  esac
  SEG_BG+=("$MODE_BG")
  SEG_TXT+=("$MODE_TXT")
fi

# ─── 6. Atomic Block 2: Exact Upstream Response Model (Pastel Lavender) ───────
local MODEL_SLUG="${${MODEL_NAME%% · *}%% \(*\)}"
MODEL_SLUG="${${MODEL_SLUG:l}// /-}"
local MODEL_TXT="${B}${RESP_MODEL:-$MODEL_SLUG}${NB}"
SEG_BG+=("$P_LAVENDER")
SEG_TXT+=("$MODEL_TXT")

# ─── 7. Atomic Block 3: Sandbox Shield (Pastel Sapphire / Peach / Rose) ───────
if [[ "$SBX_ON" == "true" ]]; then
  if [[ "$SBX_NET" == "true" ]]; then
    SEG_BG+=("$P_PEACH")
    SEG_TXT+=("${NF_GLOBE}")
  else
    SEG_BG+=("$P_SAPPHIRE")
    SEG_TXT+=("${NF_SHIELD}")
  fi
else
  SEG_BG+=("$P_ROSE")
  SEG_TXT+=("${NF_UNLOCK}")
fi

# ─── 8. Optional Block: VCS Branch & Worktree (Pastel Sky / Rose when dirty) ──
# Upstream agy's store.detectVCSOnDisk (0x102d629b0) only sets .vcs.type="git"
# and leaves .vcs.branch and .vcs.dirty empty. Resolve HEAD & linked worktree
# in-process (0 forks) and cache dirty status for 2s (or until turn completion).
local IS_WORKTREE="false"
if [[ -n "${CWD:-}" && -d "$CWD" ]]; then
  local SEARCH_DIR="$CWD" GIT_META="" HEAD_FILE=""
  while [[ -n "$SEARCH_DIR" && "$SEARCH_DIR" != "/" ]]; do
    if [[ -d "$SEARCH_DIR/.git" ]]; then
      HEAD_FILE="$SEARCH_DIR/.git/HEAD"
      break
    elif [[ -f "$SEARCH_DIR/.git" ]]; then
      read -r GIT_META < "$SEARCH_DIR/.git" 2>/dev/null || true
      if [[ "$GIT_META" == "gitdir: "* ]]; then
        local GD="${GIT_META#gitdir: }"
        [[ "$GD" != /* ]] && GD="$SEARCH_DIR/$GD"
        [[ "$GD" == *"/worktrees/"* ]] && IS_WORKTREE="true"
        HEAD_FILE="$GD/HEAD"
      fi
      break
    fi
    SEARCH_DIR="${SEARCH_DIR:h}"
  done
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
    if (( DELTA_OUT == 0 )) && [[ "$VCS_TS" == <-> ]] && (( NOW_SEC - VCS_TS < 2 )) && [[ "$VCS_CWD" == "$CWD" ]]; then
      DIRTY="$VCS_DIRTY"
    else
      if [[ -n "$(/usr/bin/git -C "$CWD" --no-optional-locks status --porcelain --ignore-submodules=dirty 2>/dev/null)" ]]; then
        DIRTY="true"
      else
        DIRTY="false"
      fi
      print -r -- "${NOW_SEC}"$'\t'"${CWD}"$'\t'"${DIRTY}" >| "$VCS_CACHE" 2>/dev/null || true
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

# ─── 12. Atomic Block 7: Implicit Cache TTL Countdown (300s Window) ───────────
# Empirical agy/Gemini implicit cache cliff is 5.0 min (300s).
# Refreshes every 15s (0.25m) while idle: 5.0m -> 4.8m -> 4.5m -> 4.2m -> 4.0m...
# >1.0m: Mint (Hot), 0.1..1.0m: Yellow (Expiring), <=0.0m: Rose (Cold).
if (( CACHE_TS > 0 )); then
  integer CACHE_REM=$(( 300 - (NOW_SEC - CACHE_TS) ))
  # Keepalive: in the last 60s ask the relay to replay the last request, so touches land
  # about every 4 minutes (the 15s tick adds up to 15s). Each costs a cache read of the
  # prompt plus ~100 thought tokens; the relay serializes touches, caps them at 4 per
  # idle stretch (~21 min of cover), and stops on any failure.
  if [[ "$RELAY_STATUS" == live ]] && (( CACHE_REM > 0 && CACHE_REM <= 60 &&
        TOT_PROMPT >= 32000 && RELAY_TOUCHES < 4 )); then
    /usr/bin/curl -sS -m 120 -X POST "${AGY_CACHE_RELAY}/_touch/${SESSION_ID}" \
      </dev/null >/dev/null 2>&1 &!
  fi
  # Keepalive marker: ↻ while armed, ↻n after n touches, ✗ once a touch has failed.
  local KEEP_MARK=""
  if [[ "$RELAY_STATUS" == fail ]]; then
    KEEP_MARK=" ✗"
  elif [[ "$RELAY_STATUS" == live ]] && (( RELAY_TOUCHES > 0 || TOT_PROMPT >= 32000 )); then
    KEEP_MARK=" ↻"
    (( RELAY_TOUCHES > 0 )) && KEEP_MARK+="$RELAY_TOUCHES"
  fi
  if (( CACHE_REM > 0 )); then
    float CACHE_MIN=$(( CACHE_REM / 60.0 ))
    local CACHE_FMT
    printf -v CACHE_FMT "%.1fm" $CACHE_MIN
    if (( CACHE_REM > 60 )); then
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
