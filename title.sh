#!/bin/zsh
# Antigravity CLI Dynamic Terminal Title (OSC 2 via native settings.json "title" runner)
# Receives StatusLineData JSON on stdin; emits one plain-text line for tea.View.WindowTitle:
#   `<glyph> <dir> ⋅ <conversation_title>` (or `<glyph> <dir>` until a title exists)
# Glyphs match agy-neo's pending breath (`⋅` resting, `✦` active) and are East-Asian-Width
# neutral (width=1 in tmux/CJK and present in Maple Mono NF CN). The ` ⋅ ` delimiter lets
# tmux show both on wide terminals and paginate cleanly between dir and title on narrow ones.
emulate -L zsh
setopt PIPE_FAIL NO_UNSET

[[ -z "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" ]] && export LC_CTYPE="en_US.UTF-8"

jq -r '
  def clean:
    gsub("[\\r\\n\\t]+"; " ")
    | gsub(" ⋅ "; " - ")
    | gsub("  +"; " ")
    | sub("^ "; "")
    | sub(" $"; "");
  def dir_base:
    ([.workspace.current_dir, .cwd, .workspace.project_dir]
      | map(select(type == "string" and length > 0))
      | .[0] // "")
    | sub("/+$"; "")
    | if length > 0 then (split("/") | last) else "" end;

  (.agent_state // "idle" | tostring) as $state |
  (.tool_confirmation_pending == true) as $confirm |
  ((if (.subagents | type) == "array" then
      ([.subagents[] | select(.status == "running" or .status == "working" or .status == "thinking")] | length)
    else 0 end) > 0) as $sub_active |
  ((.conversation_title // "" | tostring) | clean) as $raw_title |
  (if ($raw_title | length) > 72 then ($raw_title[0:71] + "…") else $raw_title end) as $title |
  (dir_base | clean) as $dir |
  (if ($dir | length) > 0 and ($title | length) > 0 and $title != $dir then "\($dir) ⋅ \($title)"
   elif ($title | length) > 0 then $title
   elif ($dir | length) > 0 then $dir
   else "agy" end) as $body |
  (if $confirm or $state == "reviewing" then "?"
   elif $state == "error" or $state == "auth" then "!"
   elif $state == "working" or $state == "tool_use" or $state == "initializing" or $state == "merging" or $sub_active then "✦"
   else "⋅" end) as $glyph |
  "\($glyph) \($body)"
' 2>/dev/null || true
