# The Pending Line and Live Thinking

The line under the conversation while a turn runs (stock `⣾ Thinking...`, `Running command...`, retry and compaction notices; patched `✦ Stargazing…  8s`): how `agy` builds it, why a thought only appeared once it was over, and what the patches change. Addresses are `v1.5.6`; struct offsets move between releases (see [`context-window-patch.md` §5.4](./context-window-patch.md#54-struct-fields-move-between-releases-v156)).

## 1. Assembly: `model.(*ConversationModel).pendingLineView` (`0x102f87c80`)

One line, built left to right, then an optional second line:

| Step | Code | Notes |
| :--- | :--- | :--- |
| State | `agentActivity` → `deriveAgentState` → `classifyStepsReverse` | Returns an `AgentState`: `(kind, payload)`. Kind `8` is forced while the conversation loads. |
| Text | an override string on the model (`+0x5c780`), else `activityCandidate` | See §2. |
| Ellipsis | `concatstring2(text, "...")` | One place for every state; Site #50a points it at a `…` already in the binary, three bytes as well. Stock kind `7` (compaction) kept the bare text, since its label carried its own `(12s)`. |
| Frame | model field `+0x5c770` + `" "` | The frame already ends in a space. Site #49i appends an empty string instead: one space after the glyph, as on the tool lines above. `lipgloss.Width` of the result is still the glyph's two columns. |
| Fit | `TruncateAnsi(text, width − frame − right − 3)` | Only on the path taken when a right-hand status exists; the other path does not reserve. Since Site #50e that path is always taken, and it reserves `50` (#50f). `View` passes a second flag that hides the status while a tip shows; stock then skipped this path too, and Site #50h takes it with the status emptied. |
| Light | `renderPendingLight` → `render.RenderRunningLight`, or `themerender.RunningLight` under a seasonal theme | Since Site #49f always the theme path, with Halloween's value (§3). |
| Right | `strings.Repeat(" ", n)` + `styledArtifactStatus` (`2 artifacts · /artifact to review`) | Right-aligns the status. Since Site #50g the padding is `elapsedSuffix(m, n)`, faint, padded inside its faint span; since #50i it reads ` (8s ⋅ thinking)` for a thought (` (1m 5s ⋅ deep in thought)` past `60s`, each naming the label's effort (` with high effort`)), ` (8s ⋅ running)` for a tool call, ` (8s)` otherwise. The separator is `⋅` (U+22C5, width-neutral), not `·` (U+00B7, two columns under a CJK locale). |
| Second line | `"\n" + pendingDecoration()` when non-empty | A separate line, not a right-hand slot. |

## 2. Text: `(*ConversationModel).activityCandidate` (`0x102f6ce90`)

1. `executionStatusLabel` first: `Model unavailable (attempt %d/%d), retrying in %ds`. If it returns text, nothing else is consulted.
2. Then by kind, each its own branch (a tool call never reaches the thinking branch, and the reverse):

| Kind | Fixed label (`AgentState.Label`) | `activityCandidate` |
| ---: | :--- | :--- |
| 1 | `Initializing agent` | label |
| 2 | rotates `Generating` / `Working` / `Loading`, one word per 10 ticks of the model's tick counter (`+0x5c768`) | label; since Site #56b the turn's verb |
| 3 | `Thinking` | Stock: `render.LastThinkingSnippet`, the latest thought paragraph flattened to one line (the label only while no thought text exists). Site #51f: the label; the thought shows in the conversation (§4). Since Site #56b the turn's verb |
| 4 | `Running` | `steps.DeriveActivityLabel`: the tool's label (`Running command`, `Reading file`, ...), else `Generating` / `Working`. Since Site #56b the turn's verb; the tool row above names the tool |
| 5 | `Waiting` | label |
| 6 | `Creating workspaces... (%ds)` (payload is seconds) | label |
| 7 | `Compacting conversation` | `compactingLabel(now, start)`, with `(12s)` from `render.fmtDuration` |
| 8 | `Loading conversation` | label |

The tick counter at `+0x5c768` also phases the running light; it counts frames, not seconds. Stock keeps one start time: `refreshActivityLabel` stamps model `+0x5c7b8` while the state is Compacting and clears it on any other, and `compactingLabel(start, now)` formats it. Site #50b stamps it for every non-idle state, so it marks the turn's start (§5).

## 3. Glyph, Light and Verb

The patched line, a blank row under the conversation and on the input's rule:

```
∴ Second paragraph: mention one command so inline code shows.

✦ Stargazing… (3s ⋅ thinking)
──────────────────────────────────────────────
```

- **Frames**: one 8-entry `[]string` (header at `0x10dc80c80`, entries at `0x10dc9c2e0`) shared by thirteen views (`NewConversationModel`, `NewAuthModel`, `NewMCPModel`, plugin sign-in, usage, live search, ...), which rely on each frame's trailing space. Stock: `⣾ ⣷ ⣯ ⣟ ⡿ ⢿ ⣻ ⣽`, 4 bytes each. The header's fourth word is the bubbles `FPS`, `100ms`; `spinner.Update` wraps at `len(Frames)` and `themedSpinnerFrame` searches the slice by its length, so the frame count is free.
- **Glyph color**: none. The frame is concatenated as a plain string, so a color has to live inside it.
- **The breath (Sites #49a–#49c)**: `∙ ⋅ ✦`, a point that grows into the star, flares lavender, rests `#4796E3` and fades, 24 frames, one breath every `2.4s`. Each frame is `ESC[38;2;R;G;Bm<glyph>ESC[m `, its color computed in `patch_agy.py` (`SPINNER_BREATH`: brightness and hue per frame between `#4796E3` and `#9177C7`). The strings sit at the end of the `__TEXT` fill.
- **Pointers in new memory do not slide**: the binary is PIE and relocates through `LC_DYLD_INFO_ONLY` rebase opcodes, which list every slot that holds a pointer. A pointer written where none was is never slid and points into unmapped memory. A 24-entry table therefore needs 24 slots that already held pointers: Halloween's pixel-art logo, two 14-row `[]string` tables that `halloween.init` lays end to end (28 slots). The frame slice's header (itself a pointer slot) points there, and `halloween.init.0` no longer calls `theme.Register` (#49d), so nothing draws that logo. With no registered theme, `themeSettingFields` drops the seasonal-theme setting from `/config`, and `theme.Resolve` returns none. Everything else Sites #49 and #56 add (strings, the blue, the verbs) holds no pointer and is addressed PC-relatively.
- **Stock running light**: `render.renderRunningLightInternal` looks the scheme's palette up itself (it does not use `Styles` #10/#11) and builds two styles: lit text from `palette[+0x020]` and the dim base from `palette[+0x130]`. `palette[+0x020]` is shared with the TUI selector and key hints (Site #12 set it to `nil`, the foreground). The live thought line, live search and `@`-suggestions keep this light: the foreground over gray.
- **The theme light (Sites #49e–#49h, #49l)**: a seasonal theme returns colors from `RunningLight(isLight)`, and `themerender.runningLightAt` makes a `lipgloss.Color` style of each; `render.LitWindow` spreads them over the band `RunningLightWindow` places, `min(len, 5)` columns wide, `len + width + 6` steps a cycle, one step per `x2` ms of wall-clock time. Stock wrapped short text one way and swung only text of 25 or more columns; Site #49l swings every length, so the band goes back and forth across the word. `renderPendingLight` takes this path only when its theme settings name an active theme; Site #49f loads Halloween's value (`itab`, `runtime.zerobase`) and goes straight to the call. Halloween's two 5-color tables (`#FF7518`…, `#C2410C`…) become the Gemini band: on a dark background `#8CBDF0 #B4C4F4 #D9CDF5 #C2AEEA #A48FD6`, trailing edge first, lavender at the crest; on a light one, darker blues and purples (#49e). The base under the band was `palette[+0x130]`: `runningLightAt`'s palette lookup (a `mapaccess1` call and a read) becomes a branch to a leaf in the `__TEXT` fill that returns `x2, x3 = color.RGBA's color.Color itab, &stages[i]`, the value `lipgloss.Color("#RRGGBB")` would box (#49h). The word starts `#4796E3`; a long turn warms it along the Gemini gradient, one of 16 stages every `12s` after the first `60s`: purple (`#9177C7`) at about `2m 30s`, rose (`#CA6673`) at `4m`. The leaf has the time (`runningLightAt`'s Unix-ms argument, spilled at entry) and reads the turn's start from the model, which `pendingLineView` spilled three frames up (`runningLightAt` ← `themerender.RunningLight` ← `renderPendingLight` ← `pendingLineView`, each its callee's only caller): `wall` holds the seconds since 1885 in bits 30–62 while the time carries a monotonic reading. The star keeps its own colors. The band steps a column per `100ms` instead of `80` at the default and `medium` speeds (#49g), one per spinner tick, so no tick skips a column.
- **Verbs (Sites #56a–#56b)**: kinds 2–4 (generating, thinking, running a tool) show one of 24 verbs of the night sky (`PENDING_VERBS`: `Stargazing`, `Starhopping`, `Constellating`, …, `Luminescing`) instead of their labels. The verb is picked by the microseconds of the turn's start (`(wall & 0x3fffffff) / 1000` of the time Site #50b stamps, modulo 24; macOS reads the wall clock in microseconds, so nanoseconds modulo 24 only ever gave 0, 8 or 16), so it holds for the turn and the time beside it never moves. Records are 16 bytes, a length byte then the verb, so the routine indexes them without pointers. It runs where Site #50c leaves `activityCandidate`'s Compacting branch dead: a leaf of 20 instructions, no call, returning through the function's own epilogue. Retries, compaction, loading, waiting and initializing keep their words.
- **Glyph choice**: in Maple Mono NF CN, `✦` (U+2726) is `572` units, as tall as `●` (`620`) and on the same line; `⋅` (U+22C5) is `240` and `∙` (U+2219) `170`, centered with it. All three are East Asian Width neutral. `·` and `•` are ambiguous, two columns under a CJK locale, which would shake the line every breath. `✧`, `⁖`, `⁘` and the Nerd Font sparkles are missing or larger than `●` (`918`). The four-fold stars `✥ ✤ ✣` read as clovers mid-breath, and `✶ ✳` are another tool's mark. Check a glyph against the font's `cmap` and render it beside `●` before choosing.
- **The gap (Sites #49j–#49k)**: stock reserves the pending row whether or not a turn runs (blank when idle), so the conversation and the input never move when a turn starts or ends. The gap keeps that rule: the block is two rows in every state. Every height reads the layout. `View` and `messageListViewportHeight` size the conversation as the terminal's height less the sum of the layout's fields, and `populateLayout` writes the pending row into field 2 as `(m+0x5c760 == 0) + pendingDecoration's rows`; #49j counts that row twice. #49k makes the drawn rows match: `pendingLineView`'s tail joined `decoration + "\n" + line` only when a decoration existed, and now every non-empty line takes that join, through a leaf in the `__TEXT` fill that sets up `concatstring3` and returns to the tail's own call: `"\n" + line`, or `decoration + "\n\n" + line`. An empty line without decoration still leaves empty, as the layout reserves nothing for it. Verified with agy's own `[ViewHeights]` log (forced on in a scratch build): `pending=2` and `total` one short of the terminal, for the status line, in every frame, idle or busy, alternate screen or inline.
- **What failed first**: an earlier #49i made the frame `"\n" + frame` and an earlier #49j set `populateLayout`'s field 3 to 2. Field 3 is the tip's row (showTips off: always 0), so the newline was counted nowhere: `upper=31 pending=2 input=3 total=36` on a 36-row terminal. In the alternate screen the pending text drew over the input's rule and the status line fell off the bottom while a turn ran. Count a row where the layout counts it, and draw it where every state draws it.
- **Light backgrounds**: the frames' colors are fixed and tuned for dark backgrounds; the band has a light-background table, the frames do not.

## 4. Why a Thought Appeared Only When It Was Over

Observed in stock (fake Gemini stream, four thought chunks two seconds apart, then text; screen replayed through a terminal emulator): for the whole thought, the conversation showed nothing and the pending line showed `⣾ <latest thought paragraph>`; the `∴ Thought for 8s` block and the answer appeared together when the first text arrived.

**Cause: the drip.** The conversation shows the steps `store.(*textDrip).flush` (`0x102e06670`) hands it, and the drip feeds a planner step's answer in a little at a time (`cutAtRuneBoundary`, 12 bytes a tick, handing over a clone cut at that point). Thought and answer are one planner step. When the step is the last one and nothing is left to drip, `flush` returns without handing it over; it is handed over in full only once a next step exists. Mid-thought the answer is empty, so the step never reached the conversation until the first answer bytes did.

**`stepContent` was ready.** For a running thought it has a live one-liner (`stepContent` `0x102d10a54`–`0x102d10e1c`): the latest paragraph (`thinkingLiveSnippet`) under the running light, then a faint `  (%s)` or `  (%s, %s tokens)`. Nothing ever drew it. Forcing the finished block instead (`0x102d10a50` → `b 0x102d10e28`) draws nothing mid-thought: that branch only renders a thought that is over.

**What groups a thought, and when.** The store groups steps into conversation items (`store.groupSteps` on rebuild, and `advanceDrip.func3` as steps arrive). Under the `verbosity` setting `medium` (the default since it was added) three predicates folded thoughts into tool groups, which draw them as `○ Thought for 3.4s (<title>)` (`summarizeThinkingSteps`): `canUpgradeTrailingThoughtToToolGroup` let a tool step absorb the thought before it, `findLastToolGroupAbsIdx` let a tool call join the group before a thought, and `canMergeConsecutiveThoughts` joined a thought to the tool group before it. The last only fires on rebuild (`--continue`, a restart): live, the drip hands a thought over before its tool calls exist. Under `high` every thought stays its own item and every tool call its own line (`● Read(<path>)`), not `● Explored N files`; `low` folds both into a token table. (`render.GroupSteps` and `coalesceThinkingSteps` serve only the subagent detail view.)

**The change (Sites #51a–#51f).** When the last step has nothing to drip and its answer is still empty, `flush` takes its partial path, handing over the step cut at an empty answer, so `stepContent` draws the live line in the conversation. An answer that has caught up keeps the stock exit, so finished text is not re-rendered each tick. The live line drops its own `(8s)`, since the pending line below counts the turn, and leads with a faint `∴ `. The pending line shows `Thinking`. Sites #52a–#52c keep every thought its own item at every verbosity, live and rebuilt; tool calls still group.

**By verbosity (`/config` → Verbosity).** `medium`, while thinking: the live line. After: one line, the summary's first line as its title, fitted to the width (Sites #54a–#54i); ctrl+o expands it to the block.

```
∴ I should read the note.            medium, while thinking: the latest paragraph, live

✦ Stargazing… (2s ⋅ thinking)
```
then, in place:
```
∴ Thought for 3s (Looking first)
● Explored 1 file (note.txt) (ctrl+o to expand)
∴ Thought for 3s (The conversation logs revealed a clear pattern. A direct comparison of s...)
● Explored 2 files (note.txt, other.txt) (ctrl+o to expand)
∴ Thought for 3s (Answering)

  The note says hello.
```

`high`: the running thought is its full block, growing as it streams, and the `∴ Thought for …` line closes the block when the thought ends, on a line the running block already left blank (Sites #53a–#53d).

```
Planning the reply                   high, while thinking: the block grows paragraph by paragraph

The user greets me, so a short answer will do. I should check…
                                     (blank: the closing line lands here)

✦ Stargazing… (5s ⋅ thinking)
```
then:
```
Planning the reply

The user greets me, so a short answer will do. I should check…
Keep it brief and friendly.
∴ Thought for 8s, 40 tokens
```

## 5. Changes

| Change | Status | Sites |
| :--- | :--- | :--- |
| A breathing Gemini star (24 truecolor frames), a `#4796E3` word under a blue-to-lavender band that warms through purple to rose over a long turn, one space after the glyph, a blank row above. Replaces the green half circle and green light of the first version: green is the completed dot's color alone | Done: frames in Halloween's logo rows, (Halloween is no longer registered), the pending light always on the theme path with Halloween's value and the Gemini band, the base read replaced by a boxed `color.RGBA` | #49a–#49k |
| `…` after the text instead of `...` | Done: the string is pointed at a `…` in the binary | #50a |
| A verb of the night sky per turn (`✦ Stargazing…`) for generating, thinking and running a tool; other states keep their words | Done: a leaf routine in `activityCandidate`'s dead Compacting branch indexes 16-byte records by the turn start's microseconds | #56a–#56b |
| A gray aside (`#999999`, Claude Code's gray; faint read `#646464`) with the turn's elapsed time and what the agent is doing, `(8s ⋅ thinking with high effort)`, `(1m 5s ⋅ deep in thought with high effort)` past a minute, `(8s ⋅ running)`, else `(8s)` (#50i: two leaf detours in the `__TEXT` fill read the state's kind from the model, through the caller's spill of `m`, and choose the format and the padding's width). Effort is not in it: only a parse of the model's label gives it, and the footer shows it. Live tokens do not exist: the count arrives when the request ends. The time runs through tool calls and resets each turn; compaction keeps its plain label and shares the time | Done: the compaction timer stamps for every busy state, and `compactingLabel` is rebuilt as `elapsedSuffix(m, pad)` in the padding's place. A tip under the line hides the status but no longer the time (#50h) | #50b–#50i |
| A thought shows in the conversation while it runs (`∴ <latest paragraph>`, live); the pending line shows `Thinking  2s` (since #56, the turn's verb) | Done: the drip hands over a thinking step with an empty answer; the live line leads with `∴ ` and drops its own time | #51a–#51f |
| Thoughts never fold into tool groups, live or when a conversation is rebuilt | Done: three grouping predicates answer no for a thought | #52a–#52c |
| Under `high`, a running thought is its full block, growing as it streams, closed by `∴ Thought for 8s, 1.2k tokens` | Done: verbosity test for a running thought, empty header for a running step, body before header | #53a–#53d |
| Under `medium`, a finished thought is one line, `∴ Thought for 7s (<title>)`, no token count; ctrl+o expands it | Done: the stock collapsed path, which Site #8 bypassed (now retired), returns with a verbosity test, a `∴ ` header, and its snippet rebuilt as ` (<first line>)` on the same line | #54a–#54i |

## 6. Observing the Line

Static reading misleads here: the line is redrawn in place, so concatenated output streams show text that is never on screen at once. Drive `agy` in a pseudo-terminal, isolated as [`capture_prompt.py`](../capture_prompt.py) is (its own `--app_data_dir`, a loopback model endpoint), and replay the output through a terminal emulator (`pyte`) to read the actual screen at each moment. A loopback endpoint answering `500` keeps the line up in its retry state; one streaming `streamGenerateContent` SSE with `"thought": true` parts reproduces a thinking turn. A fresh app data dir runs onboarding (color scheme, a data-use consent that defaults to opted in: opt out, then trust the folder).
