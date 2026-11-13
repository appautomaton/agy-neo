# `agy` TUI Color Palette, `render.Styles` & Markdown Typography Reference

To inspect the live binary tables at any time without running `lldb`, execute:
```bash
python3 inspect_agy.py --styles
```

---

## 1. `types.ColorPalettes["terminal"]` (20 Slots, `0x140 = 320` Bytes)

Constructed in `google3/third_party/jetski/cli/types/types.init` (`v1.5.3: 0x1029c4f48`–`0x1029c51bc`) and stored in `types.ColorPalettes` (`0x10c5a3400`).

| Slot Offset | `v1.5.3` Store VA | Upstream Value | Patched Value | Semantic Role & Primary Consumers |
| :--- | :--- | :--- | :--- | :--- |
| **`+0x000`** | `(zero_loop)` | `nil` | `nil` | **Background** (`Styles` #37, #38, #39, #74; Glamour `Code.BackgroundColor`) |
| **`+0x010`** | `(zero_loop)` | `nil` | `nil` | **Primary Foreground** (`Styles[+0x0798]` #3 `PrimaryText`, Agent prose) |
| **`+0x020`** | `0x1029c50b0` | `Color("12")` | **`nil` (Site #12)** | **Primary Accent: Spinner Shimmer & TUI Selector** (`renderRunningLightInternal` @ `0x102c91b9c` `Working...`/`Running command...` `#10`/`#11`, slash/`/model` selector `#21` `> /add-dir` + `#22`, and footer key hints `#54`/`#55` `↑/↓` / `enter` / `tab` $\rightarrow$ native Primary Foreground `#c8c8c8` dark / `#1c1d1f` light) The stock running light (live thought, live search, `@`-suggestions) still reads it; the pending line takes the theme path with its own colors since **Sites #49e–#49h**. |
| **`+0x030`** | `0x1029c50c0` | `Color("8")` | `Color("8")` | **Border / Horizontal Rule** (`Styles[+0x2b08]` #17 `───` in `renderUserPrompt` and `StickyPrompt`; both rules removed by **Sites #24–#29**) |
| **`+0x040`** | `0x1029c50d0` | `Color("4")` | **`nil` (Site #13)** | **User Prompt** (`Styles[+0x0000]` #0 in `renderUserPrompt` $\rightarrow$ Regular Primary Foreground, on a full-width 256-color bar, with leading `> ` styled as `Faint` via **Sites #21, #22 & #24**) |
| **`+0x050`** | `0x1029c50e0` | `Color("2")` | `Color("2")` | **Success / Completed Tool Mark `●`, drawn `⋆` since Site #57** (`Styles[+0x74a0]` #46 in `toolStatusIcon` @ `0x102c8f500`) |
| **`+0x060`** | `0x1029c50f0` | `Color("2")` | `Color("2")` | **Diff Addition Fg** (`Styles[+0x3f48]` #25, `Styles[+0xa230]` #64) |
| **`+0x070`** | `0x1029c5100` | `nil` | `nil` | **Diff Addition Bg** (`Styles[+0xa230]` #64, `Styles[+0xa9c8]` #67) |
| **`+0x080`** | `0x1029c5108` | `nil` | `nil` | **Diff Deletion Bg** |
| **`+0x090`** | `0x1029c5110` | `Color("1")` | `Color("1")` | **Diff Deletion Fg** (`Styles[+0xa4b8]` #65) |
| **`+0x0a0`** | `0x1029c5120` | `nil` | `nil` | **Diff Context Bg** (`Styles[+0xa4b8]` #65, `Styles[+0xac50]` #68) |
| **`+0x0b0`** | `0x1029c5128` | `nil` | `nil` | **Diff Context Fg** |
| **`+0x0c0`** | `0x1029c5130` | `Color("8")` | `Color("8")` | **Diff Line Number / Muted** (`Styles` #66, #67, #68) |
| **`+0x0d0`** | `0x1029c5140` | `Color("3")` | `Color("3")` | **Warning / In-Action Tool Mark `●` (`⋆`/`⊹` since Site #57) / Patched Inline `` `code` ``** (`Styles[+0x7728]` #47 pulsing `●`/`○` in `toolStatusIcon`; Glamour `Code.Color` via **Sites #17–#18**) |
| **`+0x0e0`** | `0x1029c5150` | `Color("5")` | `Color("5")` | **Mode / Special Badge** (`Styles[+0x0a20]` #4, `Styles[+0xcab0]` #80) |
| **`+0x0f0`** | `0x1029c5160` | `Color("1")` | `Color("1")` | **Error / Failed Tool Dot `●`** (`Styles[+0x7c38]` #49 in `toolStatusIcon` @ `0x102c8f494`) |
| **`+0x100`** | `0x1029c5170` | `Color("3")` | `Color("3")` | **Tertiary Warning / Waiting Approval** (`Styles` #8, #26, #37, #78) |
| **`+0x110`** | `0x1029c5180` | `Color("4")` | `Color("4")` | **Hyperlink / URI `[text](uri)`** (`Styles[+0x0f30]` #6 `CCILink` with `Underline`, `Styles` #44, #45) |
| **`+0x120`** | `0x1029c5190` | `Color("7")` | `Color("7")` | **Secondary Text / CoT Base** (`Styles[+0x0510]` #2 `CoT`, overridden by **Sites #09, #11 & #20** to native `Faint` / `Faint+Italic`) |
| **`+0x130`** | `0x1029c51a0` | `Color("8")` | `Color("8")` | **Dim / Canceled Tool Dot `●` / Shimmer Base** (`Styles[+0x79b0]` #48 canceled `●`; `renderRunningLightInternal` @ `0x102c91c08` base text; `themerender.runningLightAt`'s base too, which **Site #49h** replaces with `#4796E3` for the pending line) |

---

## 2. Key `render.Styles` Fields & TUI Consumers (`render.resolveStyles` @ `0x102c93d50`)

Each `lipgloss.Style` is `0x288` (`648`) bytes. Note that a `0x30` (`48B`) non-Style metadata block sits between Field #29 (`+0x4968`) and Field #30 (`+0x4c20`), shifting offsets for fields `#30`..`#81` by `+0x30`.

| Field | `Styles` Offset | `v1.5.3` Resolve VA | Palette Source | SGR / Attributes | TUI Consumer Functions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **#0** | `+0x0000` | `0x102c93e68` | **Site #13**: `+0x040` (`nil` Primary Fg) | **Site #21**: Regular (no `Bold`) + bar background | `render.renderUserPrompt` (`0x102c92840`) & `render.StickyPrompt` — submitted user messages (`Faint` `\x1b[2m> \x1b[22m` chevron via **Sites #22/#26** + Regular Primary Fg message on a full-width bar via **Sites #24/#28**) |
| **#1** | `+0x0288` | `0x102c93f38` | **Site #19**: `+0x010` (`nil` Primary Fg) | `Bold` (`0x01`) | `render.renderToolCallWithStatus` (`0x102c8ecac`) — tool call name `Bash`, `Edit`, `Read` |
| **#2** | `+0x0510` | `0x102c94008` | `+0x120` (patched `nil`) | **Sites #09, #11 & #20**: `Faint` (`0x20`) for `(xxx)` & `∴ Thought...` header, `Faint\|Italic` (`0x22`) for CoT body | `render.renderToolCallWithStatus` (`0x102c8edac` `(xxx)` args) & `render.stepContent` (`∴ Thought...`) |
| **#3** | `+0x0798` | `0x102c94084` | `+0x010` (`nil`) | Regular | Primary foreground prose |
| **#6** | `+0x0f30` | `0x102c9424c` | `+0x110` (`ANSI "4"` Blue) | `Underline` | `render.restoreCCIPlaceholders` (`0x102c5a070`) — clickable file/symbol links `[text](file://...)` |
| **#10** | `+0x1950` | `0x102c94470` | **Site #12**: `+0x020` (`nil` Primary Fg) | Regular | `RunningDot` — spinner shimmer shoulder |
| **#11** | `+0x1bd8` | `0x102c944ec` | **Site #12**: `+0x020` (`nil` Primary Fg) | Regular | `RunningLightPeak` — spinner shimmer peak (`Working...` / `Running command...`) |
| **#14** | `+0x2370` | `0x102c946b4` | **Site #16**: `nil` | **Site #16**: `Faint` (`0x20`, `\x1b[2m`) | `model.PromptModel.promptChevron` (`0x102f7b4f0`) — live bottom input box `>` chevron |
| **#17** | `+0x2b08` | `0x102c947d4` | `+0x030` (`ANSI "8"` Gray) | Regular | `render.renderUserPrompt` (`0x102c928b0`) — `───` rule above user message |
| **#21** | `+0x3528` | `0x102c94970` | **Site #12**: `+0x020` (`nil` Primary Fg) | `Bold` (`0x01`) | TUI selector active row (`> /add-dir`, `/model` selected row) |
| **#22** | `+0x37b0` | `0x102c94a64` | **Site #12**: `+0x020` (`nil` Primary Fg) | Regular | TUI selector active cursor (`>`) |
| **#39** | `+0x62e8` | `0x102c954b8` (`0x102c984e0` override) | **Site #14**: `nil` | **Site #14**: `Reverse` (`0x08`, `\x1b[7m`) | `model.(*selectionState).highlight` (`0x102f941a0`) — mouse text selection |
| **#46** | `+0x74a0` | `0x102c95be8` | `+0x050` (`ANSI "2"` Green) | Regular | `render.toolStatusIcon` (`0x102c8f500`) — **completed** tool call dot `● Bash(...)` / `● Read(...)` |
| **#47** | `+0x7728` | `0x102c95c64` | `+0x0d0` (`ANSI "3"` Amber) | Regular | `render.toolStatusIcon` (`0x102c8f360` $\rightarrow$ `0x102c8efe0`) — **in-action pulsing** tool call mark `●`/`○` (`⋆`/`⊹` since Site #57) (`500ms` period) |
| **#48** | `+0x79b0` | `0x102c95ce0` | `+0x130` (`ANSI "8"` Gray) | Regular | `render.toolStatusIcon` (`0x102c8f56c`) — **canceled** tool call dot `●` |
| **#49** | `+0x7c38` | `0x102c95d5c` | `+0x0f0` (`ANSI "1"` Red) | Regular | `render.toolStatusIcon` (`0x102c8f494`) — **failed / error** tool call dot `●` |
| **#54 / #55** | `+0x88e0` / `+0x8b68` | `0x102c95fc8` / `0x102c96044` | **Site #12**: `+0x020` (`nil` Primary Fg) | Regular / `Bold` | TUI footer key hints (`↑/↓` `Navigate` · `enter` `Select` · `tab` `Complete`) |

---

## 3. `lipgloss.Style` Internal Memory Layout (`0x288 = 648` Bytes)

Verified against `lipgloss.(*Style).set` (`0x1029adf60`) and `lipgloss.Style.Render` (`0x1029aa960`):
- **`+0x00` (`uint64`)**: `s.props` — bitmask of explicitly set properties (`isSet(propKey)` checks `(s.props & key) != 0`).
  - `0x001` (bit 0): `boldKey` (`\x1b[1m`)
  - `0x002` (bit 1): `italicKey` (`\x1b[3m`)
  - `0x004` (bit 2): `strikethroughKey` (`\x1b[9m`)
  - `0x008` (bit 3): `reverseKey` (`\x1b[7m`)
  - `0x010` (bit 4): `blinkKey` (`\x1b[5m`)
  - `0x020` (bit 5): `faintKey` (`\x1b[2m`)
  - `0x400` (bit 10): `foregroundKey` (`s.fgColor` at `+0x40`)
  - `0x800` (bit 11): `backgroundKey` (`s.bgColor` at `+0x50`)
  - `0x2000` (bit 13): `widthKey` (`s.width` at `+0x78`; verified in `Style.GetWidth` @ `0x1029a9740`)
- **`+0x38` (`uint64`)**: `s.attrs` — boolean values for bits `0..5` (`Bold`, `Italic`, `Strikethrough`, `Reverse`, `Blink`, `Faint`).
- **`+0x40` (`16B` interface `color.Color`)**: `s.fgColor` (ignored by `Render` when bit `0x400` of `s.props` is `0`).
- **`+0x50` (`16B` interface `color.Color`)**: `s.bgColor` (ignored by `Render` when bit `0x800` of `s.props` is `0`).

---

## 4. Glamour Markdown Inline Code (`render.glamourStyleForScheme` @ `0x102c65f90`)

In `glamourStyleForScheme`:
- The 20-slot `ColorPalette` is copied onto the stack at **`sp + 0x38`** (`sp + 0x38 + pal_off`).
- The `ansi.StyleConfig` struct (`0x1848` bytes) is constructed on the stack at **`sp + 0x2d8`**:
  - `0x102c666c0`–`0x102c666d4`: Zeroes `Code.Prefix` (`[sp, #0x14b0]`) and `Code.Suffix` (`[sp, #0x14c0]`), stripping visible padding/backticks around inline `` `code` `` spans.
  - `0x102c666d8` (**Site #17**) & `0x102c666f8` (**Site #18**): Originally loads `[sp, #0x58]` (`palette[+0x020]`) into `Code.Color` (`[sp, #0x14d0]`). Patched to load **`[sp, #0x108]` (`palette[+0x0d0] = Color("3")` Warm Amber)** so inline `` `code` `` spans remain Warm Amber while `palette[+0x020]` is `nil` (native Primary Foreground for Spinner shimmer & TUI Selector).

---

## 5. TUI Rendering Pipeline, Scrollback Split & Height Ratchet Internals (`v1.5.3`)

Critical invariants when modifying `render` or `model` functions:

| Component / Function | `v1.5.3` VA | Struct / Register Invariant | Failure Mode if Violated |
| :--- | :--- | :--- | :--- |
| **`render.stepContent`** | `0x102c88e00` | `w3` (`expanded` bool): `0x102c8915c` checks `Status == 1` (streaming single-line thought preview); `0x102c898b0` (**Site #08**) checks `expanded` for completed CoT blocks. `0x102c8a6a4` (**Site #10**) sets paragraph prefix length (`mov x2, xzr`). | Forcing multi-line CoT during `Status == 1` (`0x102c8915c`) inflates streaming height before tool calls and leaves blank lines when the height ratchet clamps. |
| **`render.(*itemRenderer).render`** | `0x102c6ff30` | Populates `RenderedItem` (`0x60B` struct): `+0x28..+0x38` = `CollapsedContent`, `+0x40..+0x50` = `ExpandedContent`, **`+0x58` = `UncommittableTailLines`** (computed at `0x102c71424..0x102c71444`). | Jumping over `0x102c71424` leaves `RenderedItem[+0x58] = 0`, causing `viewport.computeSplitPoint` (`0x102e249f8`) to prematurely flush live streaming lines into terminal scrollback. |
| **`render.padLinesToWidth` & `render.closedLineWidth`** | `0x102c5fba0` / `0x102c60070` | Called by `render.fitWidth` to pad every rendered line with spaces to full terminal width `W` so BubbleTea in-place redraws overwrite stale characters. `closedLineWidth` (`0x102c60174`) calls `utf8.DecodeRuneInString` and returns `(0, false)` on `utf8.RuneError` (`0xfffd`, `size == 1`). | Any invalid UTF-8 byte in a rendered line aborts `padLinesToWidth` for that entire block, leaving trailing characters from previous frames un-erased on screen. |
| **`model.(*App).applyLiveHeightRatchet` & `padLiveRegionBy`** | `0x102e9c2a0` / `0x102e9c3fc` | Locks the live bottom viewport height (`ratchet.maxHeight`) while `UncommittableTailLines > 0` and pads with `\n` via `padLiveRegionBy` if the live region shrinks mid-turn; resets on terminal resize (`tea.WindowSizeMsg`). | Any transient height spike during streaming permanently pads extra blank lines above the prompt box until the turn ends or the window is resized. |
| **`render.renderPlannerBody` & `render.AutoCloseMarkdown`** | `0x102c6be40` / `0x102c68230` | Stateless per-message Markdown renderer. `AutoCloseMarkdown` (`0x102c682bc..0x102c68838`) tracks triple-backtick fences and single backticks (`0x60`), but **does not parse CommonMark double-backtick spans**. | An odd count of non-triple backticks in an assistant message causes `AutoCloseMarkdown` (`0x102c68838`) to append a stray closing backtick (and `**`) at the end of that message. |
