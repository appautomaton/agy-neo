"""Declarative resolver registry with per-group Go symbol isolation."""

from __future__ import annotations

from typing import Callable, NamedTuple

from .asm import PatchSite
from .cortex import (
    _resolve_context_window_sites,
    _resolve_monitor_sites,
    _resolve_prompt_template_sites,
    _resolve_subagent_model_sites,
    _resolve_work_efficiently_sites,
)
from .keepalive import _resolve_keepalive_sites
from .pending import (
    _resolve_elapsed_sites,
    _resolve_spinner_sites,
    _resolve_tool_mark_sites,
    _resolve_verb_sites,
)
from .symbols import locate_symbols, require_symbols
from .thoughts import (
    _resolve_cot_sites,
    _resolve_thinking_sites,
    _resolve_thought_block_sites,
    _resolve_thought_grouping_sites,
)
from .tui_styles import (
    _resolve_code_theme_sites,
    _resolve_color_scheme_sites,
    _resolve_command_elbow_sites,
    _resolve_palette_and_typography_sites,
    _resolve_statusline_refresh_sites,
)


class GroupSpec(NamedTuple):
    name: str
    required: tuple[str, ...]
    any_of: tuple[tuple[str | tuple[str, ...], ...], ...]
    needs: str | None
    resolve: Callable[[bytes | bytearray, dict[str, tuple[int, int]], dict[str, object], str, bool], object]


GROUP_SPECS: tuple[GroupSpec, ...] = (
    GroupSpec(
        name="context-window",
        required=("GetCheckpointConfig", "applyFeatureProviderCheckpointOverrideConfig", "getMaxTokensForStep", "stepToMessage"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_context_window_sites(data, funcs),
    ),
    GroupSpec(
        name="palette-typography",
        required=(
            "typesInit", "resolveStyles", "lipglossColor", "halloweenInit",
            "renderUserPrompt", "concatstring2", "stringsJoin", "StickyPrompt",
            "pinHeader", "stickyPromptItem", "stickyPromptAt", "SetTerminalBackground", "RerenderAll",
        ),
        any_of=(("glamourStyle", "glamourStyleForScheme"),),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_palette_and_typography_sites(data, funcs),
    ),
    GroupSpec(
        name="cot-rendering",
        required=("stepContent", "thoughtBodyRows", "concatstring2", "stripMarkdownFormatting"),
        any_of=(),
        needs="palette-typography",
        resolve=lambda data, funcs, out, ver, strict: _resolve_cot_sites(data, funcs, out["palette-typography"][2]),
    ),
    GroupSpec(
        name="statusline-refresh",
        required=("userInputLoop", "triggerStatusLineUpdate", "StatusLineRunnerRun"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_statusline_refresh_sites(data, funcs),
    ),
    GroupSpec(
        name="tool-monitors",
        required=("isMonitorEnabled",),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_monitor_sites(data, funcs),
    ),
    GroupSpec(
        name="work-efficiently",
        required=("workEfficientlyShouldInclude", "workEfficientlyReminderHook"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_work_efficiently_sites(data, funcs),
    ),
    GroupSpec(
        name="subagent-models",
        required=("populatePlatformModels", "subagentModelsFromAvailable", "mapaccess2Faststr"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_subagent_model_sites(data, funcs),
    ),
    GroupSpec(
        name="color-scheme",
        required=("rendererStart", "rendererClose", "rendererFlush", "RequestBackgroundColor", "translateInputEvent"),
        any_of=(),
        needs="palette-typography",
        resolve=lambda data, funcs, out, ver, strict: _resolve_color_scheme_sites(
            data, funcs, (out["palette-typography"][3][0], out["palette-typography"][3][0] + 0x40)
        ),
    ),
    GroupSpec(
        name="command-elbow",
        required=("resolveStyles", "renderCommandOutput", "renderStyledLines", "renderOutputLines"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_command_elbow_sites(data, funcs),
    ),
    GroupSpec(
        name="spinner",
        required=(
            "halloweenInit0", "themeRegister", "halloweenInit", "halloweenRunningLight", "halloweenPaint",
            "renderPendingLight", "themerenderRunningLight", "themeRunningLightAt", "lipglossColor",
            "refreshActivityLabel", "concatstring2", "populateLayout", "pendingDecoration",
            "concatstring3", "runningLightWindow",
        ),
        any_of=(("pendingLineLayout", "pendingLineView"),),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_spinner_sites(data, funcs),
    ),
    GroupSpec(
        name="pending-line",
        required=(
            "refreshActivityLabel", "activityCandidate", "compactingLabel", "fmtDuration",
            "agentStateLabel", "timeSub", "timeSince", "convTstring", "convT64", "stringsRepeat",
            "halloweenPaint", "messageListViewportHeight", "managerStore", "currentModelLabel",
        ),
        any_of=(("pendingLineLayout", "pendingLineView"),),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_elapsed_sites(data, funcs),
    ),
    GroupSpec(
        name="live-thinking",
        required=(
            "dripFlush", "cutAtRuneBoundary", "logCtxlogf", "stepContent",
            "RenderRunningLight", "styleRender", "concatstring2", "activityCandidate",
            "isInFlightThinkingOnly",
        ),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_thinking_sites(data, funcs),
    ),
    GroupSpec(
        name="pending-verbs",
        required=("activityCandidate", "refreshActivityLabel", "halloweenPaint", "agentStateLabel"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_verb_sites(data, funcs),
    ),
    GroupSpec(
        name="tool-marks",
        required=(
            "halloweenPaint", "markTool", "markStatus", "markRunningDot", "markTask", "markSubagent",
            "markBackground", "markMilestone", "markWorkflowAgent", "markWorkflowCall", "markWorkflow",
        ),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_tool_mark_sites(data, funcs),
    ),
    GroupSpec(
        name="code-theme",
        required=(
            "halloweenInit", "codeBlockRender", "quickHighlight", "highlightCode",
            "sharedStyles", "newMarkdownInputs", "markdownCacheRender",
        ),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_code_theme_sites(data, funcs),
    ),
    GroupSpec(
        name="thought-grouping",
        required=("canUpgradeTrailingThought", "findLastToolGroup", "canMergeConsecutiveThoughts", "isThoughtOnlyGroup"),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_thought_grouping_sites(data, funcs),
    ),
    GroupSpec(
        name="thought-block",
        required=(
            "stepContent", "stringsJoin", "concatstring3", "fmtSprintf", "concatstring2",
            "styleRender", "convTstring", "collapsedThinkingSnippet", "fmtDuration",
            "stringsLastIndex", "stringsTrimSpace", "indexByteString", "stripMarkdownFormatting",
            "fitDetailText",
        ),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_thought_block_sites(data, funcs),
    ),
    GroupSpec(
        name="cache-keepalive",
        required=(
            "setToolResultRoleToUser", "ccpaGenerate", "keepAlivePings", "keepAlivesBeforeRequest",
            "trimLastBlock", "halloweenInit", "lipglossColor", "RequestBackgroundColor", "osGetenv",
            "scheduleNextPingLocked", "mapdeleteFaststr", "keepAlivesPing", "keepAlivesStopLocked",
            "BuildStatusLineData",
        ),
        any_of=((("buildGatewayHTTPRequest",), ("StreamGenerateContentFromGateway", "GenerateContentFromGateway")),),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_keepalive_sites(data, funcs),
    ),
    GroupSpec(
        name="prompt",
        required=(),
        any_of=(),
        needs=None,
        resolve=lambda data, funcs, out, ver, strict: _resolve_prompt_template_sites(data, ver, strict),
    ),
)

GROUP_REQUIRED_SYMBOLS: dict[str, tuple[str, ...]] = {spec.name: spec.required for spec in GROUP_SPECS}


def _resolve_groups(
    data: bytes | bytearray,
    version: str,
    strict: bool,
    *,
    funcs: dict[str, tuple[int, int]] | None = None,
) -> dict[str, object]:
    """Run every resolver with per-group symbol isolation, keeping each result or exception."""
    resolved_funcs = locate_symbols(data) if funcs is None else funcs
    out: dict[str, object] = {}

    for spec in GROUP_SPECS:
        if spec.needs is not None and isinstance(out[spec.needs], Exception):
            out[spec.name] = RuntimeError(f"not resolved: it builds on {spec.needs}, which failed")
            continue
        try:
            require_symbols(resolved_funcs, spec.required, spec.any_of)
            out[spec.name] = spec.resolve(data, resolved_funcs, out, version, strict)
        except Exception as exc:  # reported per group; resolve_patch_sites re-raises the first
            out[spec.name] = exc
    return out


def resolve_site_groups(
    data: bytes | bytearray,
    version: str,
    strict: bool = False,
    *,
    funcs: dict[str, tuple[int, int]] | None = None,
) -> dict[str, tuple[PatchSite, ...] | Exception]:
    """Each resolver's sites, or the exception that stopped it: a new release can move several anchors or symbols at once."""
    out = _resolve_groups(data, version, strict, funcs=funcs)
    flat = {
        "palette-typography": lambda r: (*r[0], *r[1]),
        "cot-rendering": lambda r: (*r[0], r[1]),
        "statusline-refresh": lambda r: (r,),
    }
    return {name: r if isinstance(r, Exception) else tuple(flat.get(name, tuple)(r)) for name, r in out.items()}


def resolve_patch_sites(data: bytes | bytearray, version: str, strict: bool = False) -> tuple[PatchSite, ...]:
    """Resolve every site in apply order.

    `strict` is for clean backups: every prompt template must match its pinned stock version.
    """
    out = _resolve_groups(data, version, strict)
    for result in out.values():
        if isinstance(result, Exception):
            raise result
    pal_pre, pal_post, _, _ = out["palette-typography"]
    cot_step_sites, cot_strip_site = out["cot-rendering"]
    return (
        *out["context-window"],
        *cot_step_sites,
        *pal_pre,
        out["statusline-refresh"],
        *pal_post,
        cot_strip_site,
        *out["tool-monitors"],
        *out["work-efficiently"],
        *out["subagent-models"],
        *out["color-scheme"],
        *out["command-elbow"],
        *out["spinner"],
        *out["pending-line"],
        *out["pending-verbs"],
        *out["tool-marks"],
        *out["code-theme"],
        *out["live-thinking"],
        *out["thought-grouping"],
        *out["thought-block"],
        *out["cache-keepalive"],
        *out["prompt"],
    )
