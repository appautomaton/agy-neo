"""Go pclntab symbol tables and per-group symbol lookup."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable

from .asm import GOPCLN_MAGIC_120, LC_SEGMENT_64, MH_MAGIC_64, VM_BASE
from .paths import _load_meta_cache, _save_meta_cache

TARGET_SYMBOLS: dict[str, str] = {
    "BuildStatusLineData": "google3/third_party/jetski/cli/store/store.BuildStatusLineData",
    "stepContent": "google3/third_party/jetski/cli/render/render.stepContent",
    "stripMarkdownFormatting": "google3/third_party/jetski/cli/render/render.stripMarkdownFormatting",
    "renderUserPrompt": "google3/third_party/jetski/cli/render/render.renderUserPrompt",
    "StickyPrompt": "google3/third_party/jetski/cli/render/render.StickyPrompt",
    "typesInit": "google3/third_party/jetski/cli/types/types.init",
    "resolveStyles": "google3/third_party/jetski/cli/render/render.resolveStyles",
    "userInputLoop": "google3/third_party/jetski/cli/store/store.(*Manager).userInputLoop",
    "triggerStatusLineUpdate": "google3/third_party/jetski/cli/store/store.(*Manager).triggerStatusLineUpdate",
    "StatusLineRunnerRun": "google3/third_party/jetski/cli/store/store.(*StatusLineRunner).Run",
    "SetTerminalBackground": "google3/third_party/jetski/cli/store/store.(*Manager).SetTerminalBackground",
    "RerenderAll": "google3/third_party/jetski/cli/store/store.(*Manager).RerenderAll",
    "pinHeader": "google3/third_party/jetski/cli/model/model.(*ConversationModel).pinHeader",
    "stickyPromptItem": "google3/third_party/jetski/cli/model/model.(*ConversationModel).stickyPromptItem",
    "stickyPromptAt": "google3/third_party/jetski/cli/model/model.(*ConversationModel).stickyPromptAt",
    "lipglossColor": "google3/third_party/golang/charm_land/lipgloss/v/v2/lipgloss.Color",
    "GetCheckpointConfig": "google3/third_party/jetski/cortex/utils/utils.GetCheckpointConfig",
    "applyFeatureProviderCheckpointOverrideConfig": "google3/third_party/jetski/cortex/config/config.applyFeatureProviderCheckpointOverrideConfig",
    "getMaxTokensForStep": "google3/third_party/jetski/cortex/chatconverters/chatconverters.(*TrajectoryChatConverter).getMaxTokensForStep",
    "stepToMessage": "google3/third_party/oneharness/internal/core/serializers/serializers.DefaultSerializer.stepToMessage",
    "rendererStart": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*cursedRenderer).start",
    "rendererClose": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*cursedRenderer).close",
    "rendererFlush": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*cursedRenderer).flush",
    "translateInputEvent": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*Program).translateInputEvent",
    "RequestBackgroundColor": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.RequestBackgroundColor",
    "renderCommandOutput": "google3/third_party/jetski/cli/render/render.renderCommandOutput",
    "renderStyledLines": "google3/third_party/jetski/cli/render/render.renderStyledLines",
    "renderOutputLines": "google3/third_party/jetski/cli/render/render.renderOutputLines",
    "pendingDecoration": "google3/third_party/jetski/cli/model/model.(*ConversationModel).pendingDecoration",
    "messageListViewportHeight": "google3/third_party/jetski/cli/model/model.(*ConversationModel).messageListViewportHeight",
    "managerStore": "google3/third_party/jetski/cli/store/store.(*Manager).Store",
    "currentModelLabel": "google3/third_party/jetski/cli/store/store.(*Manager).currentModelLabel",
    "runningLightWindow": "google3/third_party/jetski/cli/render/render.RunningLightWindow",
    "populateLayout": "google3/third_party/jetski/cli/model/model.(*ConversationModel).populateLayout",
    "activityCandidate": "google3/third_party/jetski/cli/model/model.(*ConversationModel).activityCandidate",
    "refreshActivityLabel": "google3/third_party/jetski/cli/model/model.(*ConversationModel).refreshActivityLabel",
    "compactingLabel": "google3/third_party/jetski/cli/model/model.compactingLabel",
    "agentStateLabel": "google3/third_party/jetski/cli/model/model.AgentState.Label",
    "fmtDuration": "google3/third_party/jetski/cli/render/render.fmtDuration",
    "stringsRepeat": "strings.Repeat",
    "stringsJoin": "strings.Join",
    "concatstring3": "runtime.concatstring3",
    "timeSince": "time.Since",
    "timeSub": "time.Time.Sub",
    "convT64": "runtime.convT64",
    "convTstring": "runtime.convTstring",
    "dripFlush": "google3/third_party/jetski/cli/store/store.(*textDrip).flush",
    "cutAtRuneBoundary": "google3/third_party/jetski/cli/store/store.cutAtRuneBoundary",
    "logCtxlogf": "google3/base/go/log.ctxlogf",
    "RenderRunningLight": "google3/third_party/jetski/cli/render/render.RenderRunningLight",
    "styleRender": "google3/third_party/golang/charm_land/lipgloss/v/v2/lipgloss.Style.Render",
    "concatstring2": "runtime.concatstring2",
    "canUpgradeTrailingThought": "google3/third_party/jetski/cli/store/store.canUpgradeTrailingThoughtToToolGroup",
    "findLastToolGroup": "google3/third_party/jetski/cli/store/store.findLastToolGroupAbsIdx",
    "canMergeConsecutiveThoughts": "google3/third_party/jetski/cli/store/store.canMergeConsecutiveThoughts",
    "isThoughtOnlyGroup": "google3/third_party/jetski/cli/store/store.isThoughtOnlyGroup",
    "collapsedThinkingSnippet": "google3/third_party/jetski/cli/render/render.collapsedThinkingSnippet",
    "fitDetailText": "google3/third_party/jetski/cli/render/render.fitDetailText",
    "indexByteString": "internal/bytealg.IndexByteString",
    "stringsLastIndex": "strings.LastIndex",
    "stringsTrimSpace": "strings.TrimSpace",
    "fmtSprintf": "fmt.Sprintf",
    "markTool": "google3/third_party/jetski/cli/render/render.toolMarker",
    "markStatus": "google3/third_party/jetski/cli/render/render.statusMarker",
    "markRunningDot": "google3/third_party/jetski/cli/render/render.RunningDot",
    "markTask": "google3/third_party/jetski/cli/render/render.StatusMarker",
    "markSubagent": "google3/third_party/jetski/cli/render/render.RenderSubagentItem",
    "markBackground": "google3/third_party/jetski/cli/render/render.RenderBackgroundCommandOutput",
    "markMilestone": "google3/third_party/jetski/cli/render/render.semanticMilestoneLines",
    "markWorkflowAgent": "google3/third_party/jetski/cli/render/render.workflowAgentRow",
    "markWorkflowCall": "google3/third_party/jetski/cli/render/render.workflowCallRow",
    "markWorkflow": "google3/third_party/jetski/cli/render/render.workflowMarker",
    "renderPendingLight": "google3/third_party/jetski/cli/model/model.(*ConversationModel).renderPendingLight",
    "themerenderRunningLight": "google3/third_party/jetski/cli/theme/themerender/themerender.RunningLight",
    "themeRunningLightAt": "google3/third_party/jetski/cli/theme/themerender/themerender.runningLightAt",
    "themeRegister": "google3/third_party/jetski/cli/theme/theme.Register",
    "halloweenInit": "google3/third_party/jetski/cli/theme/halloween/halloween.init",
    "halloweenInit0": "google3/third_party/jetski/cli/theme/halloween/halloween.init.0",
    "halloweenRunningLight": "google3/third_party/jetski/cli/theme/halloween/halloween.halloween.RunningLight",
    "halloweenPaint": "google3/third_party/jetski/cli/theme/halloween/halloween.paint",
    "setToolResultRoleToUser": "google3/third_party/jetski/language_server/code_assist_client/codeassistclient.setToolResultRoleToUser",
    "ccpaGenerate": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.(*Client).Generate",
    "keepAlivePings": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.keepAlivePings",
    "keepAlivesBeforeRequest": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.(*keepAlives).beforeRequest",
    "trimLastBlock": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.trimLastBlock",
    "scheduleNextPingLocked": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.(*keepAlives).scheduleNextPingLocked",
    "keepAlivesPing": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.(*keepAlives).ping",
    "keepAlivesStopLocked": "google3/third_party/jetski/language_server/modelapiccpa/modelapiccpa.(*keepAlives).stopLocked",
    "osGetenv": "os.Getenv",
    "mapdeleteFaststr": "runtime.mapdelete_faststr",
    "mapaccess2Faststr": "runtime.mapaccess2_faststr",
    "thoughtBodyRows": "google3/third_party/jetski/cli/render/render.thoughtBodyRows",
    "isInFlightThinkingOnly": "google3/third_party/jetski/cli/render/render.isInFlightThinkingOnly",
    "codeBlockRender": "google3/third_party/golang/charm_land/glamour/v/v2/ansi/ansi.(*CodeBlockElement).Render",
    "quickHighlight": "google3/third_party/golang/github_com/alecthomas/chroma/v/v2/quick/quick.Highlight",
    "highlightCode": "google3/third_party/jetski/cli/render/render.HighlightCode",
    "sharedStyles": "google3/third_party/jetski/cli/render/render.SharedStyles",
    "newMarkdownInputs": "google3/third_party/jetski/cli/render/render.newMarkdownInputs",
    "markdownCacheRender": "google3/third_party/jetski/cli/render/render.(*markdownCache).render",
    "isMonitorEnabled": "google3/gdm/security/agi_control/agent_monitoring/monitors/go/agent_monitoring.isMonitorEnabled",
    "workEfficientlyShouldInclude": "google3/third_party/jetski/cortex/mixins/mixins.(*WorkEfficientlySection).ShouldInclude",
    "workEfficientlyReminderHook": "google3/third_party/jetski/cortex/core/prehooks/prehooks.newWorkEfficientlyReminderHook.func1",
    "populatePlatformModels": "google3/third_party/jetski/cortex/cortex.(*CascadeManager).populatePlatformModels",
    "subagentModelsFromAvailable": "google3/third_party/jetski/cortex/modelutils/modelutils.SubagentModelsFromAvailableModels",
}

# Version-variant symbols:
# - v1.5.14 unified Gateway request building and renamed glamourStyleForScheme -> glamourStyle
# - v1.5.16 extracted fitPendingLabel, added activityPhaseTimer.elapsed, and added renderStepRow
# - v1.5.19 refactored pendingLineView -> pendingLineLayout (returning scroll-indicator span)
OPTIONAL_SYMBOLS: dict[str, str] = {
    "pendingLineLayout": "google3/third_party/jetski/cli/model/model.(*ConversationModel).pendingLineLayout",
    "pendingLineView": "google3/third_party/jetski/cli/model/model.(*ConversationModel).pendingLineView",
    "glamourStyle": "google3/third_party/jetski/cli/render/render.glamourStyle",
    "glamourStyleForScheme": "google3/third_party/jetski/cli/render/render.glamourStyleForScheme",
    "buildGatewayHTTPRequest": "google3/third_party/jetski/language_server/code_assist_client/codeassistclient.(*CodeAssistClient).buildGatewayHTTPRequest",
    "StreamGenerateContentFromGateway": "google3/third_party/jetski/language_server/code_assist_client/codeassistclient.(*CodeAssistClient).StreamGenerateContentFromGateway",
    "GenerateContentFromGateway": "google3/third_party/jetski/language_server/code_assist_client/codeassistclient.(*CodeAssistClient).GenerateContentFromGateway",
    "fitPendingLabel": "google3/third_party/jetski/cli/model/model.fitPendingLabel",
    "activityPhaseTimerElapsed": "google3/third_party/jetski/cli/model/model.(*activityPhaseTimer).elapsed",
    "markStepRow": "google3/third_party/jetski/cli/model/model.renderStepRow",
    "markSwarmRow": "google3/third_party/jetski/cli/swarm/swarm.StatusRow",
}


def all_known_symbols() -> dict[str, str]:
    """Combined lookup table of every symbol key recognized by any resolver."""
    return {**TARGET_SYMBOLS, **OPTIONAL_SYMBOLS}


def locate_symbols(data: bytes | bytearray) -> dict[str, tuple[int, int]]:
    """Parse Mach-O `__lrodata_gopcln` once and return `{key: (start, end)}` for every symbol present.

    Unlike `locate_target_functions`, missing symbols are omitted rather than raising, so each
    resolver group can check only the symbols it actually needs and fail in isolation.
    """
    all_syms = all_known_symbols()
    sym_sig = hashlib.blake2b(repr(sorted(all_syms.items())).encode(), digest_size=4).hexdigest()
    hdr_key = f"{len(data)}:{hashlib.blake2b(bytes(data[:4096]), digest_size=8).hexdigest()}:{sym_sig}"
    cache = _load_meta_cache()
    cached_bounds = cache.get("pclntab", {}).get(hdr_key)
    all_keys = set(all_syms)
    if isinstance(cached_bounds, dict) and set(cached_bounds) == all_keys:
        return {k: (v[0], v[1]) for k, v in cached_bounds.items() if v is not None}

    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise RuntimeError(f"Not a 64-bit Mach-O binary (magic={hex(magic)})")

    pos = 32
    text_addr: int | None = None
    gopcln_off: int | None = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            sect_pos = pos + 72
            for _ in range(nsects):
                sectname = bytes(data[sect_pos : sect_pos + 16]).rstrip(b"\x00").decode("ascii", "replace")
                addr, _, offset = struct.unpack_from("<QQI", data, sect_pos + 32)
                if sectname == "__text":
                    text_addr = addr
                elif sectname in ("__lrodata_gopcln", "__gopclntab"):
                    gopcln_off = offset
                sect_pos += 80
        pos += cmdsize

    if text_addr is None or gopcln_off is None:
        raise RuntimeError("Mach-O __text or __lrodata_gopcln section not found")

    pcln_magic = struct.unpack_from("<I", data, gopcln_off)[0]
    if pcln_magic != GOPCLN_MAGIC_120:
        raise RuntimeError(f"Unsupported Go pclntab magic: {hex(pcln_magic)}")

    nfunctab = struct.unpack_from("<Q", data, gopcln_off + 8)[0]
    funcnametab_off = gopcln_off + struct.unpack_from("<Q", data, gopcln_off + 32)[0]
    functab_off = gopcln_off + struct.unpack_from("<Q", data, gopcln_off + 64)[0]

    reverse_map = {sym.encode("utf-8"): key for key, sym in all_syms.items()}
    found: dict[str, tuple[int, int]] = {}
    text_file_base = text_addr - VM_BASE

    for i in range(nfunctab):
        entry_off, fdata_off = struct.unpack_from("<II", data, functab_off + i * 8)
        name_rel = struct.unpack_from("<i", data, functab_off + fdata_off + 4)[0]
        name_start = funcnametab_off + name_rel
        name_end = data.find(b"\x00", name_start)
        key = reverse_map.get(bytes(data[name_start:name_end]))
        if key is not None:
            next_entry_off = struct.unpack_from("<I", data, functab_off + (i + 1) * 8)[0]
            found[key] = (text_file_base + entry_off, text_file_base + next_entry_off)
            if len(found) == len(reverse_map):
                break

    cache.setdefault("pclntab", {})[hdr_key] = {
        k: ([found[k][0], found[k][1]] if k in found else None) for k in all_keys
    }
    _save_meta_cache(cache)
    return found


def locate_target_functions(
    data: bytes | bytearray, required: Iterable[str] | None = None
) -> dict[str, tuple[int, int]]:
    """Locate symbols via Mach-O `__lrodata_gopcln` and verify `required` (default: all `TARGET_SYMBOLS`)."""
    found = locate_symbols(data)
    need = set(TARGET_SYMBOLS) if required is None else set(required)
    missing = need - set(found)
    if missing:
        raise RuntimeError(f"Missing target Go symbols in binary: {sorted(missing)}")
    return found


def require_symbols(
    funcs: dict[str, tuple[int, int]],
    required: tuple[str, ...] = (),
    any_of: tuple[tuple[str | tuple[str, ...], ...], ...] = (),
) -> None:
    """Validate that a resolver group's required symbols (and variant alternatives) are present."""
    missing = [k for k in required if k not in funcs]
    for variants in any_of:
        satisfied = False
        for alt in variants:
            keys = (alt,) if isinstance(alt, str) else alt
            if all(k in funcs for k in keys):
                satisfied = True
                break
        if not satisfied:
            desc = " | ".join(v if isinstance(v, str) else "+".join(v) for v in variants)
            missing.append(f"({desc})")
    if missing:
        raise RuntimeError(f"Missing required Go symbol(s): {', '.join(missing)}")
