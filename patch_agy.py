#!/usr/bin/env python3
"""Version-adaptive patcher for agy (darwin/arm64): TUI sites and system prompt templates.

TUI sites: parses the Mach-O __lrodata_gopcln symbol table to locate target Go functions,
anchors each site via invariant preceding instruction sequences, and computes PC-relative
ARM64 `bl` displacements automatically across versions.

Prompt templates: writes every file in templates/v<version>/system_prompts/, the templates we
change, for the version the binary reports, once each original matches its recorded digest
(prompt_templates.py).

Every --apply rebuilds from the clean agy.v<version>.orig backup and re-signs the binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
from typing import NamedTuple

import prompt_templates


VM_BASE = 0x100000000
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
GOPCLN_MAGIC_120 = 0xFFFFFFF1

TARGET_SYMBOLS: dict[str, str] = {
    "ModelMaxTokens": "google3/third_party/jetski/cli/store/store.(*Store).ModelMaxTokens",
    "ContextWindowChoice": "google3/third_party/jetski/cli/store/store.(*Store).ContextWindowChoice",
    "ContextWindow": "google3/third_party/jetski/cli/store/store.(*Store).ContextWindow",
    "BuildStatusLineData": "google3/third_party/jetski/cli/store/store.BuildStatusLineData",
    "collectStats": "google3/third_party/jetski/cli/model/model.ContextModel.collectStats",
    "offersContextWindow": "google3/third_party/jetski/cli/model/model.SelectorModel.offersContextWindow",
    "stepContent": "google3/third_party/jetski/cli/render/render.stepContent",
    "stripMarkdownFormatting": "google3/third_party/jetski/cli/render/render.stripMarkdownFormatting",
    "renderUserPrompt": "google3/third_party/jetski/cli/render/render.renderUserPrompt",
    "StickyPrompt": "google3/third_party/jetski/cli/render/render.StickyPrompt",
    "typesInit": "google3/third_party/jetski/cli/types/types.init",
    "resolveStyles": "google3/third_party/jetski/cli/render/render.resolveStyles",
    "glamourStyleForScheme": "google3/third_party/jetski/cli/render/render.glamourStyleForScheme",
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
    "memequal": "runtime.memequal",
    "geminiWireMap": "google3/third_party/jetski/models/geminimodels/geminimodels.map.init.0",
    "geminiCatalog": "google3/third_party/jetski/models/geminimodels/geminimodels.Catalog",
    "geminiDetails": "google3/third_party/jetski/models/geminimodels/geminimodels.details",
    "defaultModelsInit": "google3/third_party/jetski/models/defaults/defaultmodels.init",
    "gemini36Flash": "google3/third_party/jetski/models/defaults/defaultmodels.Gemini36Flash",
    "gemini37Flash": "google3/third_party/jetski/models/defaults/defaultmodels.Gemini37Flash",
    "geminiModelInfo": "google3/third_party/jetski/models/defaults/defaultmodels.GeminiModelInfo",
    "unsupportedThinkingLevel": "google3/third_party/jetski/models/defaults/defaultmodels.unsupportedThinkingLevel",
    "toGenaiThinkingLevel": "google3/third_party/jetski/model_api/backends/components/genairequest/genairequest.toGenaiThinkingLevel",
    "rendererStart": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*cursedRenderer).start",
    "rendererClose": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*cursedRenderer).close",
    "rendererFlush": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*cursedRenderer).flush",
    "translateInputEvent": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.(*Program).translateInputEvent",
    "RequestBackgroundColor": "google3/third_party/golang/charm_land/bubbletea/v/v2/tea.RequestBackgroundColor",
    "renderCommandOutput": "google3/third_party/jetski/cli/render/render.renderCommandOutput",
    "renderStyledLines": "google3/third_party/jetski/cli/render/render.renderStyledLines",
    "renderOutputLines": "google3/third_party/jetski/cli/render/render.renderOutputLines",
    "renderRunningLightInternal": "google3/third_party/jetski/cli/render/render.renderRunningLightInternal",
    "pendingLineView": "google3/third_party/jetski/cli/model/model.(*ConversationModel).pendingLineView",
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
}

# Sites #38-#40: the Gemini API wire model for Carbon, and the map entries that carry it. They retire
# once upstream maps Carbon itself (v1.5.7), which frees their donor entries for Sites #55a-#55p.
GEMINI_WIRE_MODEL = "gemini-4-carbon"
GEMINI_WIRE_DONOR = "gemini-3.6-flash"  # CLIProxyAPI does not route it

# 1M-window models that upstream `backend.ContextWindowSelectable` (["Gemini 4 Argon"]) omits. Sites
# #1a-#2b admit every base name with this prefix (Carbon, Hydrogen); it must fit their 16-byte slot.
CONTEXT_WINDOW_EXTRA_FAMILY = b"Gemini 4 "

# Sites #55a-#55p: Gemini 4 Hydrogen as a built-in model, as Cloud Code's fetchAvailableModels serves it
# under OAuth: `gemini-4-hydrogen-<effort>`, Model enum MODEL_PLACEHOLDER_M5xx (1000 + xx), thinking level.
# Each effort takes the catalog slots of a Flash model CLIProxyAPI does not route.
HYDROGEN_FAMILY = "Gemini 4 Hydrogen"
HYDROGEN_WIRE_MODEL = "gemini-4-hydrogen"
HYDROGEN_EFFORTS: dict[str, tuple[int, int, str, str]] = {  # effort: (thinking level, enum, label, donor ID)
    "low": (1, 1527, "Gemini 4 Hydrogen (Low)", "gemini-3.6-flash-low"),
    "medium": (2, 1526, "Gemini 4 Hydrogen (Medium)", "gemini-3.6-flash-medium"),
    "high": (3, 1525, "Gemini 4 Hydrogen (High)", "gemini-3.6-flash-high"),
    "xhigh": (100, 1528, "Gemini 4 Hydrogen (XHigh)", "gemini-3.7-flash-low"),
}

# Self-contained 140-byte ARM64 leaf resolver placed in store.(*Store).ModelMaxTokens.
# The `ldr x6, [sp, #imm]` loads at +0x0 (for `store.BuildStatusLineData`: 0x338 in v1.5.0-v1.5.2, 0x348 in v1.5.3+)
# and at +0x78 (for `model.ContextModel.collectStats`: 0x128 in v1.5.0-v1.5.3, 0x140 in v1.5.5+) are synthesized dynamically,
# and so are the `s.settings` (+0x10 through v1.5.5, +0x0 in v1.5.6) and `.ContextWindow` loads at core +24 and +32.
MODEL_MAX_TOKENS_PATCHED_CORE = bytes.fromhex(
    "e10304aa074888d2e701a0f29f00076bcb010054a60100b4c60840f9"
    "660100b4c61c47a9ff1000f101010054c7004039ffc80071c0000054ffd40071"
    "e0000054ffe4007100010054c0035fd601009dd26100a0f2c0035fd601009ad2"
    "e100a0f2c0035fd6017497d2a101a0f2c0035fd6e8031eaa"
)
MODEL_MAX_TOKENS_PATCHED_EPILOGUE = bytes.fromhex("e10304aae2ffff97e00301aa00015fd6")
MODEL_MAX_TOKENS_ORIG_HEAD = bytes.fromhex(
    "900b40f9ff6330eb69040054fe0f1ef8fd831ff8fd2300d1e11b00f9033440f9"
    "830000b4e10b03a9631040a907000014e0031faafd835ff8fe0742f8c0035fd6"
    "63800291840400d19f0000f12dffff54601442a95f0005eb41ffff54e48f00a9"
    "e20305aa"
)
MODEL_MAX_TOKENS_ORIG_TAIL = bytes.fromhex(
    "00010036e30b40f9606080b91f000071ecfdff54e10b43a9"
    "e40740f9efffff17e10b43a9"
)


class PatchSite(NamedTuple):
    domain: str
    name: str
    va: int
    offset: int
    original: bytes | None  # None when variable bytes (e.g. external bl) require custom matcher
    patched: bytes


LIPGLOSS_COPY_LOOP_X5_X4_ORIG = bytes.fromhex(
    "580180d2b044c1ac904481acb044c1ac904481ac180700d178ffffb5b90040f9990000f9"
)


HOME = pathlib.Path.home()
REPO = pathlib.Path(__file__).resolve().parent
GEMINI_WRAPPER_TARGET = HOME / ".gemini/bin/agy"
DEFAULT_BINARIES: tuple[pathlib.Path, ...] = (HOME / ".local/bin/agy", GEMINI_WRAPPER_TARGET)
HUB_WRAPPER_SOURCE = REPO / "hub-wrapper.sh"
WRAPPER_REPO_MARK = b"@AGY_NEO_REPO@"


def rendered_wrapper() -> bytes:
    """hub-wrapper.sh as installed: the repo's path, wherever it is, in place of its placeholder."""
    return HUB_WRAPPER_SOURCE.read_bytes().replace(WRAPPER_REPO_MARK, str(REPO).encode())
STATUSLINE_SOURCE = REPO / "statusline.sh"
STATUSLINE_TARGET = HOME / ".gemini/antigravity-cli/statusline.sh"

SETTINGS_PATH = HOME / ".gemini/antigravity-cli/settings.json"
CACHE_DIR = REPO / ".cache"
META_CACHE_PATH = CACHE_DIR / "binary_meta.json"
VALID_PRESETS = ("Default", "256K", "512K", "900K")


def _load_meta_cache() -> dict:
    try:
        if META_CACHE_PATH.exists():
            return json.loads(META_CACHE_PATH.read_text())
    except Exception:
        pass
    return {"files": {}, "pclntab": {}}


def _save_meta_cache(cache: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = META_CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, indent=2) + "\n")
        tmp.replace(META_CACHE_PATH)
    except Exception:
        pass


def encode_adr(pc_va: int, target_va: int, rd: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative `adr` instruction."""
    delta = target_va - pc_va
    immlo = (delta & 0x3) << 29
    immhi = ((delta >> 2) & 0x7FFFF) << 5
    return struct.pack("<I", 0x10000000 | immlo | immhi | (rd & 0x1F))


def encode_adrp(pc_va: int, target_va: int, rd: int) -> bytes:
    """Encode a 32-bit ARM64 page-relative `adrp` instruction."""
    page_delta = ((target_va & ~0xFFF) - (pc_va & ~0xFFF)) >> 12
    immlo = (page_delta & 0x3) << 29
    immhi = ((page_delta >> 2) & 0x7FFFF) << 5
    return struct.pack("<I", 0x90000000 | immlo | immhi | (rd & 0x1F))


def encode_adrp_add(pc_va: int, target_va: int, rd: int) -> bytes:
    """Encode an 8-byte `adrp rd, page; add rd, rd, #off` pair."""
    imm12 = target_va & 0xFFF
    add_insn = struct.pack("<I", 0x91000000 | (imm12 << 10) | ((rd & 0x1F) << 5) | (rd & 0x1F))
    return encode_adrp(pc_va, target_va, rd) + add_insn


def decode_adrp_add(data: bytes | bytearray, off: int) -> int:
    """Decode an `adrp + add` pair at file offset `off` to its target VA."""
    w0, w1 = struct.unpack_from("<II", data, off)
    immlo = (w0 >> 29) & 0x3
    immhi = (w0 >> 5) & 0x7FFFF
    page_delta = (immhi << 2) | immlo
    if page_delta & (1 << 20):
        page_delta -= 1 << 21
    page_va = ((VM_BASE + off) & ~0xFFF) + (page_delta << 12)
    imm12 = (w1 >> 10) & 0xFFF
    return page_va + imm12


def encode_b(pc_va: int, target_va: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative unconditional `b` instruction."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned b target: {hex(pc_va)} -> {hex(target_va)}")
    imm26 = (delta // 4) & 0x03FFFFFF
    return struct.pack("<I", 0x14000000 | imm26)


def encode_bl(pc_va: int, target_va: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative `bl` instruction."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned bl target: {hex(pc_va)} -> {hex(target_va)}")
    imm26 = (delta // 4) & 0x03FFFFFF
    return struct.pack("<I", 0x94000000 | imm26)


def encode_b_ne(pc_va: int, target_va: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative `b.ne` instruction."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned b.ne target: {hex(pc_va)} -> {hex(target_va)}")
    return struct.pack("<I", 0x54000001 | (((delta // 4) & 0x7FFFF) << 5))


def encode_b_eq(pc_va: int, target_va: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative `b.eq` instruction."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned b.eq target: {hex(pc_va)} -> {hex(target_va)}")
    return struct.pack("<I", 0x54000000 | (((delta // 4) & 0x7FFFF) << 5))


COND_EQ, COND_LO, COND_HI = 0x0, 0x3, 0x8


def encode_b_cond(pc_va: int, target_va: int, cond: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative `b.<cond>` instruction."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned b.cond target: {hex(pc_va)} -> {hex(target_va)}")
    return struct.pack("<I", 0x54000000 | (((delta // 4) & 0x7FFFF) << 5) | cond)


def encode_movz(rd: int, imm16: int) -> bytes:
    """Encode `movz x<rd>, #imm16`."""
    if not 0 <= imm16 < 1 << 16:
        raise ValueError(f"movz immediate out of range: {imm16}")
    return struct.pack("<I", 0xD2800000 | (imm16 << 5) | rd)


def encode_tbz_w0_bit0(pc_va: int, target_va: int) -> bytes:
    """Encode `tbz w0, #0, target` (branch when a returned Go bool is false)."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned tbz target: {hex(pc_va)} -> {hex(target_va)}")
    return struct.pack("<I", 0x36000000 | (((delta // 4) & 0x3FFF) << 5))


def decode_tbnz_target(data: bytes | bytearray, off: int, label: str) -> int:
    """Decode the target VA of a 64-bit-register `tbnz` (0xB7000000) at file offset `off`."""
    (insn,) = struct.unpack_from("<I", data, off)
    if (insn & 0xFF000000) != 0xB7000000:
        raise RuntimeError(f"Expected tbnz for {label} at {hex(VM_BASE + off)}, got {hex(insn)}")
    imm14 = (insn >> 5) & 0x3FFF
    if imm14 & (1 << 13):
        imm14 -= 1 << 14
    return (VM_BASE + off) + (imm14 << 2)


def build_selectable_matcher(stub_va: int, len_reg: int, hit_va: int, miss_va: int, memequal_va: int) -> bytes:
    """44 bytes: `goto name.startswith(CONTEXT_WINDOW_EXTRA_FAMILY) ? hit : miss`, with name in (x0, x<len_reg>).

    Seven instructions followed by the NUL-padded literal they compare against. The call mirrors
    the whitelist loop's own `runtime.memequal(x0, x1, x2)`; every register it clobbers is reloaded
    on both exits.
    """
    n = len(CONTEXT_WINDOW_EXTRA_FAMILY)
    if n > 16:
        raise ValueError(f"CONTEXT_WINDOW_EXTRA_FAMILY exceeds its 16-byte literal slot: {n} bytes")
    code = (
        struct.pack("<I", 0xF100001F | (n << 10) | (len_reg << 5))  # cmp x<len_reg>, #n
        + encode_b_cond(stub_va + 4, miss_va, COND_LO)
        + encode_adr(stub_va + 8, stub_va + 28, 1)  # x1 = literal
        + struct.pack("<I", 0xD2800002 | (n << 5))  # mov x2, #n
        + encode_bl(stub_va + 16, memequal_va)
        + encode_tbz_w0_bit0(stub_va + 20, miss_va)
        + encode_b(stub_va + 24, hit_va)
    )
    return code + CONTEXT_WINDOW_EXTRA_FAMILY.ljust(16, b"\x00")


def decode_branch_target(data: bytes | bytearray, off: int, expected_opcode: int, label: str) -> int:
    """Decode the target VA of a 32-bit ARM64 `b` (0x14000000) or `bl` (0x94000000) at file offset `off`."""
    (insn,) = struct.unpack_from("<I", data, off)
    if (insn & 0xFC000000) != expected_opcode:
        raise RuntimeError(f"Expected branch {hex(expected_opcode)} for {label} at {hex(VM_BASE + off)}, got {hex(insn)}")
    imm26 = insn & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= 1 << 26
    return (VM_BASE + off) + (imm26 << 2)


def fold_lipgloss_copy_x5_x4(attr_mask: int) -> bytes:
    """Fold a 36B 2x-unrolled `Styles` NEON copy loop (`x5 -> x4`) to set lipgloss `s.props`/`s.attrs` (`attr_mask`)."""
    mov_x24_attr = struct.pack("<I", 0xD2800018 | ((attr_mask & 0xFFFF) << 5))
    return mov_x24_attr + bytes.fromhex(
        "b80000f9b81c00f9980280d2b044c1ac904481ac180700d1b8ffffb59f0000f9"
    )


def locate_target_functions(data: bytes | bytearray) -> dict[str, tuple[int, int]]:
    """Parse Mach-O __lrodata_gopcln to return {key: (start_offset, end_offset)}, cached by Mach-O header digest."""
    hdr_key = f"{len(data)}:{hashlib.blake2b(bytes(data[:4096]), digest_size=8).hexdigest()}"
    cache = _load_meta_cache()
    cached_bounds = cache.get("pclntab", {}).get(hdr_key)
    if isinstance(cached_bounds, dict) and set(cached_bounds) == set(TARGET_SYMBOLS):
        return {k: (v[0], v[1]) for k, v in cached_bounds.items()}

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

    reverse_map = {sym.encode("utf-8"): key for key, sym in TARGET_SYMBOLS.items()}
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
            if len(found) == len(TARGET_SYMBOLS):
                break

    missing = set(TARGET_SYMBOLS) - set(found)
    if missing:
        raise RuntimeError(f"Missing target Go symbols in binary: {sorted(missing)}")
    cache.setdefault("pclntab", {})[hdr_key] = {k: [v[0], v[1]] for k, v in found.items()}
    _save_meta_cache(cache)
    return found


def find_unique_anchor(data: bytes | bytearray, func_bounds: tuple[int, int], anchor_pre: bytes, label: str) -> int:
    """Locate the unique instruction offset immediately following `anchor_pre` inside `func_bounds`."""
    start, end = func_bounds
    first = data.find(anchor_pre, start, end)
    if first == -1:
        raise RuntimeError(f"Anchor not found for {label} in {hex(start)}..{hex(end)}")
    second = data.find(anchor_pre, first + 1, end)
    if second != -1:
        raise RuntimeError(f"Ambiguous anchor for {label}: matches at {hex(first)} and {hex(second)}")
    return first + len(anchor_pre)


# `ldr Xt, [Xn, #imm]` with the offset masked out. Struct fields move between releases (v1.5.6 grew
# ConversationModel by 0x20 and the store's model by 0x158), so an anchor that loads a field should
# match the load, not the field's offset.
LDR_X_ANY_OFFSET = 0xFFC003FF


def ldr_x(rt: int, rn: int) -> int:
    return 0xF9400000 | (rn << 5) | rt


def find_unique_words(
    data: bytes | bytearray, func_bounds: tuple[int, int], words: tuple[tuple[int, int], ...], label: str
) -> int:
    """Like `find_unique_anchor`, for instruction words given as `(value, mask)` pairs."""
    start, end = func_bounds
    matches = [
        off
        for off in range(start, end - 4 * len(words) + 1, 4)
        if all(
            struct.unpack_from("<I", data, off + 4 * i)[0] & mask == value
            for i, (value, mask) in enumerate(words)
        )
    ]
    if len(matches) != 1:
        raise RuntimeError(f"Expected one anchor for {label} in {hex(start)}..{hex(end)}, found {len(matches)}")
    return matches[0] + 4 * len(words)


def branch_target(word: int, off: int) -> int | None:
    """Return the file offset an ARM64 b/bl/b.cond/cbz/cbnz/tbz/tbnz at `off` jumps to, else None."""
    if word >> 26 in (0x05, 0x25):  # b, bl
        imm, bits = word & 0x3FFFFFF, 26
    elif word & 0xFF000010 == 0x54000000 or (word >> 25) & 0x3F == 0x1A:  # b.cond, cbz/cbnz
        imm, bits = (word >> 5) & 0x7FFFF, 19
    elif (word >> 25) & 0x3F == 0x1B:  # tbz/tbnz
        imm, bits = (word >> 5) & 0x3FFF, 14
    else:
        return None
    if imm & (1 << (bits - 1)):
        imm -= 1 << bits
    return off + 4 * imm


def assert_unreachable(
    data: bytes | bytearray, func_bounds: tuple[int, int], span: tuple[int, int], label: str
) -> None:
    """Refuse a code cave that any branch from elsewhere in its function can reach."""
    start, end = func_bounds
    for off in range(start, end, 4):
        if span[0] <= off < span[1]:
            continue
        target = branch_target(struct.unpack_from("<I", data, off)[0], off)
        if target is not None and span[0] <= target < span[1]:
            raise RuntimeError(f"{label}: {hex(VM_BASE + off)} branches into it at {hex(VM_BASE + target)}")


def resolve_build_statusline_store_sp_imm12(data: bytes | bytearray, func_bounds: tuple[int, int]) -> int:
    """Extract the 12-bit unsigned stack offset from `str x0, [sp, #imm]` in BuildStatusLineData's prologue."""
    start, end = func_bounds
    for off in range(start, min(start + 64, end), 4):
        (insn,) = struct.unpack_from("<I", data, off)
        if (insn & 0xFFC003FF) == 0xF90003E0:
            return (insn >> 10) & 0xFFF
    raise RuntimeError(f"Prologue `str x0, [sp, #imm]` not found in BuildStatusLineData at {hex(start)}")


def resolve_collect_stats_store_sp_imm12(data: bytes | bytearray, func_bounds: tuple[int, int]) -> int:
    """Extract the 12-bit unsigned stack offset from `str x3, [sp, #imm]` in ContextModel.collectStats."""
    start, end = func_bounds
    for off in range(start, min(start + 0x120, end), 4):
        (insn,) = struct.unpack_from("<I", data, off)
        if (insn & 0xFFC003FF) == 0xF90003E3:
            return (insn >> 10) & 0xFFF
    raise RuntimeError(f"`str x3, [sp, #imm]` not found in ContextModel.collectStats at {hex(start)}")


def resolve_settings_context_window_loads(
    data: bytes | bytearray, func_bounds: tuple[int, int]
) -> tuple[bytes, bytes]:
    """Return the resolver's `ldr x6, [x6, #settings]` and `ldp x6, x7, [x6, #ContextWindow]`.

    `(*Store).ContextWindowChoice` reads `s.settings.ContextWindow` with `ldr x2, [x0, #a]; cbz x2;
    ldp x0, x1, [x2, #b]`. The resolver walks the same chain from x6, so it takes `a` and `b` from
    there: v1.5.6 moved `settings` from +0x10 to +0x0.
    """
    start, _ = func_bounds
    ldr, ldp = struct.unpack_from("<I", data, start + 0x18)[0], struct.unpack_from("<I", data, start + 0x20)[0]
    ldp_x_any_offset, ldp_x0_x1_x2 = 0xFFC07FFF, 0xA9400440
    if ldr & LDR_X_ANY_OFFSET != ldr_x(2, 0) or ldp & ldp_x_any_offset != ldp_x0_x1_x2:
        raise RuntimeError(f"ContextWindowChoice no longer reads s.settings.ContextWindow as expected at {hex(start)}")
    ldr_x6 = (ldr & ~0x3FF) | (6 << 5) | 6
    ldp_x6_x7 = (ldp & ~0x7FFF) | (7 << 10) | (6 << 5) | 6
    return struct.pack("<I", ldr_x6), struct.pack("<I", ldp_x6_x7)


def _resolve_context_window_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[PatchSite, ...]:
    """Sites #1-#7, #1a-#2b & #7a-#7d: Context window presets (`256K`/`512K`/`900K`), Cortex checkpointer unlock, and statusline accounting."""
    mmt_off, _ = funcs["ModelMaxTokens"]
    mmt_va = VM_BASE + mmt_off
    choice_off, _ = funcs["ContextWindowChoice"]
    choice_va = VM_BASE + choice_off

    bs_sp_imm12 = resolve_build_statusline_store_sp_imm12(data, funcs["BuildStatusLineData"])
    cs_sp_imm12 = resolve_collect_stats_store_sp_imm12(data, funcs["collectStats"])
    bs_ldr_x5 = struct.pack("<I", 0xF94003E5 | (bs_sp_imm12 << 10))
    bs_ldr_x6 = struct.pack("<I", 0xF94003E6 | (bs_sp_imm12 << 10))
    cs_ldr_x6 = struct.pack("<I", 0xF94003E6 | (cs_sp_imm12 << 10))
    mmt_core = bytearray(MODEL_MAX_TOKENS_PATCHED_CORE)
    mmt_core[24:28], mmt_core[32:36] = resolve_settings_context_window_loads(data, funcs["ContextWindowChoice"])
    mmt_patched = bs_ldr_x6 + mmt_core + cs_ldr_x6 + MODEL_MAX_TOKENS_PATCHED_EPILOGUE

    # 1. store.(*Store).ContextWindow -> (*Store).ContextWindowChoice
    s1_off = find_unique_anchor(
        data,
        funcs["ContextWindow"],
        bytes.fromhex("e0031faa34ffff97810100b51f2003d5"),
        "Site 1 (ContextWindow)",
    )
    s1_va = VM_BASE + s1_off
    s1_patched = bytes.fromhex("e04740f9") + encode_bl(s1_va + 4, choice_va) + bytes.fromhex("08000014")
    # `ldr x2, [sp, #0x88]; ldr x2, [x2, #field]; cbz x2`, where the field moved from 0xb8 to 0x58 in v1.5.6.
    # A patched binary holds a `bl` there instead, and reports through `s1_patched`.
    (s1_field_ldr,) = struct.unpack_from("<I", data, s1_off + 4)
    if s1_field_ldr & LDR_X_ANY_OFFSET != ldr_x(2, 2):
        s1_field_ldr = 0xF9405C42
    s1_orig = bytes.fromhex("e24740f9") + struct.pack("<I", s1_field_ldr) + bytes.fromhex("620100b4")

    # 2. model.SelectorModel.offersContextWindow -> return true
    # The anchor stops before `mov x0, #-1; tbnz`, since Site #2a rewrites the mov.
    s2_off = (
        find_unique_anchor(
            data,
            funcs["offersContextWindow"],
            bytes.fromhex("e0e35ef902000014"),
            "Site 2 (offersContextWindow)",
        )
        + 8
    )
    s2_va = VM_BASE + s2_off

    # 1a-2b. Admit the CONTEXT_WINDOW_EXTRA_FAMILY where each function misses the ContextWindowSelectable
    # loop. The miss writes `mov x0, #-1` just before `tbnz x0, #63, <miss>`; the entry branches into
    # a matcher instead, which rejoins after the tbnz on a hit and at its target otherwise. Each
    # matcher sits 0x34 past its Site #1/#2, in code those sites leave unreachable.
    memequal_va = VM_BASE + funcs["memequal"][0]
    s1a_off = find_unique_anchor(
        data, funcs["ContextWindow"], bytes.fromhex("e01f40f902000014"), "Site 1a (ContextWindow whitelist miss)"
    )
    s2a_off = s2_off - 8
    s1b_off, s2b_off = s1_off + 0x34, s2_off + 0x34
    s1a_va, s1b_va, s2a_va, s2b_va = (VM_BASE + o for o in (s1a_off, s1b_off, s2a_off, s2b_off))
    s1b_patched = build_selectable_matcher(
        s1b_va, 1, s1a_va + 8, decode_tbnz_target(data, s1a_off + 4, "Site 1a"), memequal_va
    )
    s2b_patched = build_selectable_matcher(
        s2b_va, 2, s2a_va + 8, decode_tbnz_target(data, s2a_off + 4, "Site 2a"), memequal_va
    )

    # 3. store.(*Store).ModelMaxTokens -> effective context window limit resolver
    s3_off = mmt_off
    s3_va = mmt_va

    # 4. store.BuildStatusLineData -> effective context window denominator
    s4_off = find_unique_anchor(
        data,
        funcs["BuildStatusLineData"],
        bytes.fromhex("e65f40f9e77b40f9e5ffff17e0c740f9"),
        "Site 4 (BuildStatusLineData denominator)",
    )
    s4_va = VM_BASE + s4_off
    s4_patched = encode_bl(s4_va, mmt_va)

    # 5. store.BuildStatusLineData -> disable exceeds_200k_tokens false alarm
    s5_off = find_unique_anchor(
        data,
        funcs["BuildStatusLineData"],
        bytes.fromhex("e13f40f902a881d26200a0f23f0002eb"),
        "Site 5 (BuildStatusLineData exceeds_200k_tokens)",
    )
    s5_va = VM_BASE + s5_off

    # 6. model.ContextModel.collectStats -> effective context window in /context
    _, cs_end = funcs["collectStats"]
    s6_off = find_unique_anchor(
        data,
        (cs_end - 0x100, cs_end),
        bytes.fromhex("e6ffff17"),
        "Site 6 (ContextModel.collectStats)",
    )
    s6_va = VM_BASE + s6_off
    s6_patched = encode_bl(s6_va, mmt_va + 0x74)

    # 7. store.BuildStatusLineData -> actual API input + cache_read numerator
    s7_off = find_unique_anchor(
        data,
        funcs["BuildStatusLineData"],
        bs_ldr_x5 + bytes.fromhex("e30301aa842840f9a40300b4"),
        "Site 7 (BuildStatusLineData numerator)",
    )
    s7_va = VM_BASE + s7_off

    # 7a. utils.GetCheckpointConfig -> remove hardcoded min(threshold, 256000) (0x3e800) ceiling
    s7a_off = find_unique_anchor(
        data,
        funcs["GetCheckpointConfig"],
        bytes.fromhex("e35740b9"),
        "Site 7a (GetCheckpointConfig 256K clamp)",
    )
    s7a_va = VM_BASE + s7a_off

    # 7b. config.applyFeatureProviderCheckpointOverrideConfig -> zero expCp.MaxTokenLimit ([x0, #0xc]) before MergeConfigsDedup
    s7b_off = (
        find_unique_anchor(
            data,
            funcs["applyFeatureProviderCheckpointOverrideConfig"],
            bytes.fromhex("e10b48a9e48f43a9"),
            "Site 7b (applyFeatureProviderCheckpointOverrideConfig 256K reset)",
        )
        + 4
    )
    s7b_va = VM_BASE + s7b_off

    # 7c. chatconverters.(*TrajectoryChatConverter).getMaxTokensForStep -> disable 64K USER_INPUT step clamp
    s7c_off = find_unique_anchor(
        data,
        funcs["getMaxTokensForStep"],
        bytes.fromhex("1f200071600000541f4c007161010054"),
        "Site 7c (TrajectoryChatConverter.getMaxTokensForStep 64K clamp)",
    )
    s7c_va = VM_BASE + s7c_off

    # 7d. serializers.DefaultSerializer.stepToMessage -> route STEP_TYPE_USER_INPUT (0xe) to zero-limit branch
    s7d_off = find_unique_anchor(
        data,
        funcs["stepToMessage"],
        bytes.fromhex("a50880b9bf380071"),  # ldrsw x5, [x5, #8]; cmp w5, #0xe (the step's frame slot moves: §5.2)
        "Site 7d (DefaultSerializer.stepToMessage 64K clamp)",
    )
    s7d_va = VM_BASE + s7d_off

    return (
        PatchSite(
            domain="context-window",
            name="store.(*Store).ContextWindow -> (*Store).ContextWindowChoice",
            va=s1_va,
            offset=s1_off,
            original=s1_orig,
            patched=s1_patched,
        ),
        PatchSite(
            domain="context-window",
            name="store.(*Store).ContextWindow -> whitelist miss enters extra-model matcher",
            va=s1a_va,
            offset=s1a_off,
            original=bytes.fromhex("00008092"),
            patched=encode_b(s1a_va, s1b_va),
        ),
        PatchSite(
            domain="context-window",
            name=f"store.(*Store).ContextWindow -> admit {CONTEXT_WINDOW_EXTRA_FAMILY.decode()}*",
            va=s1b_va,
            offset=s1b_off,
            original=bytes.fromhex(
                "e0031faae1031faafd835ff8fe0748f8c0035fd64500048aa5ec7cd3a5200091656865f8bf0001ebc0feff54"
            ),
            patched=s1b_patched,
        ),
        PatchSite(
            domain="context-window",
            name="model.SelectorModel.offersContextWindow -> return true",
            va=s2_va,
            offset=s2_off,
            original=bytes.fromhex("f0ff5ef9100240f9"),
            patched=bytes.fromhex("200080d2e7ffff17"),
        ),
        PatchSite(
            domain="context-window",
            name="model.SelectorModel.offersContextWindow -> whitelist miss enters extra-model matcher",
            va=s2a_va,
            offset=s2a_off,
            original=bytes.fromhex("00008092"),
            patched=encode_b(s2a_va, s2b_va),
        ),
        PatchSite(
            domain="context-window",
            name=f"model.SelectorModel.offersContextWindow -> admit {CONTEXT_WINDOW_EXTRA_FAMILY.decode()}*",
            va=s2b_va,
            offset=s2b_off,
            original=bytes.fromhex(
                "fbc32c917b1f4091600740a9fb032d917b1f4091620f40a9fb432d917b1f4091641740a9fb832d917b1f4091"
            ),
            patched=s2b_patched,
        ),
        PatchSite(
            domain="context-window",
            name="store.(*Store).ModelMaxTokens -> effective context window limit resolver",
            va=s3_va,
            offset=s3_off,
            original=None,  # Verified via MODEL_MAX_TOKENS_ORIG_HEAD + MODEL_MAX_TOKENS_ORIG_TAIL
            patched=mmt_patched,
        ),
        PatchSite(
            domain="context-window",
            name="store.BuildStatusLineData -> effective context window denominator",
            va=s4_va,
            offset=s4_off,
            original=bytes.fromhex("e10304aa"),
            patched=s4_patched,
        ),
        PatchSite(
            domain="context-window",
            name="store.BuildStatusLineData -> disable exceeds_200k_tokens false alarm",
            va=s5_va,
            offset=s5_off,
            original=bytes.fromhex("e2d79f9a"),
            patched=bytes.fromhex("e2031faa"),
        ),
        PatchSite(
            domain="context-window",
            name="model.ContextModel.collectStats -> effective context window in /context",
            va=s6_va,
            offset=s6_off,
            original=bytes.fromhex("e00304aa"),
            patched=s6_patched,
        ),
        PatchSite(
            domain="context-window",
            name="store.BuildStatusLineData -> actual API input + cache_read numerator",
            va=s7_va,
            offset=s7_off,
            original=bytes.fromhex("e37b00f9831441a9e58f06a9831c40f9e33300f91f2003d5"),
            patched=bytes.fromhex("831441a9e58f06a9851c40f9e53300f96300058be37b00f9"),
        ),
        PatchSite(
            domain="context-window",
            name="utils.GetCheckpointConfig -> remove 256K (0x3e800) ceiling",
            va=s7a_va,
            offset=s7a_off,
            original=bytes.fromhex("04009dd26400a0f27f00046b04009dd26400a0f26330849a"),
            patched=bytes.fromhex("1f2003d5" * 6),
        ),
        PatchSite(
            domain="context-window",
            name="config.applyFeatureProviderCheckpointOverrideConfig -> zero expCp.MaxTokenLimit",
            va=s7b_va,
            offset=s7b_off,
            original=None,  # 24B with version-dependent `bl errorreport.ReportError` at +16..+20
            patched=bytes.fromhex("c00000b41f0c00b9" + "1f2003d5" * 4),
        ),
        PatchSite(
            domain="context-window",
            name="TrajectoryChatConverter.getMaxTokensForStep -> disable 64K USER_INPUT clamp",
            va=s7c_va,
            offset=s7c_off,
            original=bytes.fromhex("e11740f9210040f9"),
            patched=bytes.fromhex("e2031faa0a000014"),
        ),
        PatchSite(
            domain="context-window",
            name="DefaultSerializer.stepToMessage -> disable 64K STEP_TYPE_USER_INPUT clamp",
            va=s7d_va,
            offset=s7d_off,
            original=bytes.fromhex("c0000054"),
            patched=bytes.fromhex("60000054"),
        ),
    )


def _resolve_cot_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]], nl3_va: int
) -> tuple[tuple[PatchSite, ...], PatchSite]:
    """Sites #8-#11 & #23: Persistent expanded CoT (`∴ Thought...`, flush-left `Faint+Italic` paragraphs, `\\n\\n` spacing)."""
    # 8. Retired: it made stepContent expand every finished thought; Sites #54a-#54i decide by verbosity.
    #    Its anchor still locates Sites #9-#11.
    s8_off = (
        find_unique_anchor(
            data,
            funcs["stepContent"],
            bytes.fromhex("e20300aa04000014e10f40b2"),
            "Site 8 (stepContent expanded CoT check)",
        )
        + 0x10
    )

    # 9. render.stepContent -> fold Styles[+0x0510] stack copy loop & mutate "▾" (0xe2 96 be) to "∴" (0xe2 88 b4)
    s9_off = s8_off + 0x84
    s9_va = VM_BASE + s9_off

    # 10 & 11. render.stepContent -> omit 2-space paragraph prefix & style CoT body paragraphs with Faint + Italic (\x1b[2;3m)
    b_cot_loop_off = find_unique_anchor(
        data,
        (s8_off, s8_off + 0x140),
        bytes.fromhex("e2031faae3031faae4031faae5031faa"),
        "Site 10 (stepContent CoT body loop branch)",
    )
    cot_loop_entry_off = decode_branch_target(data, b_cot_loop_off, 0x14000000, "Site 10 (CoT body loop)") - VM_BASE
    s10_off = cot_loop_entry_off + 0x54
    s10_va = VM_BASE + s10_off
    s11_off = cot_loop_entry_off + 0x74
    s11_va = VM_BASE + s11_off

    # 23. render.stripMarkdownFormatting -> collapse "\n\n\n" to "\n\n" (single blank line between CoT paragraphs)
    s23_off = find_unique_anchor(
        data,
        funcs["stripMarkdownFormatting"],
        bytes.fromhex("e02f00f91f2003d5"),
        "Site 23 (stripMarkdownFormatting CoT newline collapse)",
    )
    s23_va = VM_BASE + s23_off
    sr_va = decode_branch_target(data, s23_off + 0x58, 0x94000000, "Site 23 (strings.Replace)")
    s23_patched = (
        encode_adr(s23_va, nl3_va, 2)
        + bytes.fromhex("1f2003d5e30740b2e40302aae5037fb206008092")
        + encode_bl(s23_va + 0x18, sr_va)
        + bytes.fromhex("1f2003d5")
        + encode_adr(s23_va + 0x20, nl3_va, 2)
        + bytes.fromhex("1f2003d5e30740b2e40302aae5037fb2")
    )

    step_sites = (
        PatchSite(
            domain="cot-rendering",
            name="render.stepContent -> mutate CoT header `▾ Thought...` to `∴ Thought...`",
            va=s9_va,
            offset=s9_off,
            original=bytes.fromhex("580180d27044c1ac504481ac7044c1ac504481ac180700d178ffffb5790040f9590000f9"),
            patched=bytes.fromhex("980280d27044c1ac504481ac180700d1b8ffffb55f0000f919919652191000781f2003d5"),
        ),
        PatchSite(
            domain="cot-rendering",
            name="render.stepContent -> omit 2-space leading indent on CoT body paragraphs",
            va=s10_va,
            offset=s10_off,
            original=bytes.fromhex("e2037fb2"),
            patched=bytes.fromhex("e2031faa"),
        ),
        PatchSite(
            domain="cot-rendering",
            name="render.stepContent -> style CoT body paragraphs with Faint + Italic (\\x1b[2;3m)",
            va=s11_va,
            offset=s11_off,
            original=bytes.fromhex("580180d2d044c1acb04481acd044c1acb04481ac180700d178ffffb5d90040f9b90000f9"),
            patched=bytes.fromhex("980280d2d044c1acb04481ac180700d1b8ffffb5bf0000f9590480d2f90700f9f92300f9"),
        ),
    )
    strip_site = PatchSite(
        domain="cot-rendering",
        name="render.stripMarkdownFormatting -> collapse CoT `\\n\\n\\n` to `\\n\\n` (1 empty line between paragraphs)",
        va=s23_va,
        offset=s23_off,
        original=None,
        patched=s23_patched,
    )
    return step_sites, strip_site


def _resolve_statusline_refresh_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> PatchSite:
    """Site #15: 15-second idle statusline refresh in store.(*Manager).userInputLoop."""
    u_start, u_end = funcs["userInputLoop"]
    t_start, t_end = funcs["triggerStatusLineUpdate"]
    r_start, r_end = funcs["StatusLineRunnerRun"]
    trigger_va = VM_BASE + t_start

    bl_since_off = find_unique_anchor(
        data,
        (r_start, r_end),
        bytes.fromhex("021c40f9008442a9"),
        "Site 15 (StatusLineRunner.Run time.Since)",
    )
    time_since_va = decode_branch_target(data, bl_since_off, 0x94000000, "Site 15 (time.Since)")

    trig_nop_off = (
        find_unique_anchor(
            data,
            (t_start, t_end),
            bytes.fromhex("1f2003d51f2003d5"),
            "Site 15 (triggerStatusLineUpdate runner ldr)",
        )
        - 12
    )
    (ldr_runner_insn,) = struct.unpack_from("<I", data, trig_nop_off)
    ldr_x0_runner = struct.pack("<I", (ldr_runner_insn & ~0x1F) | 0)

    s15_blk_matches: list[int] = []
    for off in range(u_start, u_end - 120, 4):
        if (
            data[off + 8 : off + 12] == bytes.fromhex("00003fd6")
            and struct.unpack_from("<I", data, off + 20)[0] & LDR_X_ANY_OFFSET == ldr_x(0, 0)
            and data[off + 24 : off + 28] == bytes.fromhex("e00000b4")
            and data[off + 32 : off + 36] == bytes.fromhex("610000b4")
            and data[off + 40 : off + 44] == bytes.fromhex("03000014")
        ):
            s15_blk_matches.append(off)
    if len(s15_blk_matches) not in (1, 2) or (
        len(s15_blk_matches) == 2 and s15_blk_matches[1] != s15_blk_matches[0] + 60
    ):
        raise RuntimeError(f"Unexpected matches for Site 15 (userInputLoop ticker): {s15_blk_matches}")
    blk1_off = s15_blk_matches[0]
    s15_off = blk1_off + 60
    blk1_va = VM_BASE + blk1_off
    s15_va = VM_BASE + s15_off

    b1 = bytearray(data[blk1_off : blk1_off + 60])
    for idx in (16, 48, 56):
        (w,) = struct.unpack_from("<I", b1, idx)
        struct.pack_into("<I", b1, idx, w - 15)
    (w36,) = struct.unpack_from("<I", b1, 36)
    struct.pack_into("<I", b1, 36, w36 - (15 << 5))
    s15_orig = bytes(b1)

    ldr_x0_m = bytes(data[blk1_off + 12 : blk1_off + 16])
    s15_patched = (
        ldr_x0_m
        + ldr_x0_runner
        + bytes.fromhex("e0fdffb4")
        + bytes.fromhex("021c40f9008442a9")
        + encode_bl(s15_va + 0x14, time_since_va)
        + bytes.fromhex("41c2afd26100c0f21f0001eb0bfdff54")
        + ldr_x0_m
        + encode_bl(s15_va + 0x2C, trigger_va)
        + encode_b(s15_va + 0x30, blk1_va)
        + bytes.fromhex("1f2003d51f2003d5")
    )

    return PatchSite(
        domain="statusline-refresh",
        name="store.(*Manager).userInputLoop -> 15s idle statusline refresh",
        va=s15_va,
        offset=s15_off,
        original=s15_orig,
        patched=s15_patched,
    )


def _resolve_palette_and_typography_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[tuple[PatchSite, ...], tuple[PatchSite, ...], int]:
    """Sites #12-#14, #16-#22 & #24-#34: `"terminal"` ANSI palette, `● Tool(xxx)` typography, and the user prompt bar."""
    # 12 & 13. types.init ("terminal" palette) ->
    #   Site 12: palette[+0x020] (Spinner shimmer & TUI Selector) from ANSI "12" to nil (Primary Foreground)
    #   Site 13: palette[+0x040] (User prompt) from ANSI "4" to nil (Primary Foreground)
    s12_base = find_unique_anchor(
        data,
        funcs["typesInit"],
        bytes.fromhex("a30080d25f7c81a85f7c81a85f7c81a85f7c81a8630400d163ffffb5"),
        "Site 12 (types.init terminal palette[+0x020])",
    )
    s12_off = s12_base + 0x0C
    s12_va = VM_BASE + s12_off
    s13_off = s12_base + 0x2C
    s13_va = VM_BASE + s13_off

    # 14. render.resolveStyles ("terminal" scheme) -> mouse selection highlight uses native Reverse (\x1b[7m)
    rs_start, rs_end = funcs["resolveStyles"]
    s14_matches: list[int] = []
    pos = rs_start
    pat_len2 = bytes.fromhex("e1037fb2")
    while True:
        idx = data.find(pat_len2, pos, rs_end)
        if idx == -1:
            break
        if (
            data[idx - 0x114 : idx - 0x110] == bytes.fromhex("e1037bb2")
            and data[idx - 0x98 : idx - 0x94] == bytes.fromhex("e10340b2")
            and data[idx + 0x54 : idx + 0x58] == bytes.fromhex("e10376b2")
        ):
            s14_matches.append(idx + 0x6C)
        pos = idx + 1
    if len(s14_matches) != 1:
        raise RuntimeError(f"Expected 1 match for Site 14 (resolveStyles Selection), got {len(s14_matches)}")
    s14_off = s14_matches[0]
    s14_va = VM_BASE + s14_off

    # 16. render.resolveStyles -> PromptChevron (`>` in live input box, Styles[+0x2370]) uses native Faint (\x1b[2m)
    pal_copy_loop = bytes.fromhex("b80080d29044c1ac704481ac9044c1ac704481ac180700d178ffffb5")
    zero_loop_x5 = bytes.fromhex("450180d29f7c81a89f7c81a89f7c81a89f7c81a8a50400d165ffffb59f0000f9")
    off_after_pal_loop = find_unique_anchor(data, funcs["resolveStyles"], pal_copy_loop, "Site 16 (resolveStyles pal_copy)")
    # The palette's frame slot: `add x3, sp, #pal` opens the copy. The first three styles built after it
    # are UserPrompt (fg palette[+0x040], Bold), ToolName (fg palette[+0x0d0], Bold) and ToolArgs (fg
    # palette[+0x120]); each starts by addressing its color, `add x27, sp, #pal+N`. v1.5.8 builds its two
    # search highlights between the copy and UserPrompt, so Sites #19-#21 are located from UserPrompt's
    # `add x27`, which no site rewrites, instead of from the copy.
    (pal_add,) = struct.unpack_from("<I", data, off_after_pal_loop - 0x28)
    if pal_add & 0xFFC003FF != 0x910003E3:
        raise RuntimeError("resolveStyles: the palette copy no longer opens with `add x3, sp, #pal`")
    insn_f0 = 0x910003FB | ((((pal_add >> 10) & 0xFFF) + 0x40) << 10)  # add x27, sp, #pal+0x40
    user_prompt = [
        o for o in range(off_after_pal_loop, min(off_after_pal_loop + 0x400, rs_end), 4)
        if struct.unpack_from("<I", data, o)[0] == insn_f0
    ]
    if len(user_prompt) != 1:
        raise RuntimeError(f"resolveStyles: expected one UserPrompt color load after the palette copy, found {len(user_prompt)}")
    up_off = user_prompt[0]
    z_off = data.find(zero_loop_x5, off_after_pal_loop, rs_end)
    if z_off == -1:
        raise RuntimeError("Site 16 (resolveStyles zero_loop_x5) not found")
    s16_off = z_off - 0x2C
    s16_va = VM_BASE + s16_off

    # 17 & 18. render.glamourStyleForScheme -> decouple inline `code` (Code.Color) from palette[+0x020] to palette[+0x0d0] (ANSI 3)
    g_post = bytes.fromhex("a10200b4e0037cb2")
    s17_off = (
        find_unique_anchor(
            data,
            funcs["glamourStyleForScheme"],
            g_post,
            "Site 17 (glamourStyleForScheme Code.Color check)",
        )
        - len(g_post)
        - 4
    )
    s17_va = VM_BASE + s17_off
    s18_off = s17_off + 0x20
    s18_va = VM_BASE + s18_off

    # 19 & 20. render.resolveStyles ->
    #   Site 19: Styles[+0x0288] (ToolName `Bash`/`Edit`/`Read`) reads palette[+0x010] (colorless Bold)
    #   Site 20: Styles[+0x0510] (ToolArgs `(xxx)` & CoT header) uses native terminal Faint (\x1b[2m)
    s19_off = up_off + 0xD0
    s19_va = VM_BASE + s19_off
    s19_orig = struct.pack("<I", insn_f0 + (0x90 << 10))
    s19_patched = struct.pack("<I", insn_f0 - (0x30 << 10))

    s20_off = up_off + 0x1D0
    s20_va = VM_BASE + s20_off

    # 21. render.resolveStyles -> Styles[+0x0000] (UserPrompt) Regular weight + adaptive 256-color background
    lc_start, _ = funcs["lipglossColor"]
    itab_va = decode_adrp_add(data, lc_start + 0xD0)
    ext_color_type_va = struct.unpack_from("<Q", data, itab_va - VM_BASE + 8)[0]
    zerobase_va = decode_adrp_add(data, lc_start + 0x150)
    bg_byte_va = zerobase_va - 8
    bg_byte_imm12 = bg_byte_va & 0xFFF

    s21_off = up_off + 0x5C
    s21_va = VM_BASE + s21_off
    s21_orig = bytes(data[s21_off : s21_off + 20])
    s21_patched = (
        bytes.fromhex("e10375b2")
        + encode_adrp_add(s21_va + 4, ext_color_type_va, 2)
        + encode_adrp_add(s21_va + 12, bg_byte_va, 3)
    )
    # The original is read from the binary, so prove the shape: stock is `orr x1, xzr, #1` (Bold) and its
    # `true` in x2, x3; anything else must already be this site.
    s21_words = struct.unpack_from("<5I", data, s21_off)
    s21_stock = (
        s21_words[0] == 0xB24003E1
        and s21_words[1] & 0x9F00001F == 0x90000002 and s21_words[2] & 0xFFC003FF == 0x91000042
        and s21_words[3] & 0x9F00001F == 0x90000003 and s21_words[4] & 0xFFC003FF == 0x91000063
    )
    if not s21_stock and s21_orig != s21_patched:
        raise RuntimeError("resolveStyles: UserPrompt no longer sets Bold where Site 21 expects it")

    # 22, 24, 25. render.renderUserPrompt ->
    #   Site 24: replace `───` rule setup with full-width background (`s.props=0x2800`, `s.width=termWidth`) + inline strings
    #   Site 22: prepend dimmed Faint `> ` ("\x1b[2m> \x1b[22m") while keeping Styles[+0x0000].Render
    #   Site 25: return strings.Join(lines, "\n") directly without `rule + "\n"`
    rup_start, _ = funcs["renderUserPrompt"]
    s24_off = find_unique_anchor(
        data,
        funcs["renderUserPrompt"],
        bytes.fromhex("430800d1e38301f9"),
        "Site 24 (renderUserPrompt rule block)",
    )
    s24_va = VM_BASE + s24_off
    s24_orig = bytes(data[s24_off : s24_off + 72])
    ldrb_w5_x4 = struct.pack("<I", 0x39400085 | (bg_byte_imm12 << 10))
    strb_w5_x4 = struct.pack("<I", 0x39000085 | (bg_byte_imm12 << 10))
    s24_patched = (
        encode_adrp(s24_va, bg_byte_va, 4)
        + ldrb_w5_x4
        + bytes.fromhex("bf000071a61d8052c500851a")
        + strb_w5_x4
        + bytes.fromhex("e4630e91050085d2850000f9823c00f9")
        + bytes.fromhex("ffbf01f9ff8f01f9ff6b01f910000014")
        + bytes.fromhex("1b5b326d3e201b5b32326d000a0a0a00")
    )
    chev_va = s24_va + 56
    nl3_va = s24_va + 68

    rup_base = find_unique_anchor(
        data,
        funcs["renderUserPrompt"],
        bytes.fromhex("7dffff17fbe30d917f7f00a9e0031faa"),
        "Site 22 (renderUserPrompt first line)",
    )
    s22_off = rup_base
    s22_va = VM_BASE + s22_off
    s22_orig = bytes(data[s22_off : s22_off + 12])
    s22_patched = encode_adr(s22_va, chev_va, 1) + bytes.fromhex("1f2003d5620180d2")

    s25_off = rup_base + 0x104
    s25_va = VM_BASE + s25_off
    s25_orig = bytes.fromhex("e26b41f9")
    s25_patched = bytes.fromhex("09000014")

    # 26-29. render.StickyPrompt & ConversationModel ->
    #   Full-width 1-line sticky user prompt bar without `───` rule
    sp_start, sp_end = funcs["StickyPrompt"]
    s26_off = find_unique_anchor(
        data,
        funcs["StickyPrompt"],
        bytes.fromhex("e3e302f9"),
        "Site 26 (StickyPrompt chevron)",
    )
    s26_va = VM_BASE + s26_off
    s26_orig = bytes(data[s26_off : s26_off + 24])
    s26_patched = (
        bytes.fromhex("620180d2e30300aae40301aae0031faa")
        + encode_adr(s26_va + 16, chev_va, 1)
        + bytes.fromhex("1f2003d5")
    )

    s27_off = s26_off + 0x2C
    s27_va = VM_BASE + s27_off
    s27_orig = bytes(data[s27_off : s27_off + 16])
    s27_patched = bytes.fromhex("ff4701f9ff6b01f9ff5b01f904000014")

    s28_off = find_unique_anchor(
        data,
        (sp_start, s26_off + 0xB0),
        bytes.fromhex("e5230091e6430c91"),
        "Site 28 (StickyPrompt full-width style copy)",
    )
    s28_va = VM_BASE + s28_off
    s28_orig = bytes(data[s28_off : s28_off + 36])
    s28_patched = bytes.fromhex(
        "180085d2d80000f9f8df42f9d83c00f9980280d2d044c1acb04481ac180700d1b8ffffb5"
    )

    s29_off = s28_off + 0x3C
    s29_va = VM_BASE + s29_off
    s29_orig = bytes(data[s29_off : s29_off + 16])
    s29_patched = bytes.fromhex("ff7301f9ff8301f9ff6301f91f000014")
    # Site #29 ends in `b +0x7c`, so the 0x78 bytes after it are dead: Site #47 keeps code there.
    sticky_cave = (s29_off + 0x10, s29_off + 0xC + 0x7C)
    assert_unreachable(data, (sp_start, sp_end), sticky_cave, "Site 29 dead span (StickyPrompt)")

    s30_off = find_unique_anchor(
        data,
        (s29_off, sp_end),
        bytes.fromhex("e36341f9040c01a9"),
        "Site 30 (StickyPrompt 1-line slice len)",
    )
    s30_va = VM_BASE + s30_off
    s30_orig = bytes.fromhex("e1037fb2")
    s30_patched = bytes.fromhex("e10340b2")

    # 31-33. ConversationModel 1-line sticky header height
    s31_off = find_unique_anchor(
        data,
        funcs["pinHeader"],
        bytes.fromhex("e24b40f9"),
        "Site 31 (pinHeader height)",
    )
    s31_va = VM_BASE + s31_off

    s32_off = find_unique_words(
        data,
        funcs["stickyPromptItem"],
        ((ldr_x(2, 27), LDR_X_ANY_OFFSET),),  # ldr x2, [x27, #field], then the patched `add x3, x1, #2`
        "Site 32 (stickyPromptItem threshold)",
    )
    s32_va = VM_BASE + s32_off

    s33_off = find_unique_anchor(
        data,
        funcs["stickyPromptAt"],
        bytes.fromhex("fd2300d1"),
        "Site 33 (stickyPromptAt hit-test)",
    )
    s33_va = VM_BASE + s33_off

    # 34. store.(*Manager).SetTerminalBackground -> update adaptive user bar byte (237 Dark / 254 Light) + RerenderAll
    stb_start, stb_end = funcs["SetTerminalBackground"]
    rerender_va = VM_BASE + funcs["RerenderAll"][0]
    s34_off = (
        find_unique_anchor(
            data,
            (stb_start + 0x200, stb_end),
            bytes.fromhex("02008092e32b40f96400e2b88400028b"),
            "Site 34 (SetTerminalBackground adaptive bg update)",
        )
        - 28
    )
    s34_va = VM_BASE + s34_off
    s34_orig = bytes(data[s34_off : s34_off + 84])
    strb_w5_x27 = struct.pack("<I", 0x39000365 | (bg_byte_imm12 << 10))
    s34_patched = (
        s34_orig[:8]
        + bytes.fromhex("1f2003d5")
        + s34_orig[12:28]
        + bytes.fromhex("e5df4039bf040071a51d8052c61f8052a500861a")
        + strb_w5_x27
        + bytes.fromhex("1f2003d5")
        + s34_orig[56:80]
        + encode_bl(s34_va + 80, rerender_va)
    )

    pre_sites = (
        PatchSite(
            domain="palette-typography",
            name="types.init -> terminal palette[+0x020] (Spinner & TUI Selector) nil (Primary Fg)",
            va=s12_va,
            offset=s12_off,
            original=bytes.fromhex("620f00a9"),
            patched=bytes.fromhex("7f7f00a9"),
        ),
        PatchSite(
            domain="palette-typography",
            name="types.init -> terminal palette[+0x040] (User prompt) nil (Primary Fg)",
            va=s13_va,
            offset=s13_off,
            original=bytes.fromhex("620f00a9"),
            patched=bytes.fromhex("7f7f00a9"),
        ),
        PatchSite(
            domain="palette-typography",
            name="render.resolveStyles -> terminal mouse selection highlight native Reverse (\\x1b[7m)",
            va=s14_va,
            offset=s14_off,
            original=LIPGLOSS_COPY_LOOP_X5_X4_ORIG,
            patched=fold_lipgloss_copy_x5_x4(0x08),
        ),
    )
    post_sites = (
        PatchSite(
            domain="palette-typography",
            name="render.resolveStyles -> PromptChevron (`>` in input box) native Faint (\\x1b[2m)",
            va=s16_va,
            offset=s16_off,
            original=LIPGLOSS_COPY_LOOP_X5_X4_ORIG,
            patched=fold_lipgloss_copy_x5_x4(0x20),
        ),
        PatchSite(
            domain="palette-typography",
            name="render.glamourStyleForScheme -> inline `code` check uses palette[+0x0d0] (ANSI 3)",
            va=s17_va,
            offset=s17_off,
            original=bytes.fromhex("e12f40f9"),
            patched=bytes.fromhex("e18740f9"),
        ),
        PatchSite(
            domain="palette-typography",
            name="render.glamourStyleForScheme -> inline `code` color uses palette[+0x0d0] (ANSI 3)",
            va=s18_va,
            offset=s18_off,
            original=bytes.fromhex("e08745a9"),
            patched=bytes.fromhex("e08750a9"),
        ),
        PatchSite(
            domain="palette-typography",
            name="render.resolveStyles -> Styles[+0x0288] (ToolName `Bash`/`Edit`/`Read`) colorless Bold",
            va=s19_va,
            offset=s19_off,
            original=s19_orig,
            patched=s19_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.resolveStyles -> Styles[+0x0510] (ToolArgs `(xxx)` & CoT header) native Faint (\\x1b[2m)",
            va=s20_va,
            offset=s20_off,
            original=LIPGLOSS_COPY_LOOP_X5_X4_ORIG,
            patched=fold_lipgloss_copy_x5_x4(0x20),
        ),
        PatchSite(
            domain="palette-typography",
            name="render.resolveStyles -> Styles[+0x0000] (UserPrompt) Regular + adaptive 256-color bg",
            va=s21_va,
            offset=s21_off,
            original=s21_orig,
            patched=s21_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.renderUserPrompt -> dimmed Faint `> ` chevron (\\x1b[2m> \\x1b[22m)",
            va=s22_va,
            offset=s22_off,
            original=s22_orig,
            patched=s22_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.renderUserPrompt -> full-width background bar (s.props=0x2800, s.width=termWidth)",
            va=s24_va,
            offset=s24_off,
            original=s24_orig,
            patched=s24_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.renderUserPrompt -> omit `───` horizontal rule above user prompt",
            va=s25_va,
            offset=s25_off,
            original=s25_orig,
            patched=s25_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.StickyPrompt -> dimmed Faint `> ` chevron (\\x1b[2m> \\x1b[22m)",
            va=s26_va,
            offset=s26_off,
            original=s26_orig,
            patched=s26_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.StickyPrompt -> skip `───` horizontal rule construction",
            va=s27_va,
            offset=s27_off,
            original=s27_orig,
            patched=s27_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.StickyPrompt -> full-width background bar (s.props=0x2800, s.width=termWidth)",
            va=s28_va,
            offset=s28_off,
            original=s28_orig,
            patched=s28_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.StickyPrompt -> skip `───` rule styling",
            va=s29_va,
            offset=s29_off,
            original=s29_orig,
            patched=s29_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="render.StickyPrompt -> return 1-line sticky header slice (len=1)",
            va=s30_va,
            offset=s30_off,
            original=s30_orig,
            patched=s30_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name="model.(*ConversationModel).pinHeader -> 1-line sticky header height",
            va=s31_va,
            offset=s31_off,
            original=bytes.fromhex("420800d1"),
            patched=bytes.fromhex("420400d1"),
        ),
        PatchSite(
            domain="palette-typography",
            name="model.(*ConversationModel).stickyPromptItem -> 1-line sticky header threshold",
            va=s32_va,
            offset=s32_off,
            original=bytes.fromhex("23080091"),
            patched=bytes.fromhex("23040091"),
        ),
        PatchSite(
            domain="palette-typography",
            name="model.(*ConversationModel).stickyPromptAt -> 1-line sticky header click hit-test",
            va=s33_va,
            offset=s33_off,
            original=bytes.fromhex("3f0800f1"),
            patched=bytes.fromhex("3f0400f1"),
        ),
        PatchSite(
            domain="palette-typography",
            name="store.(*Manager).SetTerminalBackground -> live Dark(237)/Light(254) user bar + RerenderAll",
            va=s34_va,
            offset=s34_off,
            original=s34_orig,
            patched=s34_patched,
        ),
    )
    return pre_sites, post_sites, nl3_va, sticky_cave


# Sites #48a-#48d: the `  ⎿  ` elbow under a command's output or an alert (renderCommandOutput and its
# helpers renderStyledLines and renderOutputLines, which RenderAlert shares) borrows Styles[+0x0000]:
# since Site #21 gave that style the user bar's background, the elbow showed a gray block. Each elbow
# takes the style of the reply text it introduces instead; renderStyledLines receives its lines already
# styled, so its elbow takes Styles[+0x0510], the faint style every other elbow in the TUI uses.
STYLES_ELBOW = 0x510
COMMAND_ELBOW = "  ⎿  ".encode()
COPY_STYLE, COPY_STYLES = 0xD2800158, 0xD28067F8  # mov x24, #0xa (one Style) / #0x33f (all of Styles)


def _decode_sp_add(data: bytes | bytearray, off: int) -> tuple[int, int, int] | None:
    """Decode `add xN, sp, #lo` or `add xN, sp, #hi, lsl #12; add xN, xN, #lo` at `off` to (size, xN, sp offset)."""
    a = struct.unpack_from("<I", data, off)[0]
    if a & 0xFFC003E0 == 0x910003E0:
        return 4, a & 0x1F, (a >> 10) & 0xFFF
    if a & 0xFFC003E0 == 0x914003E0:
        rd, b = a & 0x1F, struct.unpack_from("<I", data, off + 4)[0]
        if b & 0xFFC00000 == 0x91000000 and (b >> 5) & 0x1F == rd and b & 0x1F == rd:
            return 8, rd, (((a >> 10) & 0xFFF) << 12) + ((b >> 10) & 0xFFF)
    return None


def _encode_sp_add(size: int, rd: int, sp_off: int) -> bytes:
    if size == 4:
        if sp_off > 0xFFF:
            raise RuntimeError(f"sp offset {hex(sp_off)} no longer fits one `add`")
        return struct.pack("<I", 0x910003E0 | (sp_off << 10) | rd)
    return struct.pack("<II", 0x914003E0 | ((sp_off >> 12) << 10) | rd, 0x91000000 | ((sp_off & 0xFFF) << 10) | (rd << 5) | rd)


def _copy_source(data: bytes | bytearray, loop_off: int) -> tuple[int, int, int, int] | None:
    """The `add xN, sp, ...` that sets the source of the copy loop at `loop_off`: (offset, size, xN, sp offset).

    The loop body starts `ldp q16, q17, [xN], #0x20`; xN must be the register the `add` sets.
    """
    src_reg = (struct.unpack_from("<I", data, loop_off + 4)[0] >> 5) & 0x1F
    for off in range(loop_off - 4, loop_off - 16, -4):
        dec = _decode_sp_add(data, off)
        if dec and off + dec[0] == loop_off and dec[1] == src_reg:
            return off, *dec
    return None


def _copy_dest(data: bytes | bytearray, loop_off: int) -> int | None:
    """The sp offset a copy loop writes to: the `add` setting its `stp` register, just before its source."""
    src = _copy_source(data, loop_off)
    dst_reg = (struct.unpack_from("<I", data, loop_off + 8)[0] >> 5) & 0x1F
    for off in (src[0] - 4, src[0] - 8) if src else ():
        dec = _decode_sp_add(data, off)
        if dec and off + dec[0] == src[0] and dec[1] == dst_reg:
            return dec[2]
    return None


def _styles_in_frame(data: bytes | bytearray, bounds: tuple[int, int]) -> int:
    """sp offset of a Styles held in the frame: the source of its one whole-Styles copy."""
    words = range(bounds[0], bounds[1], 4)
    bases = {src[3] for o in words if struct.unpack_from("<I", data, o)[0] == COPY_STYLES and (src := _copy_source(data, o))}
    if len(bases) != 1:
        raise RuntimeError(f"Expected one by-value Styles at {hex(VM_BASE + bounds[0])}, found {len(bases)}")
    return bases.pop()


def _frame_size(data: bytes | bytearray, bounds: tuple[int, int]) -> int:
    """The frame a Go function reserves (`sub x20, sp, #frame` in its prologue)."""
    for off in range(bounds[0], bounds[0] + 32, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w & 0xFFC003FF == 0xD10003F4:
            return (w >> 10) & 0xFFF
    raise RuntimeError(f"No `sub x20, sp, #frame` prologue at {hex(VM_BASE + bounds[0])}")


def _styles_param(data: bytes | bytearray, caller: tuple[int, int], callee: tuple[int, int]) -> int:
    """sp offset, inside `callee`, of the Styles that `caller` passes it by value.

    The caller copies Styles to its own `sp + D` before each `bl`; the callee sees that at `sp + frame + D`.
    D comes from the copy itself, since other by-value arguments can precede Styles.
    """
    dests = set()
    for off in range(caller[0], caller[1], 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w >> 26 != 0x25 or branch_target(w, off) != callee[0]:
            continue
        loop = next((o for o in range(off - 4, off - 160, -4) if struct.unpack_from("<I", data, o)[0] == COPY_STYLES), None)
        src = _copy_source(data, loop) if loop else None
        stp_base = (struct.unpack_from("<I", data, loop + 8)[0] >> 5) & 0x1F if loop else None
        dest = _decode_sp_add(data, src[0] - 4) if src else None
        if dest is None or dest[1] != stp_base:
            raise RuntimeError(f"Cannot find where {hex(VM_BASE + caller[0])} places Styles for {hex(VM_BASE + callee[0])}")
        dests.add(dest[2])
    if len(dests) != 1:
        raise RuntimeError(f"Expected one Styles placement for {hex(VM_BASE + callee[0])}, found {sorted(dests)}")
    return _frame_size(data, callee) + dests.pop()


def _resolve_elbow_sites(
    data: bytes | bytearray, bounds: tuple[int, int], styles: int, style: int, label: str
) -> list[PatchSite]:
    """Every `⎿` elbow in `bounds` copies Styles[+0x0000] (sp + `styles`); make it copy sp + `style` instead."""
    loads = [
        o
        for o in range(bounds[0], bounds[1] - 8, 4)
        if struct.unpack_from("<I", data, o)[0] & 0x9F000000 == 0x90000000
        and (t := decode_adrp_add(data, o) - VM_BASE) >= 0
        and data[t : t + len(COMMAND_ELBOW)] == COMMAND_ELBOW
    ]
    if not loads:
        raise RuntimeError(f"{label}: no `⎿` elbow found")
    sites = []
    for load in loads:
        loop = next((o for o in range(load, load + 64, 4) if struct.unpack_from("<I", data, o)[0] == COPY_STYLE), None)
        src = _copy_source(data, loop) if loop else None
        # Any sp offset is accepted here, so a binary patched by an earlier rule still resolves; applying
        # from the clean backup checks that the copy really reads Styles[+0x0000] (`original`).
        if src is None:
            raise RuntimeError(f"{label}: no style copy follows the elbow at {hex(VM_BASE + load)}")
        off, size, rd, _ = src
        sites.append(
            PatchSite(
                "palette-typography",
                f"{label} -> `⎿` elbow in the reply's faint style, not the user bar's",
                VM_BASE + off,
                off,
                _encode_sp_add(size, rd, styles),
                _encode_sp_add(size, rd, style),
            )
        )
    return sites


def _reply_style_before(data: bytes | bytearray, bounds: tuple[int, int], styles: int) -> int:
    """renderCommandOutput renders the reply text, then its elbow: the style copied just before the elbow."""
    elbow = next(
        o
        for o in range(bounds[0], bounds[1] - 8, 4)
        if struct.unpack_from("<I", data, o)[0] & 0x9F000000 == 0x90000000
        and (t := decode_adrp_add(data, o) - VM_BASE) >= 0
        and data[t : t + len(COMMAND_ELBOW)] == COMMAND_ELBOW
    )
    loop = next((o for o in range(elbow - 4, elbow - 96, -4) if struct.unpack_from("<I", data, o)[0] == COPY_STYLE), None)
    src = _copy_source(data, loop) if loop else None
    if src is None or src[3] in (styles,):
        raise RuntimeError("renderCommandOutput: no reply style rendered before the elbow")
    return src[3]


def _resolve_command_elbow_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #48a-#48d: the elbows under a command's output or an alert match the reply, not the user bar."""
    rco, rsl, rol = funcs["renderCommandOutput"], funcs["renderStyledLines"], funcs["renderOutputLines"]
    rco_styles = _styles_in_frame(data, rco)
    rsl_styles, rol_styles = _styles_param(data, rco, rsl), _styles_param(data, rco, rol)
    # renderOutputLines(lineStyle, _, styles, ...): its first stack argument styles each output line.
    rol_line = _frame_size(data, rol) + 8
    if not any(
        struct.unpack_from("<I", data, o)[0] == COPY_STYLE and (src := _copy_source(data, o)) and src[3] == rol_line
        for o in range(rol[0], rol[1], 4)
    ):
        raise RuntimeError("renderOutputLines no longer renders with its first Style argument")
    return (
        *_resolve_elbow_sites(data, rco, rco_styles, _reply_style_before(data, rco, rco_styles), "render.renderCommandOutput"),
        *_resolve_elbow_sites(data, rsl, rsl_styles, rsl_styles + STYLES_ELBOW, "render.renderStyledLines"),
        *_resolve_elbow_sites(data, rol, rol_styles, rol_line, "render.renderOutputLines"),
    )


# Sites #49a-#49i: the pending line's mark is a Gemini star that breathes, and its words take a
# blue-to-lavender light. Green stays the completed dot's alone, so done and doing never share a color.
#
# The frames (#49a-#49c). A point grows into `✦`, flares lavender, rests blue and fades: 24 frames at the
# spinner's 100 ms, one breath every 2.4 s. `∙` and `⋅` grow into it because both are East Asian Width
# neutral (`·` and `•` are ambiguous: two columns in a CJK locale, which would shake the line) and
# Maple Mono draws them at 170 and 240 units beside the star's 572. Each frame carries its own
# truecolor, so the strings live in the __TEXT fill. The binary is PIE with classic rebase opcodes:
# a pointer the loader must slide has to sit in a slot that already held one, and the stock frame
# slice has 8. Halloween's pixel-art logo is two 14-row string tables laid end to end, 28 slots; the
# frame slice points there, and Halloween is no longer registered (#49d), so nothing draws its logo.
#
# The light (#49e-#49h). Stock lights the pending line with one lit style over gray. A seasonal theme
# lights it with a gradient instead: themerender.runningLightAt makes a style of each color its theme
# returns and LitWindow spreads them over a 5-column band. renderPendingLight takes that path with
# Halloween's theme value, whose two 5-color tables (dark and light backgrounds) now hold the Gemini
# band; the gray base under it becomes `#4796E3`, a static color.RGBA boxed as lipgloss.Color boxes a
# hex. The band moves a column per 100 ms instead of 80, one per spinner tick, so it never skips one.
# Thirteen views share the frame slice and rely on its trailing space, so the frames keep it;
# pendingLineView's own extra space is dropped (#49i), so the text lines up with the dots above.
# The other running lights (the live thought, search, @-suggestions) keep stock's: the foreground over gray.
SPINNER_STOCK = "⣾ ⣷ ⣯ ⣟ ⡿ ⢿ ⣻ ⣽ ".encode()
GEMINI_BLUE, GEMINI_PURPLE, GEMINI_ROSE = 0x4796E3, 0x9177C7, 0xCA6673
# A long turn warms the word along the Gemini gradient: blue for the first LONG_TURN seconds, then one
# step every STAGE_SECONDS, purple halfway, rose at the last of the TURN_STAGES (4 minutes in).
LONG_TURN, STAGE_SECONDS, TURN_STAGES = 60, 12, 16
# (glyph, brightness: 0.5 is the blue itself, toward 1 it whitens, toward 0 it darkens; hue: 0 blue, 1 purple)
SPINNER_BREATH = (
    ("∙", .20, 0), ("∙", .30, 0), ("⋅", .40, .1), ("⋅", .50, .2), ("✦", .60, .4), ("✦", .80, .7),
    ("✦", 1.0, 1.0), ("✦", .85, .8), ("✦", .70, .5), ("✦", .60, .2), *(("✦", .50, 0),) * 10,
    ("✦", .40, 0), ("⋅", .35, 0), ("∙", .25, 0), ("∙", .20, 0),
)
# The band, trailing edge first: lighter blue, lavender at its crest, purple where it leads.
GEMINI_BAND_DARK = ("#8CBDF0", "#B4C4F4", "#D9CDF5", "#C2AEEA", "#A48FD6")   # on a dark background
GEMINI_BAND_LIGHT = ("#2F6FBF", "#4A62C2", "#6553BD", "#7A4DB5", "#8A5CB8")  # on a light one
PALETTE_DIM = 0x130
PENDING_LIGHT_STEP = (80, 100)  # ms per column of the band: stock, patched


def _breath_frame(glyph: str, light: float, hue: float) -> bytes:
    mix = lambda a, b, t: tuple(round(x + (y - x) * t) for x, y in zip(a, b))
    rgb = lambda h: ((h >> 16) & 255, (h >> 8) & 255, h & 255)
    tone = mix(rgb(GEMINI_BLUE), rgb(GEMINI_PURPLE), hue)
    r, g, b = mix((0, 0, 0), tone, light / 0.5) if light < 0.5 else mix(tone, (255, 255, 255), (light - 0.5) * 0.9)
    return f"\x1b[38;2;{r};{g};{b}m{glyph}\x1b[m ".encode()


def _adrp_add_at(data: bytes | bytearray, off: int, rd: int) -> int | None:
    """Target VA of `adrp xR; add xR, xR, #lo` at `off`, else None."""
    w0, w1 = struct.unpack_from("<II", data, off)
    if w0 & 0x9F00001F != 0x90000000 | rd or w1 & 0xFFC003FF != 0x91000000 | (rd << 5) | rd:
        return None
    return decode_adrp_add(data, off)


def _slice_loads(data: bytes | bytearray, bounds: tuple[int, int]) -> list[tuple[int, int]]:
    """(offset, global VA) of every `adrp x27; add x27, x27, #lo; ldp xA, xB, [x27]` in `bounds`."""
    return [
        (o, va) for o in range(bounds[0], bounds[1] - 8, 4)
        if (va := _adrp_add_at(data, o, 27)) is not None
        and struct.unpack_from("<I", data, o + 8)[0] & 0xFFFF83E0 == 0xA9400360  # ldp xA, xB, [x27]
    ]


def _recoverable(data: bytes | bytearray, off: int, patched: bytes, original: bytes | None = None) -> bytes | None:
    """A site's original bytes: given, or read from the binary unless they already are the patch.

    A patched binary holds no stock bytes to recover; None makes --revert without a backup refuse
    instead of writing the patch back over itself.
    """
    current = bytes(data[off : off + len(patched)]) if original is None else original
    return None if current == patched else current


def _turn_color(t: float) -> tuple[int, int, int]:
    """The Gemini gradient at t in [0, 1]: blue, purple at the middle, rose at the end."""
    rgb = lambda h: ((h >> 16) & 255, (h >> 8) & 255, h & 255)
    a, b, u = (GEMINI_BLUE, GEMINI_PURPLE, t * 2) if t <= 0.5 else (GEMINI_PURPLE, GEMINI_ROSE, t * 2 - 1)
    return tuple(round(x + (y - x) * u) for x, y in zip(rgb(a), rgb(b)))


def _go_frame(data: bytes | bytearray, bounds: tuple[int, int]) -> int:
    """The bytes a Go function's prologue takes off sp: `str x30, [sp, #-n]!`, `sub x20, sp, #n`, or
    `mov x27, #n; sub x20, sp, x27`. The caller's sp is the callee's plus this."""
    for off in range(bounds[0], bounds[0] + 0x20, 4):
        w, nxt = struct.unpack_from("<II", data, off)
        frame = None
        if w & 0xFFE00FFF == 0xF8000FFE:                         # str x30, [sp, #-n]!
            frame = (-((w >> 12) & 0x1FF)) & 0x1FF
        elif w & 0xFF8003FF == 0xD10003F4:                       # sub x20, sp, #lo (or #hi, lsl #12)
            frame = ((w >> 10) & 0xFFF) << (12 if w & 0x400000 else 0)
            if nxt & 0xFFC003FF == 0xD1400294:                   # then sub x20, x20, #hi, lsl #12
                frame += ((nxt >> 10) & 0xFFF) << 12
        elif w & 0xFFE0001F == 0xD280001B and nxt == 0xCB3B63F4:  # mov x27, #n; sub x20, sp, x27
            frame = (w >> 5) & 0xFFFF
        if frame is not None:
            if frame % 8:
                raise RuntimeError(f"Frame of {frame:#x} bytes at {hex(VM_BASE + bounds[0])} is not 8-byte aligned")
            return frame
    raise RuntimeError(f"No frame-reserving prologue at {hex(VM_BASE + bounds[0])}")


def _gemini_fill(data: bytes | bytearray) -> tuple[int, bytes, dict]:
    """The strings Sites #49 and #56 add, laid out at the end of the __TEXT fill: (offset, blob, VAs).

    `at` maps each frame and band color (bytes) to its VA, and holds "rgba" (the word's color for each
    stage of a long turn, 4 bytes each, blue first) and
    "verbs" (16-byte records: a length byte, then the verb). Nothing here holds a pointer: a pointer in
    new memory would not be slid by the loader (Site #49's note), so code addresses these PC-relatively.
    """
    frames = list(dict.fromkeys(_breath_frame(*f) for f in SPINNER_BREATH))
    colors = [c.encode() for c in GEMINI_BAND_DARK + GEMINI_BAND_LIGHT]
    rgba = b"".join(bytes((*_turn_color(i / (TURN_STAGES - 1)), 255)) for i in range(TURN_STAGES))
    if any(not 0 < len(v) < 16 or not v.isascii() for v in PENDING_VERBS):
        raise RuntimeError("each pending-line verb must be 1-15 ASCII bytes")
    verbs = b"".join((bytes([len(v)]) + v.encode()).ljust(16, b"\x00") for v in PENDING_VERBS)
    marks = [m.encode() for m in TOOL_MARKS.values()]
    blob = verbs + rgba + b"".join(frames) + b"".join(colors) + b"".join(marks)
    fill, fill_end = _text_tail_cave(data)
    cave = (fill_end - len(blob)) & ~0xF
    if cave < fill + 0x400:  # leave the head of the fill to the sites that grow from it (#55a)
        raise RuntimeError(f"__TEXT has {fill_end - fill}B of fill; Sites #49 and #56 need {len(blob)}B at its end")
    if bytes(data[cave : cave + len(blob)]) not in (bytes(len(blob)), blob):
        raise RuntimeError(f"__TEXT fill at {hex(VM_BASE + cave)} holds neither zeros nor the Gemini strings")
    at: dict = {"verbs": VM_BASE + cave, "rgba": VM_BASE + cave + len(verbs)}
    pos = at["rgba"] + len(rgba)
    for x in frames + colors + marks:
        at[x] = pos
        pos += len(x)
    return cave, blob, at


def _resolve_spinner_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #49a-#49i: the breathing star, the Gemini band over a blue word, one space after the frame."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    read = lambda va, n: bytes(data[va - VM_BASE : va - VM_BASE + n])
    slice_at = lambda va: struct.unpack_from("<QQQ", data, va - VM_BASE)
    sites: list[PatchSite] = []

    def site(name: str, off: int, original: bytes | None, patched: bytes) -> None:
        orig = None if original is None else _recoverable(data, off, patched, original)
        sites.append(PatchSite("palette-typography", name, VM_BASE + off, off, orig, patched))

    def stock_or_none(off: int, patched: bytes) -> bytes | None:
        """The bytes a code site replaces, unless they already are its patch (no original to recover)."""
        current = bytes(data[off : off + len(patched)])
        return None if current == patched else current

    # Halloween's registration: `adrp x0, itab; add x0; adrp x1, value; add x1; bl theme.Register`.
    h0 = funcs["halloweenInit0"]
    reg = [o for o in range(h0[0], h0[1] - 16, 4)
           if (itab := _adrp_add_at(data, o, 0)) is not None and _adrp_add_at(data, o + 8, 1) is not None
           and (branch_target(word(o + 16), o + 16) == funcs["themeRegister"][0] or bytes(data[o + 16 : o + 20]) == NOP)]
    if len(reg) != 1:
        raise RuntimeError("halloween.init.0 no longer registers one theme value")
    theme_itab, theme_value, reg_call = _adrp_add_at(data, reg[0], 0), _adrp_add_at(data, reg[0] + 8, 1), reg[0] + 16

    # Halloween's logo rows: halloween.init copies two 14-row []string tables that lie end to end.
    rows = []
    for _, va in _slice_loads(data, funcs["halloweenInit"]):
        ptr, n, cap = slice_at(va)
        if n == cap == 14 and VM_BASE < ptr < VM_BASE + len(data) and (ptr, n) not in rows:
            rows.append((ptr, n))
    rows.sort()
    if len(rows) != 2 or rows[0][0] + 16 * rows[0][1] != rows[1][0]:
        raise RuntimeError(f"halloween.init: expected two adjacent 14-row logo tables, found {rows}")
    table_va = rows[0][0]
    if len(SPINNER_BREATH) > rows[0][1] + rows[1][1]:
        raise RuntimeError("Halloween's logo tables hold fewer slots than the breath has frames")

    # The band's two tables: halloween.RunningLight returns the light-background one when its flag is set.
    hr = funcs["halloweenRunningLight"]
    bands = [slice_at(va) for _, va in _slice_loads(data, hr)]
    if len(bands) != 2 or any(n != cap or n != len(GEMINI_BAND_DARK) for _, n, cap in bands):
        raise RuntimeError("halloween.RunningLight no longer returns two 5-color tables")
    (light_va, _, _), (dark_va, _, _) = bands  # fall-through (flag set) first, then the branch target

    # 49a. The strings, at the end of the __TEXT fill (with the pending line's verbs, Site #56a, and the
    # tool marks, Site #57).
    cave, blob, at = _gemini_fill(data)
    frames = [_breath_frame(*f) for f in SPINNER_BREATH]
    site("__TEXT fill -> the breathing star's frames, the Gemini band, the long-turn colors, the pending line's verbs, and the tool marks",
         cave, bytes(len(blob)), blob)

    # 49b. Halloween's logo rows -> the 24 frames.
    table = b"".join(struct.pack("<QQ", at[f], len(f)) for f in frames)
    site("halloween logo rows -> the breathing star's 24 frames", table_va - VM_BASE,
         read(table_va, len(table)), table)

    # 49c. The frame slice: (ptr, len, cap) of the 8 braille frames -> the 24.
    stock_run = _find_all(data, SPINNER_STOCK)
    if len(stock_run) != 1:
        raise RuntimeError(f"Expected one braille spinner run, found {len(stock_run)}")
    stock_arr = _find_all(data, b"".join(struct.pack("<QQ", VM_BASE + stock_run[0] + 4 * i, 4) for i in range(8)))
    if len(stock_arr) != 1:
        raise RuntimeError(f"Expected one braille frame table, found {len(stock_arr)}")
    stock_hdr, our_hdr = struct.pack("<QQQ", VM_BASE + stock_arr[0], 8, 8), struct.pack("<QQQ", table_va, len(frames), len(frames))
    hdrs = _find_all(data, stock_hdr) + _find_all(data, our_hdr)
    if len(hdrs) != 1:
        raise RuntimeError(f"Expected one spinner frame slice, found {len(hdrs)}")
    site("spinner frame slice -> 24 frames of the breathing star", hdrs[0], stock_hdr, our_hdr)

    # 49d. halloween.init.0 no longer registers the theme: its logo rows now hold the frames.
    site("halloween.init.0 -> Halloween is not registered (its logo rows hold the spinner frames)",
         reg_call, encode_bl(VM_BASE + reg_call, VM_BASE + funcs["themeRegister"][0]), NOP)

    # 49e. The band colors, in both of Halloween's tables.
    for va, band in ((dark_va, GEMINI_BAND_DARK), (light_va, GEMINI_BAND_LIGHT)):
        patched = b"".join(struct.pack("<QQ", at[c.encode()], len(c)) for c in band)
        bg = "dark" if band is GEMINI_BAND_DARK else "light"
        site(f"halloween running-light colors ({bg} background) -> the Gemini band", va - VM_BASE,
             read(va, len(patched)), patched)

    # 49f. renderPendingLight: the theme it lights with. Stock tests `cbz x9` (no theme settings), then
    # the forced flag and the configured ID; the value goes in x9 (itab) and x12 (data), and every path
    # meets at `cbz x9, stock` before the call. Take Halloween's value and go straight to the call.
    rp = funcs["renderPendingLight"]
    calls = _calls_to(data, rp, funcs["themerenderRunningLight"][0])
    if len(calls) != 1 or word(calls[0] - 0x28) & 0xFF00001F != 0xB4000009:  # cbz x9, stock
        raise RuntimeError("renderPendingLight no longer tests its theme just before lighting with it")
    merge = calls[0] - 0x24

    def gate(o: int) -> bytes:
        return (encode_adrp_add(VM_BASE + o, theme_itab, 9) + encode_adrp_add(VM_BASE + o + 8, theme_value, 12)
                + encode_b(VM_BASE + o + 16, VM_BASE + merge))

    gates = [o for o in range(rp[0], merge - 20, 4)
             if (word(o) & 0xFF00001F == 0xB4000009 and word(o + 4) & 0xFFC003FF == 0x3940012C)  # cbz x9; ldrb w12, [x9, #imm]
             or bytes(data[o : o + 20]) == gate(o)]
    if len(gates) != 1:
        raise RuntimeError(f"renderPendingLight: expected one theme-settings test, found {len(gates)}")
    site("model.(*ConversationModel).renderPendingLight -> always light with the theme path, as Halloween",
         gates[0], stock_or_none(gates[0], gate(gates[0])), gate(gates[0]))

    # 49g. renderPendingLight: the band's step for the default and `medium` speeds (`mov x0, #40; mov x4, #80`).
    movz = lambda rd, imm: 0xD2800000 | (imm << 5) | rd
    steps = [o + 4 for o in range(rp[0], rp[1] - 4, 4)
             if word(o) == movz(0, 40) and word(o + 4) in (movz(4, PENDING_LIGHT_STEP[0]), movz(4, PENDING_LIGHT_STEP[1]))]
    if len(steps) != 2:
        raise RuntimeError(f"renderPendingLight: expected two medium-speed steps, found {len(steps)}")
    for o, speed in zip(steps, ("`medium`", "the default")):
        site(f"model.(*ConversationModel).renderPendingLight -> at {speed} speed the band moves a column per {PENDING_LIGHT_STEP[1]} ms",
             o, pack(movz(4, PENDING_LIGHT_STEP[0])), pack(movz(4, PENDING_LIGHT_STEP[1])))

    # 49h. runningLightAt: the base under the band. Stock looks the palette up (`adrp x27; ldr x1, map;
    # adrp x0; add x0; add x2, sp; add x2; bl mapaccess1`) and reads palette[+0x130] into x2/x3. Those eight
    # instructions become a branch to a leaf in the __TEXT fill, which loads a boxed color instead: x2 =
    # color.RGBA's color.Color itab, x3 = the 4 bytes of the turn's stage. The call goes, none comes.
    # The stage: runningLightAt has the time (Unix ms, its third argument, spilled at entry); the turn's
    # start is on the model, and the model is spilled by pendingLineView, three frames up
    # (runningLightAt <- themerender.RunningLight <- renderPendingLight <- pendingLineView, each the only
    # caller). wall = 1<<63 | seconds since 1885 << 30 | ns while the time carries a monotonic reading.
    hexes = {_adrp_add_at(data, o + 4, 0) for o in range(funcs["lipglossColor"][0], funcs["lipglossColor"][1] - 8, 4)
             if word(o) == 0xAA0003E1}  # mov x1, x0 (the boxed RGBA), then adrp x0, itab
    hexes.discard(None)
    if len(hexes) != 1:
        raise RuntimeError("lipgloss.Color no longer boxes a hex as one color.Color type")
    rgba_itab = hexes.pop()
    la, tr, pv = funcs["themeRunningLightAt"], funcs["themerenderRunningLight"], funcs["pendingLineView"]
    chain = [(la, tr), (tr, rp), (rp, pv)]
    for callee, caller in chain:
        if not _calls_to(data, caller, callee[0]):
            raise RuntimeError(f"{hex(VM_BASE + callee[0])} is no longer called from {hex(VM_BASE + caller[0])}")
    m_slot = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (pv[0], pv[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    ms_slot = next((sl[1] for _, w in _words(data, (la[0], la[0] + 0x40)) if (sl := _sp_slot(w, 0xF90003E0)) and sl[0] == 2), None)
    if m_slot is None or ms_slot is None:
        raise RuntimeError("pendingLineView's m spill or runningLightAt's time spill moved")
    walk = _go_frame(data, la) + _go_frame(data, tr) + _go_frame(data, rp) + m_slot
    _, _, start = _turn_start(data, funcs["refreshActivityLabel"])
    if walk > 0x7FF8 or walk % 8 or start >> 24 or (start & 0xFFF) % 8:
        raise RuntimeError("runningLightAt: the model or its turn start is out of reach of one load")
    epoch = (1969 * 365 + 1969 // 4 - 1969 // 100 + 1969 // 400 - (1884 * 365 + 1884 // 4 - 1884 // 100 + 1884 // 400)) * 86400
    movz = lambda rd, imm, sh=0: 0xD2800000 | (sh // 16) << 21 | (imm << 5) | rd
    movk = lambda rd, imm, sh: 0xF2800000 | (sh // 16) << 21 | (imm << 5) | rd
    la_ldp = 0xA9400C02 | ((PALETTE_DIM // 8) << 15)  # stock: ldp x2, x3, [x0, #0x130]
    light_va = VM_BASE + _light_detour_base(data)

    def light(back: int) -> bytes:
        code = pack(
            _ldr_sp(9, walk),                                                       # x9 = m
            0x91400000 | ((start >> 12) << 10) | (9 << 5) | 27,                     # add x27, x9, #hi, lsl #12
            0xF9400369 | (((start & 0xFFF) // 8) << 10),                            # ldr x9, [x27, #lo]  (wall)
            0xB4000009 | (16 << 5),                                                 # cbz x9, past: no turn, stage 0
            0xD35EF929,                                                             # ubfx x9, x9, #30, #33 (seconds since 1885)
            movz(10, epoch & 0xFFFF), movk(10, epoch >> 16, 16),                    # x10 = 1970 - 1885 in seconds
            0xCB0A0129,                                                             # sub x9, x9, x10 (the start, Unix)
            _ldr_sp(10, ms_slot), movz(11, 1000), 0x9ACB094A,                       # x10 = now ms / 1000
            0xCB090149,                                                             # x9 = now - start (seconds)
            0xF1000129 | (LONG_TURN << 10),                                         # subs x9, x9, #LONG_TURN
            0x9A9FC129,                                                             # csel x9, x9, xzr, gt
            movz(11, STAGE_SECONDS), 0x9ACB0929,                                    # x9 /= STAGE_SECONDS
            movz(11, TURN_STAGES - 1), 0xEB0B013F, 0x9A8B3129,                      # x9 = min(x9, stages - 1)
        )
        assert len(code) == 4 * 19  # the cbz above skips to the end of these
        here = light_va + len(code)
        code += encode_adrp_add(here, at["rgba"], 3) + pack(0x8B090863)              # x3 = &stages[x9] (add x3, x3, x9, lsl #2)
        code += encode_adrp_add(here + 12, rgba_itab, 2)                            # x2 = the color.Color itab
        return code + encode_b(here + 20, back)

    def base_load(o: int) -> bytes:
        return encode_b(VM_BASE + o, light_va) + NOP * 7

    dims = [o - 0x1C for o in range(la[0] + 0x1C, la[1] - 4, 4)
            if (word(o) == la_ldp and word(o - 4) >> 26 == 0x25 and word(o - 0x1C) & 0x9F00001F == 0x9000001B)
            or bytes(data[o - 0x1C : o + 4]) == base_load(o - 0x1C)]
    if len(dims) != 1:
        raise RuntimeError(f"themerender.runningLightAt: expected one palette lookup for the band's base, found {len(dims)}")
    detour = light(VM_BASE + dims[0] + 0x20)
    if len(detour) > LIGHT_LEAF_ROOM:
        raise RuntimeError(f"the stage-color leaf takes {len(detour)}B; it has {LIGHT_LEAF_ROOM}B before Site #50i")
    if bytes(data[light_va - VM_BASE : light_va - VM_BASE + len(detour)]) not in (bytes(len(detour)), detour):
        raise RuntimeError(f"__TEXT fill at {hex(light_va)} holds neither zeros nor the stage-color leaf")
    site("themerender.runningLightAt -> the band's base is the turn's stage color, not palette[+0x130]",
         dims[0], stock_or_none(dims[0], base_load(dims[0])), base_load(dims[0]))
    site("__TEXT fill -> runningLightAt's leaf: seconds into the turn -> a color from blue through purple to rose",
         light_va - VM_BASE, bytes(len(detour)), detour)

    # 49i. One space between the star and the word. pendingLineView appends " " to the frame,
    # `concatstring2(nil, frame, " ")` (`mov x2, x1; adrp x3; add x3; orr x4, xzr, #1; mov x1, x0;
    # mov x0, xzr`), though the frame already ends in one; the appended string's length becomes 0.
    pv = funcs["pendingLineView"]
    cats = [c - 24 for c in _calls_to(data, pv, funcs["concatstring2"][0])
            if word(c - 24) == 0xAA0103E2 and word(c - 20) & 0x9F00001F == 0x90000003
            and data[decode_adrp_add(data, c - 20) - VM_BASE] == 0x20
            and word(c - 12) in (0xB24003E4, 0xAA1F03E4)              # orr x4, xzr, #1 / mov x4, xzr
            and bytes(data[c - 8 : c]) == bytes.fromhex("e10300aae0031faa")]  # mov x1, x0; mov x0, xzr
    if len(cats) != 1:
        raise RuntimeError(f"pendingLineView: expected one `frame + \" \"`, found {len(cats)}")
    o = cats[0] + 12
    site("model.(*ConversationModel).pendingLineView -> the frame keeps its one space; no second",
         o, stock_or_none(o, pack(0xAA1F03E4)), pack(0xAA1F03E4))

    # 49j-49k. A blank row between the conversation and the pending line, in every state. Stock keeps
    # the pending row whether or not a turn runs (blank when idle), so the conversation and the input
    # never move when a turn starts or ends; the gap follows that rule and makes the block two rows.
    # Every height reads the layout: View and messageListViewportHeight size the conversation as the
    # terminal's height less the sum of its fields, and populateLayout writes the pending row's into
    # field 2 as `(m+0x5c760 == 0) + pendingDecoration's rows` (`cmp x2, #0; cset x2, eq; ...;
    # add x2, x2, x3`). #49j counts that row twice: `add x2, x3, x2, lsl #1`. (Field 3, which an
    # earlier version set to 2, holds the tip's row; a newline counted nowhere drew the line a row low
    # and pushed the status line off the alternate screen.)
    pl = funcs["populateLayout"]
    deco = funcs["pendingDecoration"][0]
    rows = [c for c in _calls_to(data, pl, deco)]
    adds = [o for c in rows for o in range(c + 4, c + 0x60, 4)
            if word(o) == 0xF100005F and word(o + 4) == 0x9A9F17E2                  # cmp x2, #0; cset x2, eq
            and word(o + 16) in (0x8B030042, 0x8B020462)]                            # add x2, x2, x3 (or patched)
    if len(rows) != 1 or len(adds) != 1:
        raise RuntimeError(f"populateLayout: expected one pending-row reservation, found {len(adds)}")
    site("model.(*ConversationModel).populateLayout -> the pending row is reserved twice: the gap, then the line",
         adds[0] + 16, stock_or_none(adds[0] + 16, pack(0x8B020462)), pack(0x8B020462))

    # 49k. The drawn rows match: every non-empty pending line leaves pendingLineView as "\n" + line.
    # Its tail joins `decoration + "\n" + line` only when a decoration exists (`bl pendingDecoration;
    # cbnz x1, join; ldr x1, [sp, #len]; ldr x0, [sp, #ptr]; b out`). Now a non-empty line takes the
    # join too (`ldr x2, [sp, #len]; cbnz x2, join`), and an empty one without decoration still leaves
    # empty (x1 is the decoration's length, 0). The join's first instruction branches to a leaf in the
    # __TEXT fill (a `cbnz` reaches 1 MB, the fill is farther), which sets up `concatstring3(nil,
    # decoration, sep, line)` and returns to the join's own call: sep is "\n\n" when both parts exist,
    # so the decoration keeps its row and the gap sits under it, else "\n".
    pv = funcs["pendingLineView"]
    tails = [c for c in _calls_to(data, pv, deco)]
    if len(tails) != 1:
        raise RuntimeError(f"pendingLineView: expected one pendingDecoration call, found {len(tails)}")
    c = tails[0]
    ldr_sp = lambda rt, imm: 0xF94003E0 | (imm // 8) << 10 | rt
    str_imm = lambda w: ((w >> 10) & 0xFFF) * 8
    if word(c - 12) & 0xFFC003FF != 0xF90003E1 or word(c - 8) & 0xFFC003FF != 0xF90003E0:  # str x1/x0, [sp, #...]
        raise RuntimeError("pendingLineView no longer spills its line before pendingDecoration")
    len_slot, ptr_slot = str_imm(word(c - 12)), str_imm(word(c - 8))
    join, out = c + 0x14, branch_target(word(c + 16), c + 16)
    call3 = join + 0x20
    if (branch_target(word(c + 4), c + 4) != join or branch_target(word(call3), call3) != funcs["concatstring3"][0]
            or word(c + 16) >> 26 != 0x05 or word(join) not in (0xAA0103E2, *struct.unpack("<I", encode_b(VM_BASE + join, VM_BASE + _gap_leaf_base(data))))):
        raise RuntimeError("pendingLineView's tail no longer joins decoration, newline and line")
    nn = next((o for o in _find_all(data, b"\n\n") if o >= _text_section(data)[1]), None)
    if nn is None or nn >= _text_tail_cave(data)[0]:
        raise RuntimeError("no blank line in __TEXT's data to open the pending block with")
    leaf = _gap_leaf_base(data)
    cbnz = lambda pc, target, rt: struct.pack("<I", 0xB5000000 | (((target - pc) // 4) & 0x7FFFF) << 5 | rt)
    code = (pack(0xAA0103E2, 0xAA0003E1)                                   # mov x2, x1; mov x1, x0
            + encode_adrp_add(VM_BASE + leaf + 8, VM_BASE + nn, 3)          # x3 = "\n\n"
            + pack(0xB24003E4, ldr_sp(5, ptr_slot), ldr_sp(6, len_slot),   # x4 = 1; x5, x6 = line
                   0xF100005F, 0xFA4018C4, 0x9A840484, 0xAA1F03E0)         # cmp x2, #0; ccmp x6, #0, #4, ne; cinc x4, x4, ne; mov x0, xzr
            + encode_b(VM_BASE + leaf + 44, VM_BASE + call3))
    if len(code) > GAP_LEAF_ROOM:
        raise RuntimeError(f"the pending gap's leaf takes {len(code)}B; it has {GAP_LEAF_ROOM}B")
    site("__TEXT fill -> pendingLineView's leaf: a blank row above the line, under any decoration",
         leaf, bytes(len(code)), code)
    tail = pack(ldr_sp(2, len_slot)) + cbnz(c + 12, join, 2)
    site("model.(*ConversationModel).pendingLineView -> a non-empty line takes the decoration's join too",
         c + 8, stock_or_none(c + 8, tail), tail)
    jump = encode_b(VM_BASE + join, VM_BASE + leaf)
    site("model.(*ConversationModel).pendingLineView -> the join sets up in the gap's leaf",
         join, stock_or_none(join, jump), jump)

    # 49l. The band goes back and forth. RunningLightWindow(n, now, step, longStep) places the band:
    # text of 25 or more columns (`cmp x0, #0x19; b.ge long`) already swings, a triangle wave of period
    # 2(n + w + 5) at longStep; shorter text wrapped one way, `(now / step) % (n + w + 6)`. The short
    # branch now computes the same swing at its own step and joins the long branch's tail
    # (`sub x3, x3, x4; ...`). Every short running light swings: the pending word, a short live
    # thought, search. The period is at least 10, so the division needs no zero test.
    rlw = funcs["runningLightWindow"]
    gate = [o for o, w in _words(data, (rlw[0], rlw[0] + 0x40)) if w == 0xF100641F and word(o + 4) & 0xFF00001F == 0x5400000A]
    if len(gate) != 1:
        raise RuntimeError("RunningLightWindow no longer tests for 25 columns")
    short, tail = gate[0] + 8, branch_target(word(gate[0] + 4), gate[0] + 4) + 0x28
    swing_stock = (0xB4000182, 0x9AC20C23, 0xB4000506, 0x9AC60C7B, 0x9B068F63, 0xCB040063, 0xD1000C60, 0xAA0403E1,
                   0xB24003E2, 0xF85F83FD)
    swing = (pack(word(short), 0x9AC20C23,                       # cbz x2, none; sdiv x3, x1, x2  (t = now / step)
                  0x8B0600C5, 0xD10008A5,                        # add x5, x6, x6; sub x5, x5, #2  (P = 2(n + w + 5))
                  0x9AC50C7B, 0x9B058F63,                        # sdiv x27, x3, x5; msub x3, x27, x5, x3  (p = t % P)
                  0xCB0300A5, 0xEB06007F, 0x9A85B063)            # sub x5, x5, x3; cmp x3, x6; csel x3, x3, x5, lt
             + encode_b(VM_BASE + short + 36, VM_BASE + tail))
    if word(tail) != 0xCB040063 or tuple(struct.unpack_from("<10I", data, short)) not in (swing_stock, struct.unpack("<10I", swing)):
        raise RuntimeError("RunningLightWindow's branches no longer have the shape the swing rewrites")
    site("render.RunningLightWindow -> short text swings back and forth too, at its own step",
         short, stock_or_none(short, swing), swing)
    return tuple(sites)


# Sites #50a-#50i: the pending line drops its `...` and carries a faint elapsed time, `◐ Thinking  8s`.
# Stock times only compaction: refreshActivityLabel stamps a start while the state is Compacting and
# clears it otherwise, and compactingLabel(start, now) formats `Compacting conversation… (12s · esc to
# cancel)`. The stamp widens to every busy state, so it marks the turn's start. compactingLabel, whose
# only caller is the Compacting branch of activityCandidate, becomes elapsedSuffix(m, pad), returning
# `  ESC[2m<duration padded to pad-2>ESC[22m`. pendingLineView already computes that padding, which
# right-aligns an artifact status (`2 artifacts · /artifact to review`), so the suffix takes the
# padding's place and its call: the suffix sits right after the text, the status stays right-aligned,
# and no call is added anywhere. A call added to a function whose stack maps do not describe it would
# leave the garbage collector scanning the frame by the wrong map.
ELLIPSIS = "…"
# args: (width int, duration string). Explicit indexes print the time first and pad after it: `%-[1]*.0[2]s`
# is the time again, cut to nothing, left-justified in `width` columns. (Reordered, fmt reports no EXTRA.)
# The aside is a fixed gray, `#999999`, as Claude Code's is (sampled at `#989898`); faint dimmed the
# foreground to `#646464`, a step darker than the word beside it needs.
ELAPSED_FORMAT = b" \x1b[38;2;153;153;153m(%[2]s)%-[1]*.0[2]s\x1b[39m"  # one space after the verb, as a sentence
# By the state's kind (Site #50i): a thought, a tool call. Any other state shows the time alone.
# `⋅` (U+22C5) is East Asian Width neutral, one column everywhere; `·` (U+00B7) is ambiguous, two
# columns under a CJK locale, which the padding (one column per character) would not count.
ELAPSED_STATES = {3: " ⋅ thinking", 4: " ⋅ running"}
ELAPSED_LONG_THOUGHT = " ⋅ deep in thought"  # a thought past LONG_TURN seconds, as Claude Code words it
# A thought names its effort, as Claude Code's does: `(6s ⋅ thinking with high effort)`. The effort is
# the one the model's label carries, `Gemini 4 Hydrogen (High)`: the label word, then the word shown,
# the footer's own (`· high`). A label without one of these shows `thinking` alone. Each suffix is at
# most 8 bytes, the one load the matcher compares.
EFFORT_WORDS = (("(Low)", "low"), ("(Medium)", "medium"), ("(High)", "high"), ("(XHigh)", "xhigh"), ("(Max)", "max"))
EFFORT_PHRASE = " with {} effort"
ELAPSED_RESERVE = 50  # columns the text gives up: ` (120m 5s ⋅ deep in thought with medium effort)` and slack
MOV_X6_XZR = 0xAA1F03E6


def _words(data: bytes | bytearray, bounds: tuple[int, int]) -> list[tuple[int, int]]:
    return [(o, struct.unpack_from("<I", data, o)[0]) for o in range(bounds[0], bounds[1], 4)]


def _calls_to(data: bytes | bytearray, bounds: tuple[int, int], target: int) -> list[int]:
    """File offsets of every `bl` in `bounds` to the function at file offset `target`."""
    return [o for o, w in _words(data, bounds) if w >> 26 == 0x25 and branch_target(w, o) == target]


def _str_sp(rt: int, imm: int) -> int:
    return 0xF90003E0 | ((imm // 8) << 10) | rt


def _ldr_sp(rt: int, imm: int) -> int:
    return 0xF94003E0 | ((imm // 8) << 10) | rt


def _sp_slot(word: int, base: int) -> tuple[int, int] | None:
    """(rt, imm) of `str`/`ldr xT, [sp, #imm]` matching `base` (0xF90003E0 or 0xF94003E0), else None."""
    if word & 0xFFC003E0 != base:
        return None
    return word & 0x1F, ((word >> 10) & 0xFFF) * 8


def _turn_start(data: bytes | bytearray, rf: tuple[int, int]) -> tuple[int, int, int]:
    """(offset of refreshActivityLabel's Compacting test, VA of its stamp branch, model offset of the start).

    Stock stamps a start time only while compacting; Site #50b widens it to every busy state, so the
    field holds the turn's start: a time.Time, its `wall` word first.
    """
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    stamp = [o for o, w in _words(data, (rf[0], rf[1] - 4)) if w in (0xF1001C7F, 0xF100007F) and word(o + 4) & 0xFF00001E == 0x54000000]
    if len(stamp) != 1:
        raise RuntimeError(f"refreshActivityLabel: expected one Compacting test, found {len(stamp)}")
    stamp_va = branch_target(word(stamp[0] + 4), stamp[0] + 4) + VM_BASE
    # The stamped field: `add x27, xN, #lo; add x27, x27, #hi, lsl #12; ldp x5, x6, [x27]`.
    lo_add, hi_add = word(stamp_va - VM_BASE + 4), word(stamp_va - VM_BASE + 8)
    if lo_add & 0xFFC0001F != 0x9100001B or hi_add & 0xFFC003FF != 0x9140037B:
        raise RuntimeError("refreshActivityLabel: the Compacting branch no longer addresses its start field")
    return stamp[0], stamp_va, ((hi_add >> 10) & 0xFFF) << 12 | ((lo_add >> 10) & 0xFFF)


def _thought_states() -> list[str]:
    """A thought's state by `long * (1 + len(EFFORT_WORDS)) + effort`, effort 0 when the label names none."""
    efforts = [""] + [EFFORT_PHRASE.format(shown) for _, shown in EFFORT_WORDS]
    return [base + e for base in (ELAPSED_STATES[3], ELAPSED_LONG_THOUGHT) for e in efforts]


def _elapsed_formats() -> dict:
    """The aside's formats: kind -> format for the states other than a thought, ("thought", i) for each
    of a thought's states (_thought_states)."""
    with_state = lambda st: ELAPSED_FORMAT.replace(b")%", st.encode() + b")%")
    formats = {k: with_state(st) for k, st in ELAPSED_STATES.items() if k != 3}
    formats.update({("thought", i): with_state(st) for i, st in enumerate(_thought_states())})
    return formats


ELAPSED_CODE = 0x280  # bytes the detours, the effort matcher and its tables may take before the formats


def _elapsed_base(data: bytes | bytearray) -> int:
    """File offset of Site #50i's detours and formats, just before the Gemini strings in the __TEXT fill."""
    gemini, _, _ = _gemini_fill(data)
    base = (gemini - len(b"".join(_elapsed_formats().values())) - ELAPSED_CODE - 0x10) & ~0xF
    if base < _text_tail_cave(data)[0] + 0x400:
        raise RuntimeError("the __TEXT fill has no room for elapsedSuffix's detours")
    return base


LIGHT_LEAF_ROOM = 0x80  # bytes Site #49h's leaf may take before Site #50i's detours


GAP_LEAF_ROOM = 0x40  # bytes Site #49k's leaf may take before Site #49h's


def _gap_leaf_base(data: bytes | bytearray) -> int:
    """File offset of Site #49k's leaf, before Site #49h's stage-color leaf."""
    base = (_light_detour_base(data) - GAP_LEAF_ROOM) & ~0xF
    if base < _text_tail_cave(data)[0] + 0x400:
        raise RuntimeError("the __TEXT fill has no room for the pending gap's leaf")
    return base


def _light_detour_base(data: bytes | bytearray) -> int:
    """File offset of Site #49h's stage-color leaf, before Site #50i's detours."""
    base = (_elapsed_base(data) - LIGHT_LEAF_ROOM) & ~0xF
    if base < _text_tail_cave(data)[0] + 0x400:
        raise RuntimeError("the __TEXT fill has no room for the stage-color leaf")
    return base


def _model_label_path(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> dict:
    """Field offsets from the conversation model to the model's label, read from agy's own accessors:
    m.manager (messageListViewportHeight: `ldr x1, [x0, #off]`), manager.store (Manager.Store:
    `ldr x0, [x0, #off]`), store.config and config.label (currentModelLabel: `ldr x1, [x0, #off];
    cbz x1; ldp x0, x2, [x1, #off]`)."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    imm = lambda w: ((w >> 10) & 0xFFF) * 8
    mv = [imm(w) for _, w in _words(data, (funcs["messageListViewportHeight"][0], funcs["messageListViewportHeight"][0] + 0x30))
          if w & 0xFFC003FF == 0xF9400001]
    st = [imm(w) for _, w in _words(data, funcs["managerStore"]) if w & 0xFFC003FF == 0xF9400000]
    cl = funcs["currentModelLabel"]
    lab = [(imm(word(o)), ((word(o + 8) >> 15) & 0x7F) * 8) for o, w in _words(data, (cl[0], cl[1] - 8))
           if w & 0xFFC003FF == 0xF9400001 and word(o + 4) & 0xFF00001F == 0xB4000001
           and word(o + 8) & 0xFFC07FFF == 0xA9400820]
    if len(mv) != 1 or len(st) != 1 or len(lab) != 1:
        raise RuntimeError("the model label's path (manager, store, config, label) no longer reads as one load each")
    return {"manager": mv[0], "store": st[0], "config": lab[0][0], "label": lab[0][1]}


def _elapsed_detours(data: bytes | bytearray, funcs: dict[str, tuple[int, int]], fmt_off: int,
                     width_slot: int, dur_len_slot: int, secs_slot: int, conv: int, fmt_load: int) -> dict:
    """Site #50i: elapsedSuffix's two detours, and the state formats they choose, before the Gemini strings.

    elapsedSuffix(m, pad) is called only from pendingLineView, which spilled m in its own frame; the
    callee reads it there (`[sp + frame + m_slot]`), then the state's kind, which refreshActivityLabel
    keeps on the model just before the turn's start. The width detour runs where elapsedSuffix loaded
    the padding's width: width - len(time) - len("()" + state), never below 0. The format detour runs
    where it loaded the format. A thought past LONG_TURN seconds reads `thinking longer`. Both are
    leaves: no call, so no stack map is involved.
    """
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    cl, pv, rf = funcs["compactingLabel"], funcs["pendingLineView"], funcs["refreshActivityLabel"]
    frame = _go_frame(data, cl)
    m_slot = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (pv[0], pv[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    _, _, start = _turn_start(data, rf)
    kind = start - 0x10
    stores = [o for o, w in _words(data, (rf[0], rf[1] - 4))
              if w & 0xFFC0001F == 0x9140001B and word(o + 4) & 0xFFC003E0 == 0xF9000360
              and ((w >> 10) & 0xFFF) << 12 | ((word(o + 4) >> 10) & 0xFFF) * 8 == kind]
    if m_slot is None or not stores:
        raise RuntimeError("elapsedSuffix: pendingLineView's m spill or the model's state kind moved")
    if frame + m_slot > 0x7FF8 or (frame + m_slot) % 8 or kind >> 24 or (kind & 0xFFF) % 8:
        raise RuntimeError("elapsedSuffix: the caller's m or the state kind is out of reach of one load")
    formats = _elapsed_formats()
    base = _elapsed_base(data)
    va = VM_BASE + base
    at, pos = {}, va + ELAPSED_CODE
    for k, f in formats.items():
        at[k] = pos
        pos += len(f)
    label = _model_label_path(data, funcs)
    load_kind = lambda: pack(_ldr_sp(6, frame + m_slot),                                   # x6 = m (caller's spill)
                             0x91400000 | ((kind >> 12) << 10) | (6 << 5) | 27,             # add x27, x6, #hi, lsl #12
                             0xF9400366 | (((kind & 0xFFF) // 8) << 10))                    # ldr x6, [x27, #lo]
    movz = lambda rd, imm: 0xD2800000 | (imm << 5) | rd
    cmp = lambda rn, imm: 0xF100001F | (imm << 10) | (rn << 5)
    adr = lambda pc, target, rd: 0x10000000 | ((target - pc) & 3) << 29 | (((target - pc) >> 2) & 0x7FFFF) << 5 | rd
    # Columns the aside takes beyond the 2 the width already left out: its one leading space, `()`, the state.
    lead = len(ELAPSED_FORMAT) - len(ELAPSED_FORMAT.lstrip(b" "))
    cols = lambda state: lead + len(state)
    n_eff = 1 + len(EFFORT_WORDS)

    # The effort, from the model's label: x10 = m in, x12 = 0 (none) or 1 + its index in EFFORT_WORDS out,
    # back through x15. A leaf reached by a branch, not a call. The label's last 8 bytes are compared
    # with each suffix under a mask; a label shorter than 8 bytes names none.
    def effort(at_va: int, table_va: int) -> bytes:
        ldr = lambda rt, rn, off: 0xF9400000 | (off // 8) << 10 | rn << 5 | rt
        cbz = lambda rt, i, j: 0xB4000000 | ((j - i) & 0x7FFFF) << 5 | rt               # word i -> word j
        bcond = lambda i, j, c: 0x54000000 | ((j - i) & 0x7FFFF) << 5 | c
        LOOP, NONE, OUT = 15, 22, 23
        words = [
            0xAA1F03EC, ldr(10, 10, label["manager"]), cbz(10, 2, OUT),                 # x12 = 0; x10 = m.manager
            ldr(10, 10, label["store"]), cbz(10, 4, OUT),                                # .store
            ldr(10, 10, label["config"]), cbz(10, 6, OUT),                               # .config
            0xA9400000 | (label["label"] // 8) << 15 | 13 << 10 | 10 << 5 | 11,           # ldp x11, x13, [x10, #label]
            cmp(13, 8), bcond(9, OUT, 0xB),                                              # cmp x13, #8; b.lt out
            0x8B0D016B, 0xF85F816E,                                                      # add x11, x11, x13; ldur x14, [x11, #-8]
            None, None, movz(12, 1),                                                     # x13 = the suffix table; x12 = 1
            0xA8C125AA, cbz(9, 16, NONE), 0x8A0901C9, 0xEB0A013F, bcond(19, OUT, 0x0),   # loop: ldp x10, x9, [x13], #16; and; cmp
            0x9100058C, 0x14000000 | ((LOOP - 21) & 0x3FFFFFF),                         # x12 += 1; b loop
            0xAA1F03EC, 0xD61F01E0,                                                      # none: x12 = 0; out: br x15
        ]
        adrp_add = encode_adrp_add(at_va + 12 * 4, table_va, 13)
        words[12:14] = struct.unpack("<II", adrp_add)
        if len(words) != 24:
            raise RuntimeError("the effort matcher's layout drifted")
        return pack(*words)

    states = {k: v for k, v in formats.items() if isinstance(k, int)}
    width = load_kind() + pack(
        _ldr_sp(0, width_slot), _ldr_sp(7, dur_len_slot), 0xCB070000,                    # x0 = width - len(time)
        movz(7, cols("")))
    for k in states:
        width += pack(cmp(6, k), movz(8, cols(ELAPSED_STATES[k])), 0x9A870107)          # cmp x6, #k; x7 = k ? cols : x7
    width += pack(cmp(6, 3), movz(8, cols(ELAPSED_STATES[3])), 0x9A870107)
    here = va + len(width)                                                               # a long thought: wider
    width += pack(cmp(6, 3)) + encode_b_cond(here + 4, here + 24, 0x1)
    width += pack(_ldr_sp(9, secs_slot), cmp(9, LONG_TURN)) + encode_b_cond(here + 16, here + 24, 0xB)
    width += pack(movz(7, cols(ELAPSED_LONG_THOUGHT)))
    here = va + len(width)                                                               # a thought: its effort's words
    width_eff = here + 4 * 2
    width += pack(cmp(6, 3)) + encode_b_cond(here + 4, here + 4 * 9, 0x1)
    width += pack(_ldr_sp(10, frame + m_slot), adr(here + 12, here + 20, 15))
    width += b"EFFW"                                                                     # b effort (patched below)
    width += b"COLT" * 2 + pack(0x386C6928, 0x8B0800E7)                                   # x9 = cols table; ldrb w8, [x9, x12]; add x7, x7, x8
    width += pack(0xEB070000, 0x9A9FC000)                                                 # subs x0, x0, x7; csel x0, x0, xzr, gt
    width += encode_b(va + len(width), VM_BASE + conv)                                    # back to `bl convT64`
    fmt_va = va + len(width)
    fmt = load_kind() + encode_adrp_add(fmt_va + 12, VM_BASE + fmt_off, 0) + pack(movz(1, len(ELAPSED_FORMAT)))
    for k in states:
        if k == 3:
            continue
        here = fmt_va + len(fmt)
        fmt += pack(cmp(6, k)) + encode_b_cond(here + 4, here + 20, 0x1)                  # cmp; b.ne past
        fmt += encode_adrp_add(here + 8, at[k], 0) + pack(movz(1, len(formats[k])))
    here = fmt_va + len(fmt)                                                             # a thought: by length, then effort
    fmt += pack(cmp(6, 3)) + encode_b_cond(here + 4, here + 4 * 15, 0x1)               # not a thought: out
    fmt += pack(_ldr_sp(10, frame + m_slot), adr(here + 12, here + 20, 15)) + b"EFFF"
    fmt += pack(_ldr_sp(9, secs_slot), cmp(9, LONG_TURN), movz(14, n_eff),
                0x9A9FA1CE, 0x8B0E018C)                                                   # csel x14, x14, xzr, ge; add x12, x12, x14
    fmt += b"FMTT" * 2 + pack(0x8B0C0D49, 0x2940052B, 0x8B0B0140)                          # x10 = table; x9 = x10 + x12*8; ldp w11, w1; x0 = x10 + w11
    fmt += encode_b(fmt_va + len(fmt), VM_BASE + fmt_load + 12)                          # back to `add x2, sp, #args`
    eff_va = fmt_va + len(fmt)
    match_va = (eff_va + 4 * 24 + 15) & ~15
    cols_va = match_va + 16 * (len(EFFORT_WORDS) + 1)
    table_va = (cols_va + n_eff + 7) & ~7
    eff = effort(eff_va, match_va)
    if len(eff) != 4 * 24:
        raise RuntimeError(f"the effort matcher takes {len(eff)}B, not the 96B laid out")
    width = (width.replace(b"EFFW", encode_b(width_eff + 8, eff_va))
                  .replace(b"COLT" * 2, encode_adrp_add(width_eff + 12, cols_va, 9)))
    f_eff = fmt_va + fmt.index(b"EFFF")
    fmt = (fmt.replace(b"EFFF", encode_b(f_eff, eff_va))
              .replace(b"FMTT" * 2, encode_adrp_add(fmt_va + fmt.index(b"FMTT"), table_va, 10)))
    matches = b""
    for suffix, _ in EFFORT_WORDS:
        raw = suffix.encode()
        if len(raw) > 8:
            raise RuntimeError(f"effort suffix {suffix} is longer than the 8 bytes the matcher compares")
        mask = ((1 << 64) - 1) ^ ((1 << (8 * (8 - len(raw)))) - 1)
        matches += struct.pack("<QQ", int.from_bytes(raw.rjust(8, b"\0"), "little") & mask, mask)
    matches += bytes(16)
    effort_cols = bytes([0] + [len(EFFORT_PHRASE.format(shown)) for _, shown in EFFORT_WORDS])
    records = b"".join(struct.pack("<II", at[("thought", i)] - table_va, len(formats[("thought", i)]))
                       for i in range(2 * n_eff))
    code = (width + fmt + eff).ljust(match_va - va, b"\0") + matches + effort_cols.ljust(table_va - cols_va, b"\0") + records
    if len(code) > ELAPSED_CODE:
        raise RuntimeError(f"elapsedSuffix's detours and tables take {len(code)}B, more than the {ELAPSED_CODE}B laid out")
    code = code.ljust(ELAPSED_CODE, b"\0")
    blob = code + b"".join(formats.values())
    if bytes(data[base : base + len(blob)]) not in (bytes(len(blob)), blob):
        raise RuntimeError(f"__TEXT fill at {hex(va)} holds neither zeros nor elapsedSuffix's detours")
    return {"width": va, "format": fmt_va, "blob": blob, "blob_va": va}


def _resolve_elapsed_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #50a-#50i: no `...` after the pending line's text, and a faint elapsed time after it."""
    pv, rf, ac, cl = (funcs[k] for k in ("pendingLineView", "refreshActivityLabel", "activityCandidate", "compactingLabel"))
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    sites: list[PatchSite] = []

    def site(name: str, off: int, patched: bytes) -> None:
        sites.append(PatchSite("pending-line", name, VM_BASE + off, off, _recoverable(data, off, patched), patched))

    # 50a. pendingLineView: `concatstring2(nil, text, "...")` (`adrp x3; add x3; orr x4, xzr, #3`). The three
    # dots become one ellipsis, three bytes too, from a `…` already in the binary.
    ell = ELLIPSIS.encode()
    in_text = [o for o in _find_all(data, ell) if o < _text_tail_cave(data)[0]]
    if not in_text:
        raise RuntimeError("no `…` in __TEXT to point the pending line's ellipsis at")
    ell_va = VM_BASE + in_text[0]
    dots = [
        o for o, w in _words(data, (pv[0], pv[1] - 12))
        if w & 0x9F00001F == 0x90000003 and bytes(data[decode_adrp_add(data, o) - VM_BASE :][:3]) in (b"...", ell)
        and word(o + 8) == 0xB24007E4  # orr x4, xzr, #3
    ]
    if len(dots) != 1:
        raise RuntimeError(f"pendingLineView: expected one `text + \"...\"`, found {len(dots)}")
    site("model.(*ConversationModel).pendingLineView -> `…` after the text, not `...`", dots[0],
         encode_adrp_add(VM_BASE + dots[0], ell_va, 3))

    # 50b. refreshActivityLabel: `cmp x3, #7; b.eq stamp` -> `cmp x3, #0; b.ne stamp`. The stamp keeps a
    # start already set, so it now marks when the agent went busy; idle clears it.
    stamp, stamp_va, start_field = _turn_start(data, rf)
    site("model.(*ConversationModel).refreshActivityLabel -> stamp the start for every busy state", stamp,
         pack(0xF100007F) + encode_b_ne(VM_BASE + stamp + 4, stamp_va))

    # 50c. activityCandidate: `cmp x0, #7; b.ne label` -> `b label`; Compacting takes its plain label.
    seven = [o + 4 for o, w in _words(data, (ac[0], ac[1] - 4))
             if w == 0xF1001C1F and (word(o + 4) & 0xFF00001F == 0x54000001 or word(o + 4) >> 26 == 0x05)]
    if len(seven) != 1:
        raise RuntimeError(f"activityCandidate: expected one Compacting test, found {len(seven)}")
    br = seven[0]
    site("model.(*ConversationModel).activityCandidate -> Compacting shows its plain label", br,
         encode_b(VM_BASE + br, VM_BASE + branch_target(word(br), br)))

    # 50d. compactingLabel(start, now) -> elapsedSuffix(m, pad). Every call it keeps stays at its stock PC,
    # so the stack maps there still describe the frame; slots that hold pointers keep a pointer or nil.
    # Stock, around the one fmtDuration call F: F-0x6c `bl Time.Sub`; F-0x24 `str x6, [sp, #secs]`;
    # F-0x20 `orr x0, xzr, #7; mov x1, xzr; bl AgentState.Label; str x0, [sp, #P]; str x1, [sp, #L]`;
    # F+0x18 `ldr x0, [sp, #P]; ldr x1, [sp, #L]; bl convTstring; adrp x6, string; add x6`;
    # F+0x48 `adrp x0, format; add x0; mov x1, #len` for Sprintf.
    fmt_calls = _calls_to(data, cl, funcs["fmtDuration"][0])
    if len(fmt_calls) != 1:
        raise RuntimeError("compactingLabel no longer calls fmtDuration once")
    f = fmt_calls[0]
    entry, sub, secs, lab, conv, fmt_load = cl[0] + 0x1C, f - 0x6C, f - 0x24, f - 0x18, f + 0x20, f + 0x48
    head_len = 4 * 11
    fmt_off = entry + head_len
    patched_cl = bytes(data[fmt_off : fmt_off + len(ELAPSED_FORMAT)]) == ELAPSED_FORMAT
    slot = lambda off: _sp_slot(word(off), 0xF90003E0)
    if patched_cl:  # read the slots back from our own stores
        a_slot, b_slot, l_slot, p_slot = slot(entry + 0x14), slot(entry + 0x18), slot(entry), slot(lab + 4)
        shape_ok = b_slot is not None and b_slot[0] == 31 and p_slot is not None and p_slot[0] == 31
    else:
        a_slot, b_slot, p_slot, l_slot = slot(entry), slot(entry + 4), slot(lab + 4), slot(lab + 8)
        shape_ok = (
            a_slot is not None and a_slot[0] == 2 and b_slot is not None and b_slot[0] == 5
            and p_slot is not None and p_slot[0] == 0 and l_slot is not None and l_slot[0] == 1
            and word(lab - 8) == 0xB2400BE0 and word(lab - 4) == 0xAA1F03E1  # orr x0, xzr, #7; mov x1, xzr
            and branch_target(word(lab), lab) == funcs["agentStateLabel"][0]
            and branch_target(word(sub), sub) == funcs["timeSub"][0]
            and slot(secs) is not None and slot(secs)[0] == 6
            and word(conv - 8) == _ldr_sp(0, p_slot[1]) and word(conv - 4) == _ldr_sp(1, l_slot[1])
            and branch_target(word(conv), conv) == funcs["convTstring"][0]
            and word(fmt_load + 8) & 0xFFE0001F == 0xD2800001
        )
    if not shape_ok or a_slot is None or l_slot is None:
        raise RuntimeError("compactingLabel: unexpected shape around its fmtDuration call")
    dur_len = _sp_slot(word(f + 8), 0xF90003E0)  # `str x0, [sp, #ptr]; str x1, [sp, #len]` after fmtDuration
    if _sp_slot(word(f + 4), 0xF90003E0) is None or dur_len is None or dur_len[0] != 1:
        raise RuntimeError("compactingLabel: fmtDuration's result is no longer spilled right after the call")
    dur_len = dur_len[1]
    # The `int` type descriptor: fmtDuration boxes its integers with `bl convT64; adrp x1; add x1`.
    ints = {decode_adrp_add(data, o + 4) for o in _calls_to(data, funcs["fmtDuration"], funcs["convT64"][0])}
    if len(ints) != 1:
        raise RuntimeError("fmtDuration: expected one boxed integer type")
    if start_field >> 24 or (start_field & 0xFFF) + 0x10 > 0x7FF8:
        raise RuntimeError(f"start field {start_field:#x} is out of reach of one `add` and `ldr`")
    hi, lo = start_field >> 12, start_field & 0xFFF
    ld = lambda rt, off: 0xF9400360 | (((lo + off) // 8) << 10) | rt  # ldr xT, [x27, #lo + off]
    cbnz = lambda rt, at: 0xB5000000 | ((((sub - at) // 4) & 0x7FFFF) << 5) | rt
    head = pack(
        _str_sp(1, l_slot[1]),                    # pad, in a scalar slot across Since
        0x9140001B | (hi << 10),                  # add x27, x0, #hi, lsl #12   (x0 = m)
        ld(2, 0x10), ld(1, 0x8), ld(0, 0),        # x0..x2 = the start time
        _str_sp(2, a_slot[1]), _str_sp(31, b_slot[1]),  # the loc spills: a pointer, and nil
        cbnz(0, entry + 28), cbnz(1, entry + 32),  # a start: go time it
        MOV_X6_XZR,                               # none yet: 0s
    ) + encode_b(VM_BASE + entry + 40, VM_BASE + secs)
    if sub - fmt_off < len(ELAPSED_FORMAT):
        raise RuntimeError("compactingLabel: no room for the format before Time.Sub")
    body = bytearray(data[entry : fmt_load + 12])

    def put(off: int, blob: bytes) -> None:
        body[off - entry : off - entry + len(blob)] = blob

    put(entry, head + ELAPSED_FORMAT.ljust(sub - fmt_off, b"\x00"))
    put(sub, encode_bl(VM_BASE + sub, VM_BASE + funcs["timeSince"][0]))
    put(lab - 8, pack(_ldr_sp(0, l_slot[1]), 0xF1000800, 0x9A9FC000,  # width = max(pad - 2, 0)
                      _str_sp(31, p_slot[1]), _str_sp(0, l_slot[1])))  # the label's pointer slot: nil
    # 50i. The aside's width and format depend on the state, which elapsedSuffix(m, pad) reads itself:
    # two leaf detours in the __TEXT fill, one for the padding's width, one for the format.
    detours = _elapsed_detours(data, funcs, fmt_off, l_slot[1], dur_len, slot(secs)[1], conv, fmt_load)
    put(conv - 8, encode_b(VM_BASE + conv - 8, detours["width"]) + NOP
        + encode_bl(VM_BASE + conv, VM_BASE + funcs["convT64"][0])
        + encode_adrp_add(VM_BASE + conv + 4, next(iter(ints)), 6))
    put(fmt_load, encode_b(VM_BASE + fmt_load, detours["format"]) + NOP + NOP)
    if not patched_cl:
        assert_unreachable(data, cl, (entry + 8, sub), "compactingLabel's zero-start branch and moves")
    sites.append(PatchSite(
        "pending-line", "model.compactingLabel -> elapsedSuffix(m, pad): ` (8s ⋅ thinking)`, faint, of the time since the start",
        VM_BASE + entry, entry, None if patched_cl else bytes(data[entry : fmt_load + 12]), bytes(body)))
    fill_off = detours["blob_va"] - VM_BASE
    sites.append(PatchSite(
        "pending-line", "__TEXT fill -> elapsedSuffix's state formats and its two detours",
        detours["blob_va"], fill_off, bytes(len(detours["blob"])), detours["blob"]))

    # 50e-g. pendingLineView. The path that lays out `frame, text, padding, status` runs only when there
    # is a status; run it always, give the suffix room in the truncation, and call elapsedSuffix for the padding.
    m_slot = next((((w >> 15) & 0x7F) * 8 for o, w in _words(data, (pv[0], pv[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    if m_slot is None:
        raise RuntimeError("pendingLineView: the receiver spill is gone")
    reserve = [o for o, w in _words(data, pv) if w in (0xD1000C62, 0xD1000062 | (ELAPSED_RESERVE << 10))]
    if len(reserve) != 1:
        raise RuntimeError(f"pendingLineView: expected one `width - 3` truncation budget, found {len(reserve)}")
    gate = [o for o in range(reserve[0] - 0x40, reserve[0], 4)
            if word(o) & 0xFF00001F == 0xB4000001  # cbz x1, other_path (x1 = the status's length)
            or (bytes(data[o : o + 4]) == NOP and word(o - 4) & 0xFFC003FF == 0xF94003E1)]
    if len(gate) != 1:
        raise RuntimeError("pendingLineView: the right-hand status test is gone")
    repeats = [o for o in _calls_to(data, pv, funcs["stringsRepeat"][0]) if o > reserve[0]]
    repeats += [o for o in _calls_to(data, pv, cl[0]) if o > reserve[0]]
    if len(repeats) != 1 or word(repeats[0] - 20) != 0xF100007F:
        raise RuntimeError("pendingLineView: expected one padding `strings.Repeat` after the truncation")
    rp = repeats[0]
    site("model.(*ConversationModel).pendingLineView -> lay out text, suffix, status even with no status",
         gate[0], NOP)
    site(f"model.(*ConversationModel).pendingLineView -> the text gives {ELAPSED_RESERVE} columns to the suffix",
         reserve[0], pack(0xD1000062 | (ELAPSED_RESERVE << 10)))
    site("model.(*ConversationModel).pendingLineView -> padding comes from elapsedSuffix(m, pad)", rp - 16,
         pack(0x9A9FA061, _ldr_sp(0, m_slot), 0xAA1F03E2, 0xAA1F03E5)  # csel x1, x3, xzr, ge; m; x2 = x5 = nil
         + encode_bl(VM_BASE + rp, VM_BASE + cl[0]))

    # 50h. View passes a hide-status flag while a tip shows, and `tbnz w2, #0, short` then builds frame
    # and text alone: the status goes, and with it the padding that carries the elapsed time. The short
    # path instead empties the status (its length and its measured width, both scalar slots) and joins
    # the full one, so the time stays and the status stays hidden. x0 still holds the frame's width.
    hide, full = gate[0] + 8, gate[0] + 12
    len_slot, width_slot = _sp_slot(word(gate[0] - 4), 0xF94003E0), _sp_slot(word(full + 4), 0xF94003E0)
    if (word(hide) & 0xFFF8001F != 0x37000002 or len_slot is None or len_slot[0] != 1  # ldr x1, [sp, #len]; tbnz w2, #0
            or _sp_slot(word(full), 0xF90003E0) is None or width_slot is None or width_slot[0] != 3):  # str x0; ldr x3, [sp, #width]
        raise RuntimeError("pendingLineView: the hide-status test or the full path's first loads moved")
    short = hide + ((((word(hide) >> 5) & 0x3FFF) ^ 0x2000) - 0x2000) * 4
    site("model.(*ConversationModel).pendingLineView -> a tip hides the status, not the elapsed time", short,
         pack(_str_sp(31, len_slot[1]), _str_sp(31, width_slot[1])) + encode_b(VM_BASE + short + 8, VM_BASE + full))
    return tuple(sites)


# Sites #51a-#51f: a thought shows in the conversation while it runs, and the pending line says `Thinking`.
# store.(*textDrip).flush hands the conversation each planner step a little of its answer at a time
# (cutAtRuneBoundary, 12 bytes a tick). When the last step has nothing left to drip, it returns without
# handing that step over, so a step that has thought but no answer yet never reaches the conversation:
# stepContent's live one-liner for a running thought (latest paragraph under the running light) was
# never drawn, and the pending line was the only place the thought showed. #51a-#51c: when nothing follows
# and the answer is still empty, take the partial path, which hands over the step cut at its current
# point (an empty answer). An answer that has caught up keeps the stock exit, so finished text is not
# re-rendered every tick. The two instructions that decide this go where the drip's verbose-only
# `Drip stopped` log was, which #51c skips; no call moves. #51d-#51e: the live line drops its own
# `(8s)` (the pending line below already counts) and leads with a faint `∴ `, the mark the finished
# block keeps. #51f: the pending line shows the `Thinking` label instead of repeating the thought.
THOUGHT_MARK = "∴ ".encode()


def _resolve_thinking_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #51a-#51f: the running thought in the conversation, `∴ ` before it, and `Thinking` below."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    sites: list[PatchSite] = []

    def site(domain: str, name: str, off: int, patched: bytes, original: bytes | None = None) -> None:
        sites.append(PatchSite(domain, name, VM_BASE + off, off, _recoverable(data, off, patched, original), patched))

    def cond(at: int, target: int, base: int) -> int:  # b.cond / cbz / cbnz with a new 19-bit target
        return base | ((((target - at) // 4) & 0x7FFFF) << 5)

    # 51a-c. textDrip.flush, around its one cutAtRuneBoundary call C:
    #   C+0x0c `cmp x0, x5; b.gt partial`       (more to drip: hand over a cut step)
    #   C+0x20 `b.le exit` / C+0x2c `cbz x4, exit` (no step after this one: return, handing nothing over)
    #   C+0x50 `nop`, then the verbose `Drip stopped` log, ending in `bl log.ctxlogf` L.
    fl = funcs["dripFlush"]
    cuts = _calls_to(data, fl, funcs["cutAtRuneBoundary"][0])
    logs = _calls_to(data, fl, funcs["logCtxlogf"][0])
    if len(cuts) != 1 or len(logs) != 1:
        raise RuntimeError("textDrip.flush no longer cuts and logs once each")
    c, log_end = cuts[0], logs[0] + 4
    gt, le, cbz, gate = c + 0x10, c + 0x20, c + 0x2C, c + 0x50
    cave = gate + 4
    if word(gt) & 0xFF00001F != 0x5400000C or word(c + 0x0C) != 0xEB05001F:  # cmp x0, x5; b.gt
        raise RuntimeError("textDrip.flush: the drip-more test moved")
    partial = branch_target(word(gt), gt)
    if word(le) & 0xFF00001F != 0x5400000D or word(cbz) & 0xFF00001F != 0xB4000004:
        raise RuntimeError("textDrip.flush: the no-next-step tests moved")
    exit_, exit2 = branch_target(word(le), le), branch_target(word(cbz), cbz)
    patched_fl = exit_ == cave
    if patched_fl:
        exit_ = branch_target(word(cave + 4), cave + 4)
    elif exit2 != exit_ or bytes(data[gate : gate + 4]) != NOP:
        raise RuntimeError("textDrip.flush: unexpected shape after the cut")
    if not patched_fl:
        assert_unreachable(data, fl, (cave, log_end), "textDrip.flush's Drip-stopped log")
    site("pending-line", "store.(*textDrip).flush -> no next step: go ask whether the answer is still empty",
         le, pack(cond(le, cave, 0x5400000D)))
    site("pending-line", "store.(*textDrip).flush -> nil next step: the same question",
         cbz, pack(cond(cbz, cave, 0xB4000004)))
    site("pending-line", "store.(*textDrip).flush -> skip the verbose log; empty answer: hand over the thinking step",
         gate, encode_b(VM_BASE + gate, VM_BASE + log_end)
         + pack(cond(cave, partial, 0xB4000000))           # cbz x0, partial   (x0 = the cut, 0 for no answer)
         + encode_b(VM_BASE + cave + 4, VM_BASE + exit_)    # b exit
         + THOUGHT_MARK)                                     # #51d's mark, in the same dead span
    mark_va = VM_BASE + cave + 8

    # 51d-e. stepContent's live line, after RenderRunningLight R lights the snippet:
    #   R+0x14 `add x27, sp, #8, lsl #12; ldr x2, [x27, #ptr]; add x27, ...; ldr x3, [x27, #len]`  the `  (8s)`
    #   R+0x70 `bl Style.Render` (faint), then `ldr x2, lit_len; mov x3, x0; mov x4, x1; mov x0, xzr;
    #          add x27, ...; ldr x1, lit_ptr; bl concatstring2`  -> lit + suffix
    sc = funcs["stepContent"]
    lights = _calls_to(data, sc, funcs["RenderRunningLight"][0])
    if len(lights) != 1:
        raise RuntimeError("stepContent no longer lights one live line")
    r = lights[0]
    load, render, cat = r + 0x14, r + 0x70, r + 0x90
    if (branch_target(word(render), render) != funcs["styleRender"][0]
            or branch_target(word(cat), cat) != funcs["concatstring2"][0]):
        raise RuntimeError("stepContent: the live line's suffix is no longer rendered and appended")
    adrp_add = encode_adrp_add(VM_BASE + load, mark_va, 2)
    if bytes(data[load : load + 8]) != adrp_add:
        if word(load) & 0xFFFFFFE0 != 0x914023E0 or word(load + 4) & 0xFFC003FF != 0xF9400362 \
                or word(load + 12) & 0xFFC003FF != 0xF9400363:
            raise RuntimeError("stepContent: the live line no longer loads its `(8s)`")
    site("cot-rendering", "render.stepContent -> the running thought leads with `∴ `, without its own `(8s)`",
         load, adrp_add + pack(0xD2800003 | (len(THOUGHT_MARK) << 5), 0xD503201F))  # mov x3, #4; nop
    swap = (cat - 0x18, cat - 0x14, cat - 0x10, cat - 0x04)
    lit_len, lit_ptr = word(swap[0]), word(swap[3])
    if (word(swap[1]), word(swap[2])) == (0xAA0003E3, 0xAA0103E4):    # stock: mov x3, x0; mov x4, x1
        lit_len, lit_ptr = (lit_len & ~0x1F) | 4, (lit_ptr & ~0x1F) | 3
    elif (word(swap[1]), word(swap[2])) != (0xAA0103E2, 0xAA0003E1):
        raise RuntimeError("stepContent: unexpected concatenation of the live line")
    if lit_len & 0xFFC0001F != 0xF9400004 or lit_ptr & 0xFFC0001F != 0xF9400003:
        raise RuntimeError("stepContent: the lit snippet is no longer reloaded from the stack")
    site("cot-rendering", "render.stepContent -> the mark before the snippet, not the suffix after it",
         cat - 0x18, pack(lit_len, 0xAA0103E2, 0xAA0003E1, word(cat - 0x0C), word(cat - 0x08), lit_ptr))

    # 51f. activityCandidate: `cmp x0, #3; b.eq snippet` -> `cmp x0, #3; nop`; Thinking takes its label.
    ac = funcs["activityCandidate"]
    three = [o + 4 for o, w in _words(data, (ac[0], ac[1] - 4))
             if w == 0xF1000C1F and (word(o + 4) & 0xFF00001F == 0x54000000 or bytes(data[o + 4 : o + 8]) == NOP)]
    if len(three) != 1:
        raise RuntimeError(f"activityCandidate: expected one Thinking test, found {len(three)}")
    site("pending-line", "model.(*ConversationModel).activityCandidate -> Thinking shows its label, not the thought",
         three[0], NOP)
    return tuple(sites)



# Sites #56a-#56b: while the agent works, the pending line names the turn with a verb of the night sky,
# `✦ Stargazing…  4s`, as the star beside it suggests, instead of `Thinking` or `Running command`. The
# conversation above already says what is happening: the live thought, the tool row. One verb holds for
# the turn (the microseconds of the turn's start, Site #50b, pick it), so the time beside it never moves.
# States that tell the user something keep their words: a retry's countdown, compaction, loading,
# waiting. activityCandidate tests the state's kind; kinds 2-4 (generating, thinking, running a tool)
# take the verb. The code goes where Site #50c leaves the Compacting branch dead: a leaf, no call.
PENDING_VERBS = (
    "Stargazing", "Starhopping", "Constellating", "Twinkling", "Glimmering", "Scintillating",
    "Shimmering", "Gleaming", "Radiating", "Kindling", "Dawning", "Starweaving",
    "Eclipsing", "Transiting", "Culminating", "Precessing", "Gravitating", "Accreting",
    "Spiraling", "Drifting", "Wayfinding", "Charting", "Triangulating", "Luminescing",
)


def _resolve_verb_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #56a-#56b: a verb per turn on the pending line for generating, thinking and running a tool."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    ac = funcs["activityCandidate"]
    _, _, start_field = _turn_start(data, funcs["refreshActivityLabel"])
    _, _, at = _gemini_fill(data)

    # Stock, after executionStatusLabel: `ldr x0, [sp, #kind]; cmp x0, #3; b.eq snippet` (Site #51f: nop);
    # `cmp x0, #4; b.eq derive`; `cmp x0, #7; b.ne label` (Site #50c: `b label`); the Compacting branch up
    # to `derive`. The receiver is spilled at entry: `stp x0, x1, [sp, #m]`.
    four = [o for o, w in _words(data, (ac[0], ac[1] - 8))
            if (w == 0xF100101F or bytes(data[o : o + 4]) == encode_b(VM_BASE + o, VM_BASE + o + 16))
            and word(o + 8) == 0xF1001C1F]
    if len(four) != 1:
        raise RuntimeError(f"activityCandidate: expected one Running test before the Compacting one, found {len(four)}")
    o4 = four[0]
    cave = o4 + 16
    m_spill = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (ac[0], ac[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    label = branch_target(word(o4 + 12), o4 + 12)
    if m_spill is None or label is None:
        raise RuntimeError("activityCandidate: the receiver spill or the label branch moved")
    derive = branch_target(word(o4 + 4), o4 + 4)
    patched = bytes(data[o4 : o4 + 4]) == encode_b(VM_BASE + o4, VM_BASE + cave)
    if patched:
        derive = None
    elif derive is None or word(o4 + 4) & 0xFF00001F != 0x54000000:
        raise RuntimeError("activityCandidate: the Running test no longer branches on equal")
    # The epilogue the label path ends with: `bl AgentState.Label; ldur x29; ldr x30, [sp], #n; ret`.
    epilogue = [word(label + 0x10 + 4 * i) for i in range(3)]
    if epilogue[2] != 0xD65F03C0 or epilogue[0] != 0xF85F83FD:
        raise RuntimeError("activityCandidate: the label path no longer returns right after the call")
    if start_field >> 24 or (start_field & 0xFFF) > 0xFFF:
        raise RuntimeError(f"turn start {start_field:#x} is out of reach of two `add`s")
    n = len(PENDING_VERBS)
    body = (
        pack(0xD1000801, 0xF100083F)                                # sub x1, x0, #2; cmp x1, #2   (kinds 2-4)
        + encode_b_cond(VM_BASE + cave + 8, VM_BASE + label, 0x8)   # b.hi label
        + pack(_ldr_sp(2, m_spill),                                 # x2 = m
               0x91000000 | ((start_field & 0xFFF) << 10) | (2 << 5) | 27,       # add x27, x2, #lo
               0x91400000 | ((start_field >> 12) << 10) | (27 << 5) | 27,         # add x27, x27, #hi, lsl #12
               0xF9400363,                                          # ldr x3, [x27]          (the start's wall)
               0x92407463,                                          # and x3, x3, #0x3fffffff (its nanoseconds)
               0xD2800004 | (1000 << 5), 0x9AC40863,                # x3 /= 1000: macOS reads the wall clock in
                                                                    # microseconds, so nanoseconds mod 24 hit only 0, 8, 16
               0xD2800004 | (n << 5),                               # mov x4, #n
               0x9AC40865, 0x9B048CA3)                              # udiv x5, x3, x4; msub x3, x5, x4, x3
        + encode_adrp_add(VM_BASE + cave + 0x34, at["verbs"], 0)    # x0 = the records
        + pack(0x8B031000, 0x38401401, *epilogue)                   # add x0, x0, x3, lsl #4; ldrb w1, [x0], #1; return
    )
    end = cave + len(body)
    if not patched:
        if end > derive:
            raise RuntimeError(f"activityCandidate: the dead Compacting branch holds {derive - cave}B, the verb needs {len(body)}B")
        assert_unreachable(data, ac, (cave, derive), "activityCandidate's Compacting branch")
    return (
        PatchSite("pending-line", "model.(*ConversationModel).activityCandidate -> past Thinking, go pick the verb",
                  VM_BASE + o4, o4, bytes(data[o4 : o4 + 4]) if not patched else None, encode_b(VM_BASE + o4, VM_BASE + cave)),
        PatchSite("pending-line", f"model.(*ConversationModel).activityCandidate -> generating, thinking, running: one of {n} verbs per turn",
                  VM_BASE + cave, cave, bytes(data[cave:end]) if not patched else None, body),
    )


# Site #58: a code comment holds one gray while the answer streams. Code blocks go through chroma's
# 256-color formatter, whose findClosest walks a Go map of the palette and keeps the first color at
# the smallest distance. The `native` style's comments are `italic #999999`, equally far from 246
# (`#949494`) and 247 (`#9e9e9e`), and Go randomizes a map's order on every walk; each re-render of a
# streaming answer (every 16 ms) drew every comment above it in one of the two. `#979797` is nearest
# 246 alone, the gray it was already drawn in half the time.
CODE_COMMENT_GRAY = (b'<entry type="Comment" style="italic #999999"/>', b'<entry type="Comment" style="italic #979797"/>')


def _resolve_code_theme_sites(data: bytes | bytearray) -> tuple[PatchSite, ...]:
    """Site #58: the `native` code style's comment gray, off the 246/247 tie."""
    start = data.find(b'<style name="native">')
    end = data.find(b"</style>", start)
    if start < 0 or end < 0:
        raise RuntimeError("chroma's `native` style is no longer embedded")
    hits = [o for needle in CODE_COMMENT_GRAY for o in _find_all(data[start:end], needle)]
    if len(hits) != 1:
        raise RuntimeError(f"`native` style: expected one comment entry at #999999, found {len(hits)}")
    off = start + hits[0]
    stock, patched = CODE_COMMENT_GRAY
    return (PatchSite("code-theme", "chroma `native` style -> comments #979797, nearest 246 alone (no 246/247 coin flip)",
                      VM_BASE + off, off, _recoverable(data, off, patched, stock if bytes(data[off:off + len(stock)]) == stock else patched),
                      patched),)


# Sites #57a-#57z: the transcript's status marks take the star's family. A finished call was `●`, a
# running one pulsed `●`/`○`; now `⋆` (U+22C6, a small solid star, 434 units beside the spinner's
# `✦` at 572) and `⊹` (U+22B9, a thin four-point twinkle). Both are East Asian Width neutral, three
# UTF-8 bytes like the circles, so only the `adrp`/`add` pairs that load them change. Their colors are
# untouched: green done, red failed, yellow running. Only the transcript's renderers change (tool,
# command, subagent, task, background-command and workflow rows); lists and pickers elsewhere keep circles.
TOOL_MARKS = {"●": "⋆", "○": "⊹"}
TOOL_MARK_FUNCS = ("markTool", "markStatus", "markRunningDot", "markTask", "markSubagent", "markBackground",
                   "markMilestone", "markWorkflowAgent", "markWorkflowCall", "markWorkflow")


def _resolve_tool_mark_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #57: `⋆` for `●` and `⊹` for `○` in the transcript's status marks."""
    _, _, at = _gemini_fill(data)
    text_end = _text_tail_cave(data)[0]
    # The circles' addresses, from RunningDot, which loads each once (`○` lit, `●` not). A patched
    # binary loads the marks instead; then every site already reads as patched.
    star = {}
    for circle, mark in TOOL_MARKS.items():
        loads = set()
        lo, hi = funcs["markRunningDot"]
        for o in range(lo, hi - 8, 4):
            va = _adrp_add_at(data, o, struct.unpack_from("<I", data, o)[0] & 0x1F)
            if va is not None and (va == at[mark.encode()] or (0 <= va - VM_BASE < text_end
                                   and bytes(data[va - VM_BASE : va - VM_BASE + 3]) == circle.encode())):
                loads.add(va)
        if len(loads) != 1:
            raise RuntimeError(f"render.RunningDot no longer loads one `{circle}`")
        star[loads.pop()] = at[mark.encode()]
    star.update({v: v for v in list(star.values())})
    sites = []
    for name in TOOL_MARK_FUNCS:
        lo, hi = funcs[name]
        found = 0
        for o in range(lo, hi - 8, 4):
            rd = struct.unpack_from("<I", data, o)[0] & 0x1F
            va = _adrp_add_at(data, o, rd)
            if va is None:
                continue
            star_va = star.get(va)
            if star_va is None:
                continue
            patched = encode_adrp_add(VM_BASE + o, star_va, rd)
            glyph = next(m for m in TOOL_MARKS.values() if at[m.encode()] == star_va)
            sites.append(PatchSite("tool-marks", f"{TARGET_SYMBOLS[name].rsplit('/', 1)[1]} @+{o - lo:#x} -> `{glyph}`",
                                   VM_BASE + o, o, _recoverable(data, o, patched), patched))
            found += 1
        if not found:
            raise RuntimeError(f"{TARGET_SYMBOLS[name]} no longer loads a status circle")
    return tuple(sites)


# Sites #52a-#52b: under `verbosity: "medium"` (the default) a thought stays its own block, as under
# `high`, while tool calls still group (`● Explored 3 files`). The store groups steps into conversation
# items as they arrive (advanceDrip.func3) and again on rebuild (groupSteps), through the same two
# predicates. canUpgradeTrailingThoughtToToolGroup (medium only) let a tool call absorb the thought
# before it, which the tool group then drew as `○ Thought for 7.4s (<title>)`: it now answers no (#52a).
# findLastToolGroupAbsIdx scans back for the group a new tool call joins; under `high` a planner step
# with thought text stops the scan, under `medium` it was skipped, so the next call joined the group
# before the thought and swallowed it. The scan now stops there whatever the verbosity (#52b), which
# also keeps a thought that stands alone from being covered by the group around it.
# canMergeConsecutiveThoughts joins a thought to the item before it: another thought (kept), or, under
# `medium` only, a tool group. Rebuilding a conversation (`--continue`, a restart) takes that second path,
# so the thought between two tool calls became the group's `○ Thought` line and the calls around it one
# group. The `medium` test now answers no (#52c).
def _resolve_thought_grouping_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #52a-#52c: thoughts are never folded into tool groups."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    up = funcs["canUpgradeTrailingThought"][0]
    answer_no = bytes.fromhex("e0031faac0035fd6")  # mov x0, xzr; ret  (a leaf at entry: no frame yet)
    head = bytes(data[up : up + 8])
    if head != answer_no and head[:4] != bytes.fromhex("900b40f9"):  # ldr x16, [x28, #0x10]
        raise RuntimeError("canUpgradeTrailingThoughtToToolGroup no longer opens with its stack check")

    fl = funcs["findLastToolGroup"]
    # `cmp x7, #4; b.ne other; ldr w17, [x6]; "high"; b.ne other; ldr x12, [x12]`: the `high` test before
    # reading a planner step's thought field. Patched: `b` straight to that `ldr x12, [x12]`.
    high = [o for o, w in _words(data, (fl[0], fl[1] - 0x1C))
            if word(o + 0x1C) == 0xF940018C and (w == 0xF10010FF or branch_target(w, o) == o + 0x1C and w >> 26 == 0x05)]
    if len(high) != 1 or (word(high[0]) == 0xF10010FF and word(high[0] + 8) != 0xB94000D1):
        raise RuntimeError(f"findLastToolGroupAbsIdx: expected one `high` test before the thought check, found {len(high)}")
    # After `bl isThoughtOnlyGroup; tbnz w0, yes`: `ldr x1, [sp, #len]; cmp x1, #6; b.ne no` ("medium").
    # Patched: `b no`.
    cm = funcs["canMergeConsecutiveThoughts"]
    medium = [o for o in _calls_to(data, cm, funcs["isThoughtOnlyGroup"][0])
              if word(o + 4) >> 24 == 0x37 and (word(o + 0xC) == 0xF100183F and word(o + 0x10) & 0xFF00001F == 0x54000001
                                                 or word(o + 8) >> 26 == 0x05)]
    if len(medium) != 1:
        raise RuntimeError(f"canMergeConsecutiveThoughts: expected one `medium` test after the thought-group test, found {len(medium)}")
    m = medium[0] + 8
    no = branch_target(word(m + 8), m + 8) if word(m) >> 26 != 0x05 else branch_target(word(m), m)
    return (
        PatchSite("thought-grouping", "store.canUpgradeTrailingThoughtToToolGroup -> never (a tool call does not absorb the thought before it)",
                  VM_BASE + up, up, None if head == answer_no else head, answer_no),
        PatchSite("thought-grouping", "store.findLastToolGroupAbsIdx -> a step with thought stops the scan at every verbosity",
                  VM_BASE + high[0], high[0], bytes(data[high[0] : high[0] + 4]) if word(high[0]) == 0xF10010FF else None,
                  encode_b(VM_BASE + high[0], VM_BASE + high[0] + 0x1C)),
        PatchSite("thought-grouping", "store.canMergeConsecutiveThoughts -> a thought never joins the tool group before it",
                  VM_BASE + m, m, _recoverable(data, m, encode_b(VM_BASE + m, VM_BASE + no)),
                  encode_b(VM_BASE + m, VM_BASE + no)),
    )



# Sites #53a-#53d: under `verbosity: "high"` a thought streams into the conversation as its full block,
# and its `∴ Thought for 8s, 1.2k tokens` line closes the block instead of heading it. stepContent sent a
# running thought to the live one-liner (Sites #51d-#51e), and its full-block branch bailed out for a
# running step, so the block appeared all at once when the thought ended. #53a-#53b: a running thought
# takes the full branch when verbosity is `high` (`medium` keeps the one-liner). #53c: inside the full
# branch, a running thought skips the header (its slots hold an empty string) and goes straight to the
# body, so the paragraphs grow as they stream. #53d: the block is `body + "\n" + header` instead of
# `header + "\n" + body`; while the thought runs, the empty header leaves a blank last line, which the
# closing line fills in place.
#
# Sites #54a-#54i: under any other verbosity a finished thought is one line, `∴ Thought for 7s (<title>)`,
# and ctrl+o still expands it to the block. stepContent already had this collapsed form, reached when the
# item is not expanded (the retired Site #8 bypassed it): `▸ <header>`, then the thought's last paragraph
# on a second line, or the header alone when the step also holds an answer. #54a: the collapsed path
# first asks whether verbosity is `high` (the expanded block, as before), then builds its header as
# `"∴ " + header` with the `Sprintf` call site turned into `concatstring2` (#54b). #54c-#54d: outside
# `high` the header leaves out the token count, which only arrives when the request ends and would make
# the line jump. #54e-#54g: the snippet joins the header on the same line, without the two-space indent,
# also beside an answer. #54h-#54i: `collapsedThinkingSnippet` (only this path calls it) returns
# ` (<first line>)`, fitted to the width minus the header, instead of the last paragraph. "Is verbosity
# `high`" is a length test: the setting is one of `low`, `medium`, `high`.
def _resolve_thought_block_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #53a-#53d & #54a-#54i: the running thought grows under `high`; elsewhere a finished thought is one line."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    calls = lambda o, sym: word(o) >> 26 == 0x25 and branch_target(word(o), o) == funcs[sym][0]
    sc = funcs["stepContent"]
    sites: list[PatchSite] = []

    def site(name: str, off: int, patched: bytes) -> None:
        sites.append(PatchSite("cot-rendering", name, VM_BASE + off, off, _recoverable(data, off, patched), patched))

    def cond(at: int, target: int, base: int) -> int:
        return base | ((((target - at) // 4) & 0x7FFFF) << 5)

    def entered_from_outside(lo: int, hi: int, bounds: tuple[int, int]) -> bool:
        return any(not lo <= o < hi and (t := branch_target(word(o), o)) is not None and lo < t < hi
                   for o in range(bounds[0], bounds[1], 4))

    # The CoT gate: `cmp w11, #0xb; b.ne full; cbnz x8, full` then the live one-liner (stock), or
    # `cmp w11, #0xb; b.ne full; b cave` (patched).
    gates = [o + 8 for o, w in _words(data, (sc[0], sc[1] - 8))
             if w == 0x71002D7F and word(o + 4) & 0xFF00001F == 0x54000001
             and (word(o + 8) & 0xFF00001F == 0xB5000008 or word(o + 8) >> 26 == 0x05)]
    if len(gates) != 1:
        raise RuntimeError(f"stepContent: expected one live/full CoT gate, found {len(gates)}")
    gate = gates[0]
    full, live = branch_target(word(gate - 4), gate - 4), gate + 4

    # The full branch: `cbz x10; cbnz x8; ...; cmp w12, #1; b.ls bail; cmp w11, #8; b.eq bail;
    # cmp w11, #0xb; b.eq bail` (running steps bail out), then the `low` test, which loads the verbosity's
    # length: `add x27, sp, #0x18, lsl #12; ldr x11, [x27, #len]; cmp x11, #3`.
    bails = [full + 0x20, full + 0x28, full + 0x30]
    if word(full + 0x2C) != 0x71002D7F or len({branch_target(word(b), b) for b in bails}) != 1:
        raise RuntimeError("stepContent: the full CoT branch no longer bails out of running steps in one place")
    bail = branch_target(word(bails[0]), bails[0])
    if word(full + 0x3C) != 0xF1000D7F or word(full + 0x38) & 0xFFC003FF != 0xF940036B:
        raise RuntimeError("stepContent: the full CoT branch no longer loads the verbosity")
    verb_len = (word(full + 0x34), word(full + 0x38))  # x11 = len(verbosity)
    is_high = 0xF100117F  # cmp x11, #4
    if {s for o in range(sc[0], sc[1], 4) if (s := branch_target(word(o), o)) is not None and bail <= s < bail + 0x14} != {bail} \
            or [o for o in range(sc[0], sc[1], 4) if branch_target(word(o), o) == bail] != bails:
        raise RuntimeError("stepContent: the running-step bail-out is reached from elsewhere")

    # The block: `bl strings.Join` (the body, "\n"), then `add x27; ldr x2, [x27, #hlen]; adrp x3; add x3;
    # orr x4, xzr, #1; mov x5, x0; mov x6, x1; mov x0, xzr; add x27; ldr x1, [x27, #hptr]; bl concatstring3`.
    joins = [o for o in _calls_to(data, sc, funcs["stringsJoin"][0])
             if branch_target(word(o + 0x2C), o + 0x2C) == funcs["concatstring3"][0]]
    if len(joins) != 1:
        raise RuntimeError(f"stepContent: expected one `header + \"\\n\" + body`, found {len(joins)}")
    j = joins[0]
    hlen, hptr = word(j + 0x08), word(j + 0x28)
    stock_order = (word(j + 0x18), word(j + 0x1C)) == (0xAA0003E5, 0xAA0103E6)
    if stock_order:
        if hlen & 0xFFC0001F != 0xF9400002 or hptr & 0xFFC0001F != 0xF9400001:
            raise RuntimeError("stepContent: the CoT header is no longer reloaded for the block")
        hlen, hptr = (hlen & ~0x1F) | 6, (hptr & ~0x1F) | 5
    elif (word(j + 0x18), word(j + 0x1C)) != (0xAA0103E2, 0xAA0003E1):
        raise RuntimeError("stepContent: unexpected assembly of the CoT block")
    # The header is stored once: `add x27, ...; str x0, [x27, #hptr]; add x27, ...; str x1, [x27, #hlen]`;
    # the body code follows it.
    st_ptr, st_len = (hptr & ~0x1F & ~0x00400000) | 0, (hlen & ~0x1F & ~0x00400000) | 1
    stores = [o for o, w in _words(data, (sc[0], sc[1] - 12))
              if w == st_ptr and word(o - 4) == word(j + 0x24) and word(o + 8) == st_len and word(o + 4) == word(j + 0x04)]
    if len(stores) != 1:
        raise RuntimeError(f"stepContent: expected one store of the CoT header, found {len(stores)}")
    body = stores[0] + 12

    # The collapsed path, where Site #8's `tbz w3, #0` sends an item that is not expanded. Its first 0x64
    # bytes build the header's `Sprintf` arguments; they become the verbosity tests and the new header.
    s8 = find_unique_anchor(data, sc, bytes.fromhex("e20300aa04000014e10f40b2"), "Site 8 (stepContent expanded CoT check)") + 0x10
    if word(s8) & 0xFFF8001F != 0x36000003:
        raise RuntimeError("stepContent: the expanded test is no longer `tbz w3, #0` (an old patch with Site #8?)")
    span, expanded = branch_target(word(s8), s8), s8 + 4
    hdr_call = span + 0x64
    if not (calls(hdr_call, "fmtSprintf") or calls(hdr_call, "concatstring2")) or not calls(span + 0xB4, "styleRender"):
        raise RuntimeError("stepContent: the collapsed CoT header is no longer `Render(Sprintf(...))`")
    if calls(hdr_call, "fmtSprintf") and (not calls(span + 0x30, "convTstring") or entered_from_outside(span, hdr_call, sc)):
        raise RuntimeError("stepContent: the collapsed CoT header code changed")
    # The snippet: `bl collapsedThinkingSnippet`, `concatstring2("  ", snippet)` (+0x28, prefix length at
    # +0x10), rendered, then `concatstring3(header, "\n", snippet)` (+0xa4, separator length at +0x8c).
    snips = _calls_to(data, sc, funcs["collapsedThinkingSnippet"][0])
    if len(snips) != 1:
        raise RuntimeError(f"stepContent: expected one collapsed thinking snippet, found {len(snips)}")
    c = snips[0]
    if not calls(c + 0x28, "concatstring2") or not calls(c + 0xA4, "concatstring3") \
            or word(c + 0x10) not in (0xB27F03E2, 0xAA1F03E2) or word(c + 0x8C) not in (0xB24003E4, 0xAA1F03E4):
        raise RuntimeError("stepContent: the collapsed CoT snippet is no longer joined as `header\\n  snippet`")
    # Before it, `ldr x2, [x27, #answer]; cbz x2, snippet`: a step that also holds an answer kept the
    # header alone.
    has_answer = c - 0x78
    if branch_target(word(has_answer), has_answer) != c - 0x18 \
            or not (word(has_answer) & 0xFF00001F == 0xB4000002 or word(has_answer) >> 26 == 0x05):
        raise RuntimeError("stepContent: the collapsed CoT snippet is no longer skipped beside an answer")

    # The token count: `fmtDuration` twice in the header code, first for `Thought for %s, %s tokens` and
    # then for `Thought for %s`, each after `mov x0, x1`; before the first, `add x27, sp, #0x8, lsl #12;
    # ldr x2, [x27, #tokens]; cbz x2, plain` (stock) or `add x27; ldr x11, [x27, #len]; b cave` (patched).
    durs = _calls_to(data, (full, span), funcs["fmtDuration"][0])
    if len(durs) != 2 or word(durs[0] - 4) != 0xAA0103E0 or word(durs[1] - 4) != 0xAA0103E0:
        raise RuntimeError("stepContent: the CoT header no longer formats its duration in two places")
    tok, plain, tok_at = durs[0] - 4, durs[1] - 4, durs[0] - 0x10
    if word(tok_at + 8) & 0xFF00001F == 0xB4000002 and branch_target(word(tok_at + 8), tok_at + 8) == plain:
        tok_load = (word(tok_at), word(tok_at + 4))
    elif (word(tok_at), word(tok_at + 4)) == verb_len and branch_target(word(tok_at + 8), tok_at + 8) == span + 0x44:
        tok_load = (word(span + 0x4C), word(span + 0x50))
    else:
        raise RuntimeError("stepContent: the CoT header no longer tests its token count")

    # The span: [0x00] collapsed path (#54a), [0x2c] running thought (#53b), [0x44] token count (#54d).
    v = lambda o: VM_BASE + o
    collapsed = (pack(*verb_len, is_high, cond(span + 0x0C, expanded, 0x54000000),  # high: b.eq expanded
                      0xAA0203E3, 0xAA0103E4)                                       # mov x3, x2; mov x4, x1
                 + encode_adr(v(span + 0x18), v(span + 0x28), 1)                     # adr x1, "∴ "
                 + pack(0xD2800082, 0xAA1F03E0)                                     # mov x2, #4; mov x0, xzr
                 + encode_b(v(span + 0x24), v(hdr_call)) + THOUGHT_MARK)
    running = pack(cond(span + 0x2C, full, 0xB5000008), *verb_len, is_high,
                   cond(span + 0x3C, full, 0x54000000)) + encode_b(v(span + 0x40), v(live))
    tokens = pack(is_high, cond(span + 0x48, plain, 0x54000001), *tok_load,
                  cond(span + 0x54, plain, 0xB4000002)) + encode_b(v(span + 0x58), v(tok)) + NOP * 2
    assert (len(collapsed), len(running), len(tokens)) == (0x2C, 0x18, 0x20)

    site("render.stepContent -> a running thought asks whether verbosity is `high`", gate, encode_b(v(gate), v(span + 0x2C)))
    site("render.stepContent -> a running thought under `high`: the full block, else the live one-liner", span + 0x2C, running)
    site("render.stepContent -> a running thought in the full branch: empty header, straight to the body", bail,
         pack(word(j + 0x24), st_ptr | 31, word(j + 0x04), st_len | 31) + encode_b(v(bail + 16), v(body)))
    site("render.stepContent -> the CoT block is body, then its `∴ Thought for` line", j + 0x08,
         pack(hlen, word(j + 0x0C), word(j + 0x10), word(j + 0x14), 0xAA0103E2, 0xAA0003E1, word(j + 0x20), word(j + 0x24), hptr))
    site("render.stepContent -> a collapsed thought under `high` expands; else its header is `∴ <header>`", span, collapsed)
    site("render.stepContent -> the collapsed header's `Sprintf` becomes `concatstring2`", hdr_call,
         encode_bl(v(hdr_call), VM_BASE + funcs["concatstring2"][0]))
    site("render.stepContent -> the CoT header asks whether verbosity is `high` before its token count", tok_at,
         pack(*verb_len) + encode_b(v(tok_at + 8), v(span + 0x44)))
    site("render.stepContent -> outside `high`, the CoT header leaves out the token count", span + 0x44, tokens)
    site("render.stepContent -> the collapsed snippet loses its two-space indent", c + 0x10, pack(0xAA1F03E2))
    site("render.stepContent -> the collapsed snippet joins its header on one line", c + 0x8C, pack(0xAA1F03E4))
    site("render.stepContent -> a collapsed thought keeps its snippet beside an answer", has_answer,
         encode_b(v(has_answer), v(c - 0x18)))

    # collapsedThinkingSnippet(text, width): TrimSpace; the paragraph after `strings.LastIndex(s, "\n\n")`;
    # stripMarkdownFormatting; collapseWhitespace; fitDetailText(s, max(width-2, 15)). Rebuilt from +0x4c:
    # the line before `IndexByteString(s, '\n')`, then ` (` + line + `)`, or "" for an empty line.
    f = funcs["collapsedThinkingSnippet"][0]
    width_at = f + 0x24
    stock_snip = calls(f + 0x58, "stringsLastIndex")
    if word(width_at) not in (0xD1000842, 0xD1006042) or not calls(f + 0x40, "stringsTrimSpace") \
            or (word(f + 0x44), word(f + 0x48)) != (0xF90023E0, 0xF9001BE1) \
            or not (stock_snip or calls(f + 0x58, "indexByteString")) \
            or not calls(f + 0x98, "stripMarkdownFormatting") or word(f + 0xA0) != 0xF9401FE2 or not calls(f + 0xA4, "fitDetailText"):
        raise RuntimeError("collapsedThinkingSnippet: unexpected code")
    if stock_snip and (not calls(f + 0x88, "stringsTrimSpace") or entered_from_outside(f + 0x4C, f + 0xB8, funcs["collapsedThinkingSnippet"])):
        raise RuntimeError("collapsedThinkingSnippet: unexpected control flow")
    epilogue = [word(o) for o in ((f + 0xA8, f + 0xAC, f + 0xB0) if stock_snip else (f + 0x8C, f + 0x90, f + 0x94))]
    snippet = (pack(0xD2800142) + NOP * 2 + encode_bl(v(f + 0x58), VM_BASE + funcs["indexByteString"][0])  # mov x2, #'\n'
               + pack(0xF9401BE1, 0xF100001F, 0x9A81A001, 0xF94023E0)  # x1 = i < 0 ? len : i; x0 = ptr
               + encode_b(v(f + 0x6C), v(f + 0x98)) + b" ()\0"                                    # strip it
               + encode_adr(v(f + 0x74), v(f + 0x70), 1)                                          # x1 = " ("
               + pack(0xD2800042, 0x91000825, 0xD2800026, 0xAA1F03E0)                             # x5 = ")"
               + encode_bl(v(f + 0x88), VM_BASE + funcs["concatstring3"][0]) + pack(*epilogue)
               + bytes(data[f + 0x98 : f + 0xA8])                                                 # fitted
               + pack(cond(f + 0xA8, f + 0x8C, 0xB4000001), 0xAA0003E3, 0xAA0103E4)               # cbz x1, ret
               + encode_b(v(f + 0xB4), v(f + 0x74)))
    assert len(snippet) == 0x6C
    # The width it fits to leaves room for `∴ Thought for 12m 5s (` and `)`.
    site("render.collapsedThinkingSnippet -> fit to the width minus the collapsed CoT header", width_at, pack(0xD1006042))
    site("render.collapsedThinkingSnippet -> ` (<first line>)` instead of the last paragraph", f + 0x4C, snippet)
    return tuple(sites)



def _resolve_monitor_sites(data: bytes | bytearray) -> tuple[PatchSite, ...]:
    """Disable synchronous pre-tool LLM monitors (`agy_tool_safety`, `sir_flash_lite`, `severe_internal_risks_agy`)."""
    header = b"# proto-file: gdm/security/agi_control/agent_monitoring/monitors/monitor_config.proto"
    start = find_unique_anchor(data, (0, len(data)), header, "MonitorsConfig header")
    end = data.find(b"\x00", start)
    bounds = (start, end if end != -1 else len(data))
    return tuple(
        PatchSite(
            domain="tool-monitors",
            name=f"MonitorsConfig.{name} -> enabled:false",
            va=VM_BASE + off,
            offset=off,
            original=b"enabled: true",
            patched=b"enabled:false",
        )
        for name in ("agy_tool_safety", "sir_flash_lite", "severe_internal_risks_agy")
        for off in (find_unique_anchor(data, bounds, f'  name: "{name}"\n  '.encode(), f"Monitor {name}"),)
    )


def _gemini_wire_map(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[set[str], dict[str, dict]]:
    """Every key of the `geminimodels` wire map, and the entries whose value operands decode.

    Each entry starts with its key: `adrp x2; add x2, x2, #lo; mov x3, #len; bl mapassign_faststr`, then
    sets its value length (`mov|orr xR, #len; str xR, [x0, #8]`) and pointer (`adrp x4; add x4; str x4, [x0]`).
    Entries that encode their value length otherwise are keys only.
    """
    start, end = funcs["geminiWireMap"]

    def word(off: int) -> int:
        return struct.unpack_from("<I", data, off)[0]

    def read_str(va: int, n: int) -> str:
        return bytes(data[va - VM_BASE : va - VM_BASE + n]).decode("ascii", "replace")

    key_offs = [
        off
        for off in range(start, end - 8, 4)
        if (word(off) & 0x9F00001F) == 0x90000002
        and (word(off + 4) & 0xFFC003FF) == 0x91000042
        and (word(off + 8) & 0xFFE0001F) == 0xD2800003
    ]
    keys: set[str] = set()
    entries: dict[str, dict] = {}
    for i, k in enumerate(key_offs):
        stop = key_offs[i + 1] if i + 1 < len(key_offs) else end
        key_va, key_len = decode_adrp_add(data, k), (word(k + 8) >> 5) & 0xFFFF
        key = read_str(key_va, key_len)
        keys.add(key)
        len_str = next((o for o in range(k + 12, stop, 4) if (word(o) & 0xFFFFFFE0) == 0xF9000400), None)
        ptr = next(
            (
                o
                for o in range(k + 12, stop - 8, 4)
                if (word(o) & 0x9F00001F) == 0x90000004
                and (word(o + 4) & 0xFFC003FF) == 0x91000084
                and word(o + 8) == 0xF9000004
            ),
            None,
        )
        if len_str is None or ptr is None or ptr < len_str:
            continue
        len_insn = word(len_str - 4)
        reg = word(len_str) & 0x1F
        if (len_insn & 0xFFE0001F) == 0xD2800000 | reg:  # mov xR, #len
            val_len = (len_insn >> 5) & 0xFFFF
        elif len_insn == 0xB27C03E0 | reg:  # orr xR, xzr, #0x10
            val_len = 16
        else:
            continue
        val_va = decode_adrp_add(data, ptr)
        entries[key] = {
            "off": k, "key_va": key_va, "len_off": len_str - 4, "reg": reg,
            "ptr_off": ptr, "val_va": val_va, "val_len": val_len, "value": read_str(val_va, val_len),
        }
    return keys, entries


def _resolve_gemini_wire_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #38-#40: map `gemini-4-carbon-{high,medium,low}` to the wire model `gemini-4-carbon`.

    Under `modelProvider: "gemini"`, `geminimodels.MapModel` turns a picker ID into the model the
    Gemini API request names (`gemini-4-argon-medium` -> `gemini-4-argon` + `thinkingLevel`). v1.5.5
    added Carbon to `defaultmodels` only, so Carbon IDs reach CLIProxyAPI unmapped and fail with
    `unknown provider`. Each site retargets one `gemini-3.6-flash-*` entry of the map, a model
    CLIProxyAPI does not route, by rewriting operands only: key pointer and length, value pointer
    and length. The value is the 15-byte prefix of the Carbon key itself, which also marks an entry
    as ours. Once upstream maps Carbon itself (v1.5.7, with a value length these sites do not decode),
    they retire and the binary keeps upstream's map.
    """
    keys, entries = _gemini_wire_map(data, funcs)

    def read_str(va: int, n: int) -> str:
        return bytes(data[va - VM_BASE : va - VM_BASE + n]).decode("ascii", "replace")

    def ours(e: dict) -> bool:
        return e["val_va"] == e["key_va"] and e["val_len"] == len(GEMINI_WIRE_MODEL)

    carbon_keys = {lvl: f"{GEMINI_WIRE_MODEL}-{lvl}" for lvl in ("high", "medium", "low")}
    if any(key in keys and not (key in entries and ours(entries[key])) for key in carbon_keys.values()):
        return ()  # Upstream maps Carbon itself.

    sites = []
    for lvl, carbon_key in carbon_keys.items():
        donor_key = f"{GEMINI_WIRE_DONOR}-{lvl}"
        donor = entries.get(donor_key)
        if donor is not None and read_str(donor["val_va"], donor["val_len"]) == GEMINI_WIRE_DONOR:
            entry = donor
        elif carbon_key in entries and ours(entries[carbon_key]):
            entry = entries[carbon_key]
        else:
            raise RuntimeError(
                f"geminimodels map has neither {donor_key} nor a patched {carbon_key}; "
                "re-derive Sites #38-#40 for this version"
            )
        needle = carbon_key.encode()
        target = data.find(needle)
        if target == -1 or data.find(needle, target + 1) != -1:
            raise RuntimeError(f"Expected exactly one {carbon_key!r} string literal in the binary")
        target_va = VM_BASE + target

        k, span_end = entry["off"], entry["ptr_off"] + 8
        # A patched entry has no recoverable original; --revert restores from the clean backup.
        original = bytes(data[k:span_end]) if entry is donor else None
        patched = bytearray(data[k:span_end])
        patched[0:12] = encode_adrp_add(VM_BASE + k, target_va, 2) + struct.pack("<I", 0xD2800003 | (len(needle) << 5))
        rel = entry["len_off"] - k
        patched[rel : rel + 4] = struct.pack("<I", 0xD2800000 | (len(GEMINI_WIRE_MODEL) << 5) | entry["reg"])
        rel = entry["ptr_off"] - k
        patched[rel : rel + 8] = encode_adrp_add(VM_BASE + entry["ptr_off"], target_va, 4)
        sites.append(
            PatchSite(
                domain="gemini-wire",
                name=f"geminimodels map: {carbon_key} -> {GEMINI_WIRE_MODEL} (in place of {donor_key})",
                va=VM_BASE + k,
                offset=k,
                original=original,
                patched=bytes(patched),
            )
        )
    return tuple(sites)


def _text_tail_cave(data: bytes | bytearray) -> tuple[int, int]:
    """File offsets [start, end) of the fill between the __TEXT segment's last section and its end."""
    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_SEGMENT_64 and bytes(data[pos + 8 : pos + 24]).rstrip(b"\x00") == b"__TEXT":
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, pos + 24)
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            last = max(sum(struct.unpack_from("<QQ", data, pos + 72 + i * 80 + 32)) for i in range(nsects))
            if fileoff != 0 or vmaddr != VM_BASE:
                raise RuntimeError("__TEXT no longer maps the file from offset 0 at VM_BASE")
            return last - VM_BASE, min(vmsize, filesize)
        pos += cmdsize
    raise RuntimeError("Mach-O __TEXT segment not found")


def _resolve_hydrogen_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #55a-#55p: Gemini 4 Hydrogen as a built-in model, with four efforts, for gateway sessions.

    agy v1.5.7 knows Hydrogen only from Cloud Code (OAuth). Through an enterprise gateway it is a custom
    model: shown as its raw ID, without an effort gauge, and sent with `thinkingBudget: 4096`, which
    CLIProxyAPI honors, so even xhigh thinks like high. Built-in models send the base model plus a
    `thinkingLevel`. Hydrogen takes the slots of Gemini 3.6 Flash (low, medium, high) and 3.7 Flash low,
    which CLIProxyAPI does not route, everywhere a model is defined:

    - #55a  its IDs and labels, in the zero fill at the end of __TEXT;
    - #55b  `defaultmodels.Gemini36Flash` becomes Hydrogen's info builder: effort -> Model enum (as Cloud
            Code serves them), and the xhigh label whole, since `GeminiModelInfo` only names Low-High;
    - #55c-#55f  `defaultmodels.init` builds the four efforts in the donors' slots;
    - #55g-#55j  the `geminimodels` wire map sends each as `gemini-4-hydrogen`;
    - #55k-#55n  `geminimodels.Catalog` (the static GEMINI_API_KEY list) lists them, keyed and labeled;
    - #55o  and orders them where the donors stood;
    - #55p  `toGenaiThinkingLevel` names xhigh `XHIGH`, which CLIProxyAPI accepts, not `EXTRA_HIGH`.

    OAuth sessions are unaffected: Cloud Code requests name `gemini-4-hydrogen-<effort>` and a numeric
    level, and its catalog arrives from the server. Calls stay at their stock PCs (§5.5). Each site
    reads a stock or a patched binary; a patched one has no recoverable original, and --revert restores
    from the clean backup.

    v1.5.8 ships Hydrogen as a built-in with the same four IDs and labels, and sends the same request
    (`gemini-4-hydrogen`, `thinkingLevel` LOW through XHIGH), keeping 3.6 and 3.7 Flash. There the sites
    retire, as the Carbon wire-map sites did on v1.5.7.
    """

    def w(off: int) -> int:
        return struct.unpack_from("<I", data, off)[0]

    def read_str(va: int, n: int) -> str:
        return bytes(data[va - VM_BASE : va - VM_BASE + n]).decode("ascii", "replace")

    def pk(*words: int) -> bytes:
        return b"".join(struct.pack("<I", x) for x in words)

    def is_bl(off: int, target_off: int) -> bool:
        return w(off) == struct.unpack("<I", encode_bl(VM_BASE + off, VM_BASE + target_off))[0]

    efforts = list(HYDROGEN_EFFORTS)
    ids = {e: f"{HYDROGEN_WIRE_MODEL}-{e}" for e in efforts}
    donors = {HYDROGEN_EFFORTS[e][3]: e for e in efforts}
    top = HYDROGEN_EFFORTS["xhigh"][1]
    if HYDROGEN_EFFORTS["xhigh"][0] != 100 or any(
        HYDROGEN_EFFORTS[e][1] != top - HYDROGEN_EFFORTS[e][0] for e in ("low", "medium", "high")
    ):
        raise RuntimeError("Site #55b computes the enum as 1528 - level (xhigh: 1528); HYDROGEN_EFFORTS changed")
    if any(not HYDROGEN_EFFORTS[e][2].startswith(HYDROGEN_FAMILY) for e in efforts):
        raise RuntimeError("Hydrogen labels must start with HYDROGEN_FAMILY")
    # These sites turn each donor's wire-map entry into Hydrogen's. A map that holds Hydrogen beside
    # every donor is upstream's own (v1.5.8): the sites retire and the binary keeps its models.
    wire_keys, _ = _gemini_wire_map(data, funcs)
    if set(donors) <= wire_keys and wire_keys & set(ids.values()):
        return ()
    sites: list[PatchSite] = []

    # 55a. Strings: IDs, then labels, NUL-terminated, in one page (Site #55o addresses them from one adrp).
    strings = [ids[e].encode() for e in efforts] + [HYDROGEN_EFFORTS[e][2].encode() for e in efforts]
    blob = b"".join(s + b"\x00" for s in strings)
    fill, fill_end = _text_tail_cave(data)
    cave = (fill + 0x1F) & ~0xF
    if (cave & ~0xFFF) != ((cave + len(blob) - 1) & ~0xFFF):
        cave = (cave + 0xFFF) & ~0xFFF
    if cave + len(blob) > fill_end:
        raise RuntimeError(f"__TEXT has {fill_end - fill}B of fill; Hydrogen's strings need {len(blob)}B")
    current = bytes(data[cave : cave + len(blob)])
    if current not in (bytes(len(blob)), blob):
        raise RuntimeError(f"__TEXT fill at {hex(VM_BASE + cave)} holds neither zeros nor Hydrogen's strings")
    at, pos = {}, VM_BASE + cave
    for key, s in zip([("id", e) for e in efforts] + [("label", e) for e in efforts], strings):
        at[key] = pos
        pos += len(s) + 1
    sites.append(PatchSite("hydrogen", "__TEXT fill -> Gemini 4 Hydrogen IDs and labels", VM_BASE + cave, cave, bytes(len(blob)), blob))

    # 55b. Gemini36Flash(id, level) -> GeminiModelInfo(name, id, enum, level), for levels 1-3 and 100.
    g36 = funcs["gemini36Flash"][0]
    info, unsupported = funcs["geminiModelInfo"][0], funcs["unsupportedThinkingLevel"][0]
    if not (is_bl(g36 + 0x64, info) and is_bl(g36 + 0x88, unsupported)):
        raise RuntimeError("defaultmodels.Gemini36Flash no longer calls GeminiModelInfo at +0x64 and unsupportedThinkingLevel at +0x88")
    family_len, xhigh_label = len(HYDROGEN_FAMILY), at[("label", "xhigh")]
    cmp_w = lambda rn, imm: 0x7100001F | imm << 10 | rn << 5  # noqa: E731
    va = VM_BASE + g36
    body = (
        pk(w(g36 + 0x18), cmp_w(2, 100))                              # str x0, [sp, #0x48]; cmp w2, #100
        + encode_b_cond(va + 0x20, va + 0x30, COND_EQ)
        + pk(0x51000449, cmp_w(9, 2))                                 # sub w9, w2, #1; cmp w9, #2
        + encode_b_cond(va + 0x2C, va + 0x7C, COND_HI)                # levels other than 1-3 and 100: unsupported
        + encode_movz(9, top)
        + pk(cmp_w(2, 100), 0x9A8203EA, 0xCB0A0124)                   # csel x10, xzr, x2, eq; sub x4, x9, x10
        + encode_movz(6, family_len) + encode_movz(7, len(HYDROGEN_EFFORTS["xhigh"][2]))
        + pk(0xAA0203E5, 0xAA0003E2, 0xAA0103E3, 0x9A8600E1)          # x5 = level; x2, x3 = id; csel x1, x7, x6, eq
        + encode_adrp_add(va + 0x58, xhigh_label, 0)                  # name: the xhigh label, or its family prefix
        + NOP
        + bytes(data[g36 + 0x64 : g36 + 0x7C])                        # bl GeminiModelInfo; return
        + encode_adrp_add(va + 0x7C, xhigh_label, 0) + encode_movz(1, family_len)
    )
    stock = (
        w(g36 + 0x1C) == cmp_w(2, 1) and w(g36 + 0x2C) == cmp_w(2, 2) and w(g36 + 0x3C) == cmp_w(2, 3)
        and all(w(g36 + o) & 0xFFE0001F == 0xD2800003 for o in (0x24, 0x34, 0x44))
    )
    if not stock and bytes(data[g36 + 0x18 : g36 + 0x88]) != body:
        raise RuntimeError("defaultmodels.Gemini36Flash is neither stock nor Site #55b")
    sites.append(PatchSite("hydrogen", "defaultmodels.Gemini36Flash -> Gemini 4 Hydrogen info, efforts low-xhigh",
                           va + 0x18, g36 + 0x18, bytes(data[g36 + 0x18 : g36 + 0x88]) if stock else None, body))

    # 55c-55f. defaultmodels.init: `adrp x0, id; add; mov x1, #len; mov x2, #level; bl Gemini3xFlash`.
    ini_start, ini_end = funcs["defaultModelsInit"]
    callees = (g36, funcs["gemini37Flash"][0])
    calls: dict[str, int] = {}
    for off in range(ini_start + 16, ini_end, 4):
        if not any(is_bl(off, c) for c in callees):
            continue
        if (w(off - 16) & 0x9F00001F) != 0x90000000 or (w(off - 8) & 0xFFE0001F) != 0xD2800001:
            continue
        name = read_str(decode_adrp_add(data, off - 16), (w(off - 8) >> 5) & 0xFFFF)
        effort = donors.get(name) or next((e for e in efforts if ids[e] == name), None)
        if effort is not None:
            if effort in calls:
                raise RuntimeError(f"defaultmodels.init builds {name} twice")
            calls[effort] = off
    if set(calls) != set(efforts):
        raise RuntimeError(f"defaultmodels.init: found slots for {sorted(calls)}, expected {efforts}")
    for e in efforts:
        off = calls[e]
        id_va, level = at[("id", e)], HYDROGEN_EFFORTS[e][0]
        patched = (encode_adrp_add(VM_BASE + off - 16, id_va, 0) + encode_movz(1, len(ids[e]))
                   + encode_movz(2, level) + encode_bl(VM_BASE + off, VM_BASE + g36))
        donor = HYDROGEN_EFFORTS[e][3]
        is_stock = read_str(decode_adrp_add(data, off - 16), (w(off - 8) >> 5) & 0xFFFF) == donor
        sites.append(PatchSite("hydrogen", f"defaultmodels.init: {ids[e]} in place of {donor}", VM_BASE + off - 16,
                               off - 16, bytes(data[off - 16 : off + 4]) if is_stock else None, patched))

    # 55g-55j. geminimodels wire map: <id> -> gemini-4-hydrogen, the IDs' own prefix.
    _, entries = _gemini_wire_map(data, funcs)
    for e in efforts:
        donor = HYDROGEN_EFFORTS[e][3]
        entry, is_stock = entries.get(donor), True
        if entry is None or entry["value"] != donor.rsplit("-", 1)[0]:
            entry, is_stock = entries.get(ids[e]), False
            if entry is None or entry["value"] != HYDROGEN_WIRE_MODEL:
                raise RuntimeError(f"geminimodels map has neither {donor} nor a patched {ids[e]}")
        k, span_end, id_va = entry["off"], entry["ptr_off"] + 8, at[("id", e)]
        patched = bytearray(data[k:span_end])
        patched[0:12] = encode_adrp_add(VM_BASE + k, id_va, 2) + encode_movz(3, len(ids[e]))
        rel = entry["len_off"] - k
        patched[rel : rel + 4] = encode_movz(entry["reg"], len(HYDROGEN_WIRE_MODEL))
        rel = entry["ptr_off"] - k
        patched[rel : rel + 8] = encode_adrp_add(VM_BASE + entry["ptr_off"], id_va, 4)
        sites.append(PatchSite("hydrogen", f"geminimodels map: {ids[e]} -> {HYDROGEN_WIRE_MODEL} (in place of {donor})",
                               VM_BASE + k, k, bytes(data[k:span_end]) if is_stock else None, bytes(patched)))

    # 55k-55n. geminimodels.Catalog: `mov x0, #enum; bl details; mov x1, #label_len; str x1, [x0, #0x10]; ...
    # adrp x4, label; add; str x4, [x0, #8]; ... adrp x2, id; add; mov x3, #id_len; bl mapassign_faststr`.
    cat_start, cat_end = funcs["geminiCatalog"]
    details = funcs["geminiDetails"][0]
    key_lens: dict[int, int] = {}  # key VA -> length, for Site #55o
    slots: dict[str, int] = {}
    for off in range(cat_start, cat_end - 0x54, 4):
        if (w(off) & 0xFFE0001F) != 0xD2800000 or not is_bl(off + 4, details):
            continue
        if (w(off + 8) & 0xFFE0001F) != 0xD2800001 or w(off + 0xC) != 0xF9000801 or w(off + 0x34) != 0xF9000404:
            continue
        if (w(off + 0x44) & 0x9F00001F) != 0x90000002 or (w(off + 0x4C) & 0xFFE0001F) != 0xD2800003:
            continue
        key_va, key_len = decode_adrp_add(data, off + 0x44), (w(off + 0x4C) >> 5) & 0xFFFF
        key_lens[key_va] = key_len
        name = read_str(key_va, key_len)
        effort = donors.get(name) or next((e for e in efforts if ids[e] == name), None)
        if effort is not None:
            slots[effort] = off
    if set(slots) != set(efforts):
        raise RuntimeError(f"geminimodels.Catalog: found slots for {sorted(slots)}, expected {efforts}")
    for e in efforts:
        off, (_, enum, label, donor) = slots[e], HYDROGEN_EFFORTS[e]
        patched = bytearray(data[off : off + 0x50])
        patched[0:4] = encode_movz(0, enum)
        patched[8:12] = encode_movz(1, len(label))
        patched[0x2C:0x34] = encode_adrp_add(VM_BASE + off + 0x2C, at[("label", e)], 4)
        patched[0x44:0x50] = encode_adrp_add(VM_BASE + off + 0x44, at[("id", e)], 2) + encode_movz(3, len(ids[e]))
        is_stock = read_str(decode_adrp_add(data, off + 0x44), (w(off + 0x4C) >> 5) & 0xFFFF) == donor
        sites.append(PatchSite("hydrogen", f"geminimodels.Catalog: {ids[e]} ({label}) in place of {donor}",
                               VM_BASE + off, off, bytes(data[off : off + 0x50]) if is_stock else None, bytes(patched)))

    # 55o. Catalog's ordered IDs: `adrp x3, id; add x3; stp x3, x<len>, [x0, #slot]`, lengths in shared
    # registers. The donors' four entries follow 3.7 Flash medium's; they become one adrp and per-entry adds.
    def triplet(off: int) -> tuple[int, int, int] | None:
        a, b, c = w(off), w(off + 4), w(off + 8)
        if (a & 0x9F00001F) != 0x90000003 or (b & 0xFFC003FF) != 0x91000063 or (c & 0xFFC003FF) != 0xA9000003:
            return None
        return decode_adrp_add(data, off), (c >> 10) & 0x1F, ((c >> 15) & 0x7F) * 8  # key VA, length reg, slot
    found = {off: t for off in range(cat_start, cat_end - 12, 4) if (t := triplet(off))}
    len_reg = {key_lens[t[0]]: t[1] for t in found.values() if t[0] in key_lens}
    medium37 = next((va for va, n in key_lens.items() if read_str(va, n) == "gemini-3.7-flash-medium"), None)
    anchor = next((off for off, t in found.items() if t[0] == medium37), None)
    if anchor is None:
        raise RuntimeError("geminimodels.Catalog: no ordered entry for gemini-3.7-flash-medium")
    span, slot0 = anchor + 12, found[anchor][2] + 0x10
    order = ["xhigh", "high", "medium", "low"]  # where the 3.7 low and 3.6 high, medium, low IDs stood
    need = {len(ids[e]) for e in order} - {len(ids[e]) for e in ("high", "medium")}
    if not need <= set(len_reg):
        raise RuntimeError(f"geminimodels.Catalog: no shared length register for {sorted(need - set(len_reg))}")
    page = at[("id", "low")]
    if any((at[("id", e)] & ~0xFFF) != (page & ~0xFFF) for e in efforts):
        raise RuntimeError("Hydrogen's IDs must share one page")
    add_x = lambda rd, rn, imm: 0x91000000 | imm << 10 | rn << 5 | rd  # noqa: E731
    stp = lambda rt, rt2, slot: 0xA9000000 | (slot // 8) << 15 | rt2 << 10 | rt  # noqa: E731
    patched = encode_adrp(VM_BASE + span, page, 3)
    for i, e in enumerate(order):
        n, slot = len(ids[e]), slot0 + 0x10 * i
        patched += pk(add_x(9, 3, at[("id", e)] & 0xFFF))
        if e in ("high", "medium"):
            patched += encode_movz(10, n) + pk(stp(9, 10, slot))
        else:
            patched += pk(stp(9, len_reg[n], slot))
    patched += NOP
    stock_keys = [found.get(span + 12 * i) for i in range(4)]
    is_stock = all(t is not None and t[2] == slot0 + 0x10 * i and read_str(t[0], key_lens.get(t[0], 0)) == HYDROGEN_EFFORTS[e][3]
                   for i, (t, e) in enumerate(zip(stock_keys, order)))
    if len(patched) != 48 or (not is_stock and bytes(data[span : span + 48]) != patched):
        raise RuntimeError("geminimodels.Catalog's ordered IDs are neither stock nor Site #55o")
    sites.append(PatchSite("hydrogen", "geminimodels.Catalog: order Hydrogen xhigh-low where its donors stood",
                           VM_BASE + span, span, bytes(data[span : span + 48]) if is_stock else None, patched))

    # 55p. toGenaiThinkingLevel: `cmp w0, #100; b.ne; adrp x0, "EXTRA_HIGH"; add; mov x1, #10`.
    t_start, t_end = funcs["toGenaiThinkingLevel"]
    cmp100 = next((o for o in range(t_start, t_end, 4) if w(o) == 0x7101901F), None)
    if cmp100 is None or (w(cmp100 + 8) & 0x9F00001F) != 0x90000000 or (w(cmp100 + 16) & 0xFFE0001F) != 0xD2800001:
        raise RuntimeError("toGenaiThinkingLevel no longer names level 100 at `cmp w0, #100`")
    xhigh = data.find(b"THINKING_LEVEL_XHIGH")
    if xhigh < 0:
        raise RuntimeError("No THINKING_LEVEL_XHIGH literal to borrow XHIGH from")
    xhigh_va = VM_BASE + xhigh + len(b"THINKING_LEVEL_")
    name = read_str(decode_adrp_add(data, cmp100 + 8), (w(cmp100 + 16) >> 5) & 0xFFFF)
    if name not in ("EXTRA_HIGH", "XHIGH"):
        raise RuntimeError(f"toGenaiThinkingLevel names level 100 {name!r}")
    patched = encode_adrp_add(VM_BASE + cmp100 + 8, xhigh_va, 0) + encode_movz(1, 5)
    sites.append(PatchSite("hydrogen", "genairequest.toGenaiThinkingLevel -> name level 100 XHIGH, not EXTRA_HIGH",
                           VM_BASE + cmp100 + 8, cmp100 + 8,
                           bytes(data[cmp100 + 8 : cmp100 + 20]) if name == "EXTRA_HIGH" else None, patched))
    return tuple(sites)


# Sites #41-#47: follow the terminal's light/dark switch live. bubbletea already decodes DEC mode 2031
# notifications (`CSI ? 997 ; 1|2 n`) into uv.Dark/LightColorSchemeEvent and passes them through
# untranslated; agy never enables the mode and ignores the events. These sites lend the mode the
# focus-reporting lifecycle (agy never reports focus), so the renderer enables it on the first frame and
# on resume, and disables it on close and suspend, and turn each notification into the message behind tea.RequestBackgroundColor:
# the OSC 11 reply then reaches SetTerminalBackground, where Site #34 recolors the bar and rerenders.
FOCUS_MODE, COLOR_SCHEME_MODE = b"1004", b"2031"
NOP = bytes.fromhex("1f2003d5")


def go_type_descriptor(data: bytes | bytearray, name: str, types_base: int) -> int:
    """Return the file offset of the zero-size struct type whose abi.Type.Str names `name`."""
    raw = name.encode()
    records = [i - 2 for i in _find_all(data, raw) if data[i - 1] == len(raw)]
    found = []
    for rec in records:
        name_off = struct.pack("<i", rec - types_base)
        for i in _find_all(data, name_off):
            desc = i - 40
            if desc % 8 == 0 and struct.unpack_from("<Q", data, desc)[0] == 0 and data[desc + 23] & 0x1F == 25:
                found.append(desc)
    if len(found) != 1:
        raise RuntimeError(f"Expected one zero-size struct type named {name}, found {len(found)}")
    return found[0]


def _find_all(data: bytes | bytearray, needle: bytes) -> list[int]:
    hits, i = [], data.find(needle)
    while i != -1:
        hits.append(i)
        i = data.find(needle, i + 1)
    return hits


def _find_mode_string_load(
    data: bytes | bytearray, func_bounds: tuple[int, int], suffix: bytes, label: str
) -> tuple[int, int]:
    """Return (offset of the `adrp+add` loading `ESC[?1004<suffix>` or its 2031 form, offset of the string)."""
    start, end = func_bounds
    wanted = (b"\x1b[?" + FOCUS_MODE + suffix, b"\x1b[?" + COLOR_SCHEME_MODE + suffix)
    loads = []
    for off in range(start, end - 8, 4):
        w0, w1 = struct.unpack_from("<II", data, off)
        if w0 & 0x9F000000 == 0x90000000 and w1 & 0xFF800000 == 0x91000000:
            target = decode_adrp_add(data, off) - VM_BASE
            if 0 <= target < len(data) and bytes(data[target : target + 8]) in wanted:
                loads.append((off, target))
    if len(loads) != 1:
        raise RuntimeError(f"{label}: expected one load of the focus mode string, found {len(loads)}")
    return loads[0]


def _resolve_mode_guard(
    data: bytes | bytearray, func_bounds: tuple[int, int], suffix: bytes, label: str
) -> tuple[PatchSite, int]:
    """In the renderer's start or close, the `tbz wN, #0` (ReportFocus) that skips the mode write; returns the string."""
    load_off, str_off = _find_mode_string_load(data, func_bounds, suffix, label)
    # `ldrb wN, [x, #ReportFocus]; tbz wN, #0, <skip>` precedes the write by a few loads.
    guard = next(
        (
            o
            for o in range(load_off - 4, load_off - 28, -4)
            if struct.unpack_from("<I", data, o)[0] & 0xFFF80000 == 0x36000000 or bytes(data[o : o + 4]) == NOP
        ),
        None,
    )
    if guard is None:
        raise RuntimeError(f"{label}: no `tbz wN, #0` guarding the focus mode write")
    guard_orig = bytes(data[guard : guard + 4]) if bytes(data[guard : guard + 4]) != NOP else None
    mode = "enable" if suffix == b"h" else "disable"
    return PatchSite("color-scheme", f"{label} -> always {mode} the reporting mode", VM_BASE + guard, guard, guard_orig, NOP), str_off


def _resolve_first_frame_guard(data: bytes | bytearray, func_bounds: tuple[int, int]) -> PatchSite:
    """In flush, `tbnz wN, #0, <enable>` (view.ReportFocus) on the first frame: always take it.

    The block runs when `lastView == nil || lastView.ReportFocus != view.ReportFocus`. ReportFocus stays
    false, so only the first frame gets here, and it now enables the mode instead of skipping it.
    """
    label = "tea.(*cursedRenderer).flush"
    load_off, _ = _find_mode_string_load(data, func_bounds, b"h", label)
    enable_block = load_off - 8  # ldr x3, [x0, #scr]; ldr x0, [x3, #w]; adrp; add
    start, end = func_bounds

    def is_guard(off: int) -> bool:  # `tbnz wN, #0` when clean, `b` once patched
        word = struct.unpack_from("<I", data, off)[0]
        return (word & 0xFFF80000 == 0x37000000 or word >> 26 == 0x05) and branch_target(word, off) == enable_block

    guards = [o for o in range(start, end, 4) if is_guard(o)]
    if len(guards) != 1:
        raise RuntimeError(f"{label}: expected one `tbnz wN, #0` into the focus enable block, found {len(guards)}")
    guard = guards[0]
    orig = bytes(data[guard : guard + 4])
    return PatchSite(
        "color-scheme",
        f"{label} -> enable the reporting mode on the first frame",
        VM_BASE + guard,
        guard,
        orig if struct.unpack_from("<I", orig)[0] >> 26 != 0x05 else None,
        encode_b(VM_BASE + guard, VM_BASE + enable_block),
    )


def _resolve_color_scheme_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]], cave: tuple[int, int]
) -> tuple[PatchSite, ...]:
    """Sites #41-#47: enable DEC mode 2031 and answer each light/dark notification with an OSC 11 query."""
    # 41-43. The renderer writes the mode string on resume (start), on close and suspend, and on the first frame.
    s41, set_off = _resolve_mode_guard(data, funcs["rendererStart"], b"h", "tea.(*cursedRenderer).start")
    s42, reset_off = _resolve_mode_guard(data, funcs["rendererClose"], b"l", "tea.(*cursedRenderer).close")
    s43 = _resolve_first_frame_guard(data, funcs["rendererFlush"])
    # 44-45. The focus-reporting strings become DEC 2031 (`ESC[?2031h` / `ESC[?2031l`, same length).
    s44, s45 = (
        PatchSite("color-scheme", f"ansi focus mode string -> DEC 2031 ({name})", VM_BASE + off, off,
                  b"\x1b[?" + FOCUS_MODE + suffix, b"\x1b[?" + COLOR_SCHEME_MODE + suffix)
        for name, off, suffix in (("enable", set_off, b"h"), ("disable", reset_off, b"l"))
    )

    # tea.RequestBackgroundColor: `return backgroundColorMsg{}`, i.e. (type, &runtime.zerobase).
    rbc = funcs["RequestBackgroundColor"][0]
    add_x0, add_x1 = struct.unpack_from("<I", data, rbc + 4)[0], struct.unpack_from("<I", data, rbc + 12)[0]
    if add_x0 & 0x1F != 0 or add_x1 & 0x1F != 1:
        raise RuntimeError("tea.RequestBackgroundColor no longer returns (x0 = type, x1 = &zerobase)")
    bg_msg_va, zerobase_va = decode_adrp_add(data, rbc), decode_adrp_add(data, rbc + 8)
    # Go names types relative to moduledata.types; recover that base from the known descriptor.
    bg_name = b"*tea.backgroundColorMsg"
    bg_rec = [i - 2 for i in _find_all(data, bg_name) if data[i - 1] == len(bg_name)]
    if len(bg_rec) != 1:
        raise RuntimeError("tea.backgroundColorMsg type name not found")
    types_base = bg_rec[0] - struct.unpack_from("<i", data, bg_msg_va - VM_BASE + 40)[0]
    dark_va = VM_BASE + go_type_descriptor(data, "*uv.DarkColorSchemeEvent", types_base)
    light_va = VM_BASE + go_type_descriptor(data, "*uv.LightColorSchemeEvent", types_base)

    # 46. translateInputEvent's default (`return e`), the target of its leading `cbz x1` (nil event),
    # branches to the matcher instead.
    t_start, t_end = funcs["translateInputEvent"]
    cbz = next(
        (o for o in range(t_start, t_start + 64, 4) if struct.unpack_from("<I", data, o)[0] & 0xFF00001F == 0xB4000001),
        None,
    )
    if cbz is None:
        raise RuntimeError("translateInputEvent: leading `cbz x1, <default>` not found")
    default = branch_target(struct.unpack_from("<I", data, cbz)[0], cbz)
    epilogue = default + 8
    if bytes(data[default + 4 : default + 8]) != bytes.fromhex("e10302aa"):  # mov x1, x2
        raise RuntimeError("translateInputEvent: default no longer returns the event unchanged")

    # 47. The matcher, in Site #29's dead span: a light/dark event returns backgroundColorMsg{}, whose
    # handler in the event loop sends OSC 11; anything else returns unchanged.
    cave_off = cave[0]
    cave_va, default_va, epi_va = VM_BASE + cave_off, VM_BASE + default, VM_BASE + epilogue
    hit = cave_va + 0x2C
    cave_code = (
        encode_adrp_add(cave_va, dark_va, 3)
        + bytes.fromhex("3f0003eb")  # cmp x1, x3
        + encode_b_eq(cave_va + 0x0C, hit)
        + encode_adrp_add(cave_va + 0x10, light_va, 3)
        + bytes.fromhex("3f0003eb")
        + encode_b_eq(cave_va + 0x1C, hit)
        + bytes.fromhex("e00301aae10302aa")  # mov x0, x1; mov x1, x2: return e
        + encode_b(cave_va + 0x28, epi_va)
        + encode_adrp_add(hit, bg_msg_va, 0)  # return backgroundColorMsg{}
        + encode_adrp_add(hit + 8, zerobase_va, 1)
        + encode_b(hit + 0x10, epi_va)
    )
    if len(cave_code) > cave[1] - cave[0]:
        raise RuntimeError(f"Color-scheme cave needs {len(cave_code)}B, the dead span holds {cave[1] - cave[0]}B")

    return (
        s41,
        s42,
        s43,
        s44,
        s45,
        PatchSite(
            "color-scheme",
            "tea.(*Program).translateInputEvent -> light/dark notification becomes an OSC 11 background query",
            default_va,
            default,
            bytes.fromhex("e00301aa"),
            encode_b(default_va, cave_va),
        ),
        PatchSite(
            "color-scheme",
            "render.StickyPrompt dead span (Site #29) -> color-scheme event matcher",
            cave_va,
            cave_off,
            bytes(data[cave_off : cave_off + len(cave_code)]),
            cave_code,
        ),
    )


def _resolve_prompt_template_sites(data: bytes | bytearray, version: str, strict: bool) -> tuple[PatchSite, ...]:
    """Templates that templates/v<version>/system_prompts/ changes from stock (see prompt_templates.py)."""
    return tuple(
        PatchSite("prompt", f"{o.action} system_prompts/{o.name}", VM_BASE + o.slot.offset, o.slot.offset, o.original, o.patched)
        for o in prompt_templates.resolve_overrides(data, version, strict)
    )


def _resolve_groups(data: bytes | bytearray, version: str, strict: bool) -> dict[str, object]:
    """Run every resolver, keeping each one's result or the exception that stopped it."""
    funcs = locate_target_functions(data)
    out: dict[str, object] = {}

    def run(name: str, resolve, needs: str | None = None) -> None:
        if needs is not None and isinstance(out[needs], Exception):
            out[name] = RuntimeError(f"not resolved: it builds on {needs}, which failed")
            return
        try:
            out[name] = resolve()
        except Exception as exc:  # reported per group; resolve_patch_sites re-raises the first
            out[name] = exc

    run("context-window", lambda: _resolve_context_window_sites(data, funcs))
    # -> (pre, post, nl3_va, sticky_cave). Site #29's dead span holds the color-scheme matcher (Site #47).
    run("palette-typography", lambda: _resolve_palette_and_typography_sites(data, funcs))
    cave = lambda: out["palette-typography"][3]
    run("cot-rendering", lambda: _resolve_cot_sites(data, funcs, out["palette-typography"][2]), "palette-typography")
    run("statusline-refresh", lambda: _resolve_statusline_refresh_sites(data, funcs))
    run("tool-monitors", lambda: _resolve_monitor_sites(data))
    run("gemini-wire", lambda: _resolve_gemini_wire_sites(data, funcs))
    run("color-scheme", lambda: _resolve_color_scheme_sites(data, funcs, (cave()[0], cave()[0] + 0x40)), "palette-typography")
    run("command-elbow", lambda: _resolve_command_elbow_sites(data, funcs))
    run("spinner", lambda: _resolve_spinner_sites(data, funcs))
    run("pending-line", lambda: _resolve_elapsed_sites(data, funcs))
    run("live-thinking", lambda: _resolve_thinking_sites(data, funcs))
    run("pending-verbs", lambda: _resolve_verb_sites(data, funcs))
    run("tool-marks", lambda: _resolve_tool_mark_sites(data, funcs))
    run("code-theme", lambda: _resolve_code_theme_sites(data))
    run("thought-grouping", lambda: _resolve_thought_grouping_sites(data, funcs))
    run("thought-block", lambda: _resolve_thought_block_sites(data, funcs))
    run("hydrogen", lambda: _resolve_hydrogen_sites(data, funcs))
    run("prompt", lambda: _resolve_prompt_template_sites(data, version, strict))
    return out


def resolve_site_groups(data: bytes | bytearray, version: str, strict: bool = False) -> dict[str, tuple[PatchSite, ...] | Exception]:
    """Each resolver's sites, or the exception that stopped it: a new release can move several anchors at once."""
    out = _resolve_groups(data, version, strict)
    flat = {
        "palette-typography": lambda r: (*r[0], *r[1]),
        "cot-rendering": lambda r: (*r[0], r[1]),
        "statusline-refresh": lambda r: (r,),
    }
    return {name: r if isinstance(r, Exception) else tuple(flat.get(name, tuple)(r)) for name, r in out.items()}


def resolve_patch_sites(data: bytes | bytearray, version: str, strict: bool = False) -> tuple[PatchSite, ...]:
    """Resolve every site, in apply order: the TUI/Cortex code sites, tool monitors, Gemini wire map, color scheme, command elbow, spinner, pending line, its verbs, tool marks, live thinking, thought grouping, thought block, Hydrogen, and changed prompt templates.

    `strict` is for clean backups: every prompt template must match its pinned stock version.
    """
    out = _resolve_groups(data, version, strict)
    for result in out.values():
        if isinstance(result, Exception):
            raise result
    pal_pre, pal_post, _, _ = out["palette-typography"]
    cot_step_sites, cot_strip_site = out["cot-rendering"]
    return (
        *out["context-window"], *cot_step_sites, *pal_pre, out["statusline-refresh"], *pal_post, cot_strip_site,
        *out["tool-monitors"], *out["gemini-wire"], *out["color-scheme"], *out["command-elbow"], *out["spinner"],
        *out["pending-line"], *out["pending-verbs"], *out["tool-marks"], *out["code-theme"], *out["live-thinking"], *out["thought-grouping"], *out["thought-block"],
        *out["hydrogen"], *out["prompt"],
    )


# Stock shapes. A site whose original bytes are read from the binary reads as `unpatched` wherever its
# resolver lands (references/context-window-patch.md §5.6). So every code site's stock bytes are also
# pinned by shape: the instructions with each operand that moves between releases masked out (branch
# and page targets, frame slots, struct fields). site_shapes.json holds the shapes a person has reviewed;
# --apply refuses a clean binary that shows any other, and --accept-shapes records them after review.
SHAPES_PATH = REPO / "site_shapes.json"


def _text_section(data: bytes | bytearray) -> tuple[int, int]:
    """File offsets [start, end) of the Mach-O `__text` section."""
    pos = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_SEGMENT_64:
            for i in range(struct.unpack_from("<I", data, pos + 64)[0]):
                sect = pos + 72 + i * 80
                if bytes(data[sect : sect + 16]).rstrip(b"\x00") == b"__text":
                    _, size, offset = struct.unpack_from("<QQI", data, sect + 32)
                    return offset, offset + size
        pos += cmdsize
    raise RuntimeError("Mach-O __text section not found")


def stock_shape(code: bytes) -> str:
    """Digest of ARM64 code with the operands that move between releases masked out."""
    words = []
    for (w,) in struct.iter_unpack("<I", code):
        if w & 0x7C000000 == 0x14000000:                    # b, bl
            w &= 0xFC000000
        elif w & 0x1F000000 == 0x10000000:                  # adr, adrp
            w &= 0x9F00001F
        elif w & 0xFF000010 == 0x54000000:                  # b.cond
            w &= 0xFF00001F
        elif w & 0x7E000000 == 0x34000000:                  # cbz, cbnz
            w &= 0xFF00001F
        elif w & 0x7E000000 == 0x36000000:                  # tbz, tbnz
            w &= 0xFFF8001F
        elif w & 0x3F800000 == 0x11000000:                  # add, sub #imm (cmp and cmn keep theirs)
            w &= 0xFF8003FF
        elif w & 0x3B000000 == 0x39000000:                  # ldr, str [xN, #imm]
            w &= 0xFFC003FF
        elif w & 0x3A000000 == 0x28000000:                  # ldp, stp
            w &= 0xFFC07FFF
        elif w & 0x3B200000 == 0x38000000:                  # ldur, stur, pre- and post-indexed
            w &= 0xFFE00FFF
        words.append(w)
    return hashlib.blake2b(struct.pack(f"<{len(words)}I", *words), digest_size=8).hexdigest()


def stock_shapes(data: bytes | bytearray, sites: tuple[PatchSite, ...]) -> dict[str, str]:
    """The shape of every unpatched code site in a clean binary, by site name."""
    text_start, text_end = _text_section(data)
    return {
        s.name: stock_shape(bytes(data[s.offset : s.offset + len(s.patched)]))
        for s in sites
        if text_start <= s.offset < text_end and len(s.patched) % 4 == 0 and site_state(data, s) == "unpatched"
    }


def unreviewed_shapes(data: bytes | bytearray, sites: tuple[PatchSite, ...]) -> list[str]:
    """Names of the sites whose stock code has a shape that site_shapes.json does not hold."""
    known = json.loads(SHAPES_PATH.read_text()) if SHAPES_PATH.exists() else {}
    return [name for name, shape in stock_shapes(data, sites).items() if shape not in known.get(name, ())]


def accept_shapes(path: pathlib.Path) -> None:
    """Record the stock shapes of a clean binary (or of its clean backup) as reviewed."""
    backup = backup_path_for(path)
    source = backup if backup.exists() else path
    data = source.read_bytes()
    sites = resolve_patch_sites(data, detect_binary_version(path), strict=True)
    dirty = [s.name for s in sites if site_state(data, s) != "unpatched"]
    if dirty:
        raise RuntimeError(f"{source} is not clean ({len(dirty)} sites, first: {dirty[0]}); shapes come from a stock binary")
    known = json.loads(SHAPES_PATH.read_text()) if SHAPES_PATH.exists() else {}
    added = 0
    for name, shape in stock_shapes(data, sites).items():
        if shape not in known.setdefault(name, []):
            known[name].append(shape)
            added += 1
    SHAPES_PATH.write_text(json.dumps(dict(sorted(known.items())), indent=1, ensure_ascii=False) + "\n")
    print(f"[shape] {source}: {added} new shape(s) recorded in {SHAPES_PATH}")


def site_state(data: bytes | bytearray, site: PatchSite) -> str:
    actual = bytes(data[site.offset : site.offset + len(site.patched)])
    if actual == site.patched:
        return "patched"
    if site.original is not None:
        if actual == site.original:
            return "unpatched"
    else:
        # Site 3 (ModelMaxTokens): 140 bytes with a version-dependent `bl runtime.memequal` at +100..+104
        # +28 loads a Store field whose offset moves between releases (0x68 through v1.5.5, 0x148 in v1.5.6).
        head = MODEL_MAX_TOKENS_ORIG_HEAD
        if (
            actual[:28] == head[:28]
            and struct.unpack_from("<I", actual, 28)[0] & LDR_X_ANY_OFFSET == ldr_x(3, 0)
            and actual[32 : len(head)] == head[32:]
            and actual.endswith(MODEL_MAX_TOKENS_ORIG_TAIL)
            and actual[103] == 0x97
        ):
            return "unpatched"
        # Site 7b (applyFeatureProviderCheckpointOverrideConfig): 24 bytes with `bl errorreport.ReportError` at +16..+20
        if (
            len(actual) == 24
            and actual[:16] == bytes.fromhex("c10000b4e02b00f9e00301aae10302aa")
            and (actual[19] & 0xFC) == 0x94
            and actual[20:24] == bytes.fromhex("e02b40f9")
        ):
            return "unpatched"
        # Site 23 (stripMarkdownFormatting): 52 bytes with version-dependent `adrp+add` at +0..+8 and +32..+40
        if (
            len(actual) == 52
            and actual[8:24] == bytes.fromhex("e30740b2e4031faae5031faa06008092")
            and actual[40:52] == bytes.fromhex("e3037fb2e4031faae5031faa")
        ):
            return "unpatched"
    return f"unknown (at {hex(site.offset)}: {actual.hex()})"


def _file_stat_key(path: pathlib.Path) -> str:
    st = path.stat()
    return f"{path.resolve()}:{st.st_mtime_ns}:{st.st_size}"


def sha256_file(path: pathlib.Path) -> str:
    key = _file_stat_key(path)
    cache = _load_meta_cache()
    entry = cache.get("files", {}).get(key, {})
    if "sha256" in entry:
        return entry["sha256"]
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    digest = h.hexdigest()
    cache.setdefault("files", {}).setdefault(key, {})["sha256"] = digest
    _save_meta_cache(cache)
    return digest


def detect_binary_version(path: pathlib.Path) -> str:
    key = _file_stat_key(path)
    cache = _load_meta_cache()
    entry = cache.get("files", {}).get(key, {})
    if "version" in entry:
        return entry["version"]
    ver = "unknown"
    try:
        out = subprocess.check_output([str(path), "--version"], text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
        if out:
            ver = out.split()[0]
    except Exception:
        pass
    if ver != "unknown":
        cache.setdefault("files", {}).setdefault(key, {})["version"] = ver
        _save_meta_cache(cache)
    return ver


def backup_path_for(path: pathlib.Path) -> pathlib.Path:
    ver = detect_binary_version(path)
    suffix = f".v{ver}.orig" if ver != "unknown" else ".orig"
    return path.with_suffix(suffix)


def inspect_binary(path: pathlib.Path) -> tuple[str, tuple[PatchSite, ...]]:
    if not path.exists():
        return "missing", ()
    with path.open("rb") as f:
        head = f.read(4)
    if head.startswith(b"#!"):
        return "wrapper", ()
    data = path.read_bytes()
    sites = resolve_patch_sites(data, detect_binary_version(path))
    states = set()
    for site in sites:
        st = site_state(data, site)
        if st.startswith("unknown"):
            return st, sites
        states.add(st)
    if states == {"unpatched"}:
        return "unpatched", sites
    if states == {"patched"}:
        return "patched", sites
    return f"partial ({', '.join(sorted(states))})", sites


def codesign_adhoc(path: pathlib.Path) -> None:
    subprocess.run(["codesign", "-f", "-s", "-", str(path)], check=True)


def apply_patch(path: pathlib.Path) -> None:
    if path == GEMINI_WRAPPER_TARGET and HUB_WRAPPER_SOURCE.exists():
        state, _ = inspect_binary(path)
        if state != "wrapper" or path.read_bytes() != rendered_wrapper():
            path.write_bytes(rendered_wrapper())
            path.chmod(0o755)
            sidecar = path.parent / "agy.version.json"
            if sidecar.exists():
                sidecar.unlink()
            print(f"[wrap] Installed hub wrapper {HUB_WRAPPER_SOURCE} -> {path} (repo {REPO})")
            return

    # Always rebuild from the clean backup: the binary is exactly backup + every current site,
    # so an override removed from prompt_overrides.json is undone on the next apply. A binary patched
    # under an earlier rule for some site may no longer resolve; with a backup at hand, that is moot.
    backup = backup_path_for(path) if path.exists() else None
    try:
        state, _ = inspect_binary(path)
    except RuntimeError as exc:
        if backup is None or not backup.exists():
            raise
        state = f"unresolved ({exc})"
    if state in ("missing", "wrapper"):
        print(f"[skip] {path} ({state})")
        return
    backup = backup_path_for(path)
    if not backup.exists():
        if state != "unpatched":
            raise RuntimeError(f"Refusing to patch {path} without clean backup: state is {state}")
        shutil.copy2(path, backup)
        print(f"[bak]  Created backup {backup}")

    source = backup if backup.exists() else path
    data = bytearray(source.read_bytes())
    sites = resolve_patch_sites(data, detect_binary_version(path), strict=True)
    for site in sites:
        st = site_state(data, site)
        if st != "unpatched":
            raise RuntimeError(f"Unexpected state in {source} for {site.name}: {st}")
    if unreviewed := unreviewed_shapes(data, sites):
        raise RuntimeError(
            f"Stock code at {len(unreviewed)} site(s) in {source} has a shape no reviewed release had:\n  "
            + "\n  ".join(unreviewed)
            + "\nA site can land on the wrong instructions and still read as clean (references/context-window-patch.md §5.6)."
            "\nRead them with `probe_agy.py sites <previous .orig> <this .orig>`, then record them:"
            f"\n  patch_agy.py --accept-shapes --binary {path}"
        )
    for site in sites:
        data[site.offset : site.offset + len(site.patched)] = site.patched

    tmp_path = path.with_suffix(".patching")
    tmp_path.write_bytes(data)
    shutil.copymode(source, tmp_path)
    codesign_adhoc(tmp_path)
    tmp_path.replace(path)
    print(f"[done] Patched ({len(sites)} sites) and re-signed {path}")


def revert_patch(path: pathlib.Path) -> None:
    if not path.exists():
        print(f"[skip] {path} (missing)")
        return
    with path.open("rb") as f:
        if f.read(4).startswith(b"#!"):
            print(f"[skip] {path} (wrapper)")
            return

    backup = backup_path_for(path)
    if backup.exists():
        if path.read_bytes() == backup.read_bytes():
            print(f"[ok]   {path} is already unpatched")
            return
        tmp_path = path.with_suffix(".reverting")
        shutil.copy2(backup, tmp_path)
        codesign_adhoc(tmp_path)
        tmp_path.replace(path)
        print(f"[done] Restored {path} from {backup}")
        return

    state, sites = inspect_binary(path)
    if state == "unpatched":
        print(f"[ok]   {path} is already unpatched")
        return

    data = bytearray(path.read_bytes())
    for site in sites:
        if site.original is None:
            raise RuntimeError(f"Cannot revert {site.name} without backup file {backup}")
        data[site.offset : site.offset + len(site.original)] = site.original

    tmp_path = path.with_suffix(".reverting")
    tmp_path.write_bytes(data)
    shutil.copymode(path, tmp_path)
    codesign_adhoc(tmp_path)
    tmp_path.replace(path)
    print(f"[done] Reverted and re-signed {path}")


def set_context_window(preset: str) -> None:
    settings = json.loads(SETTINGS_PATH.read_text()) if SETTINGS_PATH.exists() else {}
    if preset == "Default":
        settings.pop("contextWindow", None)
    else:
        settings["contextWindow"] = preset
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"[cfg]  Updated {SETTINGS_PATH}: contextWindow={preset!r}")


def print_status(binaries: list[pathlib.Path], verbose: bool = False) -> None:
    for path in binaries:
        state, sites = inspect_binary(path)
        ver = detect_binary_version(path) if path.exists() else "-"
        digest = sha256_file(path)[:16] if path.exists() else "-"
        print(f"Binary   : {path} (v{ver}) -> {state} (sha256: {digest}...)")
        if verbose and sites:
            for idx, s in enumerate(sites, 1):
                print(f"  [{idx:02d}] [{s.domain}] {hex(s.va)} (off {hex(s.offset)}): {s.name} [{len(s.patched)}B]")
    if SETTINGS_PATH.exists():
        settings = json.loads(SETTINGS_PATH.read_text())
        print(f"Settings : {SETTINGS_PATH} -> model={settings.get('model')!r}, contextWindow={settings.get('contextWindow')!r}")
    env_override = os.environ.get("AGY_CLI_AUTO_COMPACT_OVERRIDE")
    print(f"Env Var  : AGY_CLI_AUTO_COMPACT_OVERRIDE={env_override!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="Show current binary and settings status")
    group.add_argument("--apply", action="store_true", help="Rebuild from the clean backup with every TUI site and prompt template applied")
    group.add_argument("--revert", action="store_true", help="Revert the binary patch to original bytes")
    group.add_argument("--accept-shapes", action="store_true",
                       help="Record the stock code shapes of a clean binary as reviewed (site_shapes.json), then show status")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print resolved virtual addresses for each site")
    parser.add_argument(
        "--set-window",
        choices=VALID_PRESETS,
        help="Optionally set 'contextWindow' in ~/.gemini/antigravity-cli/settings.json",
    )
    parser.add_argument(
        "--binary",
        type=pathlib.Path,
        action="append",
        help="Target specific agy binary path(s) (defaults to ~/.local/bin/agy and ~/.gemini/bin/agy)",
    )
    args = parser.parse_args()
    binaries = args.binary or list(DEFAULT_BINARIES)

    if args.apply:
        for path in binaries:
            apply_patch(path)
        if STATUSLINE_SOURCE.exists() and (
            not STATUSLINE_TARGET.exists() or STATUSLINE_SOURCE.read_bytes() != STATUSLINE_TARGET.read_bytes()
        ):
            tmp_sl = STATUSLINE_TARGET.with_suffix(".sh.tmp")
            shutil.copy2(STATUSLINE_SOURCE, tmp_sl)
            tmp_sl.replace(STATUSLINE_TARGET)
            print(f"[sync] Atomically synced {STATUSLINE_SOURCE} -> {STATUSLINE_TARGET}")
    elif args.revert:
        for path in binaries:
            revert_patch(path)
    elif args.accept_shapes:
        for path in binaries:
            if path.exists() and inspect_binary(path)[0] != "wrapper":
                accept_shapes(path)

    if args.set_window:
        set_context_window(args.set_window)

    print_status(binaries, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
