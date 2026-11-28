"""Cortex engine resolvers: context-window clamps, tool monitors, work-efficiently, subagent models, and prompt templates."""

from __future__ import annotations

import struct

import prompt_templates

from .asm import (
    VM_BASE,
    PatchSite,
    _adrp_add_at,
    _calls_to,
    _recoverable,
    _sp_slot,
    branch_target,
    encode_b,
    find_unique_anchor,
)


def _resolve_context_window_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[PatchSite, ...]:
    """Sites #7a-#7d: Remove Cortex 256K checkpointer ceilings and 64K USER_INPUT step clamps.

    v1.5.15 widened native `AGY_CLI_AUTO_COMPACT_OVERRIDE` across all eligible models with
    `/context` and `/model` display, retiring the old dead-flag `/model` selector and
    `BuildStatusLineData` sites (#1-#7, #1a-#2b). `hub-wrapper.sh` exports `AUTO_COMPACT_WINDOW`
    from `agy-neo.conf` as `AGY_CLI_AUTO_COMPACT_OVERRIDE`, and `statusline.sh` computes its
    usage percentage against the same effective threshold.
    """
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


def _resolve_monitor_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Disable synchronous pre-tool monitors regardless of embedded or remote Mendel config.

    Patching the embedded `MonitorsConfig` textproto (`enabled:false`) is overridden on OAuth
    sessions by `jetski.getMendelConfig` -> `MergeMonitorsConfig`. Every monitor factory gates on
    `agent_monitoring.isMonitorEnabled`; returning false at entry (`mov x0, xzr; ret`) disables
    both embedded and remote Mendel monitors cleanly with zero stack usage.
    """
    fn_start = funcs["isMonitorEnabled"][0]
    answer_no = bytes.fromhex("e0031faac0035fd6")  # mov x0, xzr; ret
    head = bytes(data[fn_start : fn_start + 8])
    if head != answer_no and head[:4] != bytes.fromhex("900b40f9"):  # ldr x16, [x28, #0x10]
        raise RuntimeError("agent_monitoring.isMonitorEnabled no longer opens with its stack check")
    return (
        PatchSite(
            domain="tool-monitors",
            name="agent_monitoring.isMonitorEnabled -> false (disable embedded and Mendel pre-tool monitors)",
            va=VM_BASE + fn_start,
            offset=fn_start,
            original=_recoverable(data, fn_start, answer_no),
            patched=answer_no,
        ),
    )


def _resolve_work_efficiently_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[PatchSite, ...]:
    """Suppress `<work_efficiently>` prompt section and single-tool-turn reminder hook in all auth modes.

    1. `mixins.(*WorkEfficientlySection).ShouldInclude` returns `false` (`mov x0, xzr; ret`),
       so the 949-char Go-generated `<work_efficiently>` section is never injected even when OAuth
       Mendel flags or `AGY_CLI_WORK_EFFICIENTLY` enable it.
    2. `prehooks.newWorkEfficientlyReminderHook.func1` has Go ABI signature
       `func(context.Context, *core.InvocationContext) (*core.InvocationHookResult, error)`,
       returning `(x0, x1, x2)`. `core.runInvocationHooks` explicitly checks `cbz x0` (nil result)
       and `cbnz x1` (non-nil error), matching sibling `newMessageDeliveryHook.func1`. Zeroing all
       three return registers (`x0`, `x1`, `x2`) and returning at entry (`16B`) is a zero-allocation
       leaf with no stack frame or call sites (§5.5).
    """
    word = lambda o: struct.unpack_from("<I", data, o)[0]

    si_start, si_end = funcs["workEfficientlyShouldInclude"]
    if si_end - si_start < 8:
        raise RuntimeError("WorkEfficientlySection.ShouldInclude is smaller than 8 bytes")
    si_stock = bytes.fromhex("e00340b2c0035fd6")  # orr x0, xzr, #0x1; ret
    si_patched = bytes.fromhex("e0031faac0035fd6")  # mov x0, xzr; ret
    si_head = bytes(data[si_start : si_start + 8])
    if si_head not in (si_stock, si_patched):
        raise RuntimeError(
            f"WorkEfficientlySection.ShouldInclude unexpected entry bytes: {si_head.hex()}"
        )

    hk_start, hk_end = funcs["workEfficientlyReminderHook"]
    if hk_end - hk_start < 16:
        raise RuntimeError("newWorkEfficientlyReminderHook.func1 is smaller than 16 bytes")
    hk_patched = bytes.fromhex("e0031faae1031faae2031faac0035fd6")  # mov x0,xzr; mov x1,xzr; mov x2,xzr; ret
    hk_head = bytes(data[hk_start : hk_start + 16])
    if hk_head != hk_patched:
        if (
            hk_head[:8] != bytes.fromhex("900b40f9ff6330eb")  # ldr x16, [x28, #0x10]; cmp sp, x16
            or (word(hk_start + 8) & 0xFF00001F) != 0x54000009  # b.ls morestack
            or (word(hk_start + 12) & 0xFFE00FFF) != 0xF8000FFE  # str x30, [sp, #-frame]!
        ):
            raise RuntimeError(
                f"newWorkEfficientlyReminderHook.func1 unexpected prologue: {hk_head.hex()}"
            )

    return (
        PatchSite(
            domain="work-efficiently",
            name="mixins.(*WorkEfficientlySection).ShouldInclude -> false (omit <work_efficiently> in all auth modes)",
            va=VM_BASE + si_start,
            offset=si_start,
            original=si_stock,
            patched=si_patched,
        ),
        PatchSite(
            domain="work-efficiently",
            name="prehooks.newWorkEfficientlyReminderHook.func1 -> return (nil, nil) at entry (suppress single-tool reminders)",
            va=VM_BASE + hk_start,
            offset=hk_start,
            original=_recoverable(data, hk_start, hk_patched),
            patched=hk_patched,
        ),
    )


def _resolve_subagent_model_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[PatchSite, ...]:
    """Unlock explicit dropdown model IDs for `invoke_subagent` and `run_workflow` under OAuth.

    In `cortex.(*CascadeManager).populatePlatformModels`, upstream checks the experiment flag
    `"enable-subagent-dropdown-models"` via `runtime.mapaccess2_faststr`: when true, it passes
    the full `*FetchAvailableModelsResponse` (`[sp, #0x50]`) to `SubagentModelsFromAvailableModels`;
    when false, it constructs a stripped struct carrying only `TieredModelIds` (`flash_lite`/`flash`/`pro`).
    Replacing the `tbz w1, #0, false_branch` right after `mapaccess2_faststr` with an unconditional
    `b true_branch` keeps both stock call PCs intact (§5.5) and unlocks every available model ID
    (such as `gemini-4-neon-xhigh`) in `SubagentModelOptions`.
    """
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pm = funcs["populatePlatformModels"]
    map_fn = funcs["mapaccess2Faststr"][0]
    sub_fn = funcs["subagentModelsFromAvailable"][0]
    flag = b"enable-subagent-dropdown-models"

    flag_calls: list[int] = []
    for call_off in _calls_to(data, pm, map_fn):
        if call_off < pm[0] + 12:
            continue
        va = _adrp_add_at(data, call_off - 12, 2)
        if (
            va is not None
            and 0 <= va - VM_BASE <= len(data) - len(flag)
            and bytes(data[va - VM_BASE : va - VM_BASE + len(flag)]) == flag
            and word(call_off - 4) == 0xB24013E3  # orr x3, xzr, #0x1f (len == 31)
        ):
            flag_calls.append(call_off)
    if len(flag_calls) != 1:
        raise RuntimeError(
            f"populatePlatformModels: expected 1 `enable-subagent-dropdown-models` lookup, found {len(flag_calls)}"
        )

    gate_off = flag_calls[0] + 4
    sub_calls = [c for c in _calls_to(data, pm, sub_fn) if c > gate_off]
    if len(sub_calls) != 2:
        raise RuntimeError(
            f"populatePlatformModels: expected 2 SubagentModelsFromAvailableModels calls after flag lookup, found {len(sub_calls)}"
        )

    true_target = sub_calls[0] - 4
    resp_load = _sp_slot(word(true_target), 0xF94003E0)
    if resp_load is None or resp_load[0] != 0:
        raise RuntimeError("populatePlatformModels: true branch no longer loads `*FetchAvailableModelsResponse` into x0")
    if word(sub_calls[0] + 4) >> 26 != 0x05:  # b merge
        raise RuntimeError("populatePlatformModels: true branch no longer jumps to merge after call")
    false_target = sub_calls[0] + 8

    gate_patched = encode_b(VM_BASE + gate_off, VM_BASE + true_target)
    w_gate = word(gate_off)
    if bytes(data[gate_off : gate_off + 4]) != gate_patched:
        if (w_gate & 0xFFF8001F) != 0x36000001 or branch_target(w_gate, gate_off) != false_target:
            raise RuntimeError(
                f"populatePlatformModels: expected `tbz w1, #0, {hex(VM_BASE + false_target)}` at {hex(VM_BASE + gate_off)}, got {hex(w_gate)}"
            )

    return (
        PatchSite(
            domain="subagent-models",
            name='cortex.(*CascadeManager).populatePlatformModels -> bypass "enable-subagent-dropdown-models" gate (unlock explicit subagent models)',
            va=VM_BASE + gate_off,
            offset=gate_off,
            original=_recoverable(data, gate_off, gate_patched),
            patched=gate_patched,
        ),
    )


def _resolve_prompt_template_sites(data: bytes | bytearray, version: str, strict: bool) -> tuple[PatchSite, ...]:
    """Templates that templates/v<version>/system_prompts/ changes from stock (see prompt_templates.py)."""
    return tuple(
        PatchSite(
            "prompt",
            f"{o.action} system_prompts/{o.name}",
            VM_BASE + o.slot.offset,
            o.slot.offset,
            o.original,
            o.patched,
        )
        for o in prompt_templates.resolve_overrides(data, version, strict)
    )
