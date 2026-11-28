"""TUI style, palette, command-elbow, DEC 2031 color-scheme, adaptive code-theme, and statusline-refresh resolvers."""

from __future__ import annotations

import struct

from .asm import (
    LDR_X_ANY_OFFSET,
    LIPGLOSS_COPY_LOOP_X5_X4_ORIG,
    NOP,
    VM_BASE,
    PatchSite,
    _calls_to,
    _decode_sp_add,
    _decode_x27_sp_add,
    _encode_sp_add,
    _find_all,
    _frame_size,
    _go_frame,
    _ldr_sp,
    _recoverable,
    _section_file_bounds,
    _str_sp,
    assert_unreachable,
    branch_target,
    decode_adrp_add,
    decode_branch_target,
    encode_adr,
    encode_adrp,
    encode_adrp_add,
    encode_b,
    encode_b_eq,
    encode_bl,
    find_unique_anchor,
    find_unique_words,
    fold_lipgloss_copy_x5_x4,
    go_type_descriptor,
    ldr_x,
)
from .caves import CODE_THEME_LEAF_ROOM, _code_theme_leaf_base, _halloween_logo_slices

# Sites #48a-#48d constants
STYLES_ELBOW = 0x510
COMMAND_ELBOW = "  ⎿  ".encode()
COPY_STYLE = 0xD2800158  # mov x24, #0xa (one Style)

# Sites #41-#47 constants
FOCUS_MODE, COLOR_SCHEME_MODE = b"1004", b"2031"

# Site #58a constant
CODE_COMMENT_GRAY = (
    b'<entry type="Comment" style="italic #999999"/>',
    b'<entry type="Comment" style="italic #979797"/>',
)


def _copy_styles_insn(data: bytes | bytearray, rs_bounds: tuple[int, int]) -> int:
    """The `mov x24, #N` opening a whole-Styles NEON copy loop (0x33f through v1.5.9, 0x349 in v1.5.10+)."""
    found = {
        w
        for o in range(rs_bounds[0], rs_bounds[1] - 12, 4)
        if ((w := struct.unpack_from("<I", data, o)[0]) & 0xFFE0001F) == 0xD2800018
        and ((w >> 5) & 0xFFFF) >= 0x200
        and struct.unpack_from("<I", data, o + 4)[0] & 0xFFFFFC1F == 0xACC14410
    }
    if len(found) != 1:
        raise RuntimeError(f"resolveStyles: expected one whole-Styles copy loop count, found {[hex(x) for x in found]}")
    return found.pop()


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


def _styles_in_frame(data: bytes | bytearray, bounds: tuple[int, int], copy_styles: int) -> int:
    """sp offset of a Styles held in the frame: the source of its one whole-Styles copy."""
    words = range(bounds[0], bounds[1], 4)
    bases = {src[3] for o in words if struct.unpack_from("<I", data, o)[0] == copy_styles and (src := _copy_source(data, o))}
    if len(bases) != 1:
        raise RuntimeError(f"Expected one by-value Styles at {hex(VM_BASE + bounds[0])}, found {len(bases)}")
    return bases.pop()


def _styles_param(data: bytes | bytearray, caller: tuple[int, int], callee: tuple[int, int], copy_styles: int) -> int:
    """sp offset, inside `callee`, of the Styles that `caller` passes it by value.

    The caller copies Styles to its own `sp + D` before each `bl`; the callee sees that at `sp + frame + D`.
    D comes from the copy itself, since other by-value arguments can precede Styles.
    """
    dests = set()
    for off in range(caller[0], caller[1], 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w >> 26 != 0x25 or branch_target(w, off) != callee[0]:
            continue
        loop = next((o for o in range(off - 4, off - 160, -4) if struct.unpack_from("<I", data, o)[0] == copy_styles), None)
        src = _copy_source(data, loop) if loop else None
        stp_base = (struct.unpack_from("<I", data, loop + 8)[0] >> 5) & 0x1F if loop else None
        dest = _decode_sp_add(data, src[0] - 4) if src else None
        if dest is None or dest[1] != stp_base:
            raise RuntimeError(f"Cannot find where {hex(VM_BASE + caller[0])} places Styles for {hex(VM_BASE + callee[0])}")
        dests.add(dest[2])
    if len(dests) != 1:
        raise RuntimeError(f"Expected one Styles placement for {hex(VM_BASE + callee[0])}, found {sorted(dests)}")
    return _frame_size(data, callee) + dests.pop()


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
) -> tuple[tuple[PatchSite, ...], tuple[PatchSite, ...], int, tuple[int, int]]:
    """Sites #12-#14, #16-#22 & #24-#34: `"terminal"` ANSI palette, `● Tool(xxx)` typography, and the user prompt bar."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    # 12 & 13. types.init ("terminal" palette) ->
    #   Site 12: palette[+0x020] (Spinner shimmer & TUI Selector) from ANSI "12" to nil (Primary Foreground)
    #   Site 13: palette[+0x040] (User prompt) from ANSI "4" to nil (Primary Foreground)
    s12_base = find_unique_anchor(
        data,
        funcs["typesInit"],
        bytes.fromhex("a30080d25f7c81a85f7c81a85f7c81a85f7c81a8630400d163ffffb5"),
        "Site 12 (types.init terminal palette[+0x020])",
    )
    w_pal_base = word(s12_base - 0x20)
    if w_pal_base & 0xFFC003FF != 0x910003E2:  # add x2, sp, #pal_base
        raise RuntimeError("types.init: terminal palette zero-loop no longer opens with `add x2, sp, #imm`")
    pal_base = (w_pal_base >> 10) & 0xFFF

    def _find_pal_store(field_off: int, label: str) -> int:
        want = 0x910003FB | ((pal_base + field_off) << 10)  # add x27, sp, #(pal_base + field_off)
        hits = [
            o + 4
            for o in range(s12_base, min(s12_base + 0x80, funcs["typesInit"][1] - 4), 4)
            if word(o) == want and word(o + 4) in (0xA9000F62, 0xA9007F7F)
        ]
        if len(hits) != 1:
            raise RuntimeError(f"Expected 1 match for {label}, got {len(hits)}")
        return hits[0]

    s12_off = _find_pal_store(0x20, "Site 12 (types.init terminal palette[+0x020])")
    s12_va = VM_BASE + s12_off
    s13_off = _find_pal_store(0x40, "Site 13 (types.init terminal palette[+0x040])")
    s13_va = VM_BASE + s13_off

    # 14. render.resolveStyles ("terminal" scheme) -> mouse selection highlight uses native Reverse (\x1b[7m)
    rs_start, rs_end = funcs["resolveStyles"]
    copy_styles = _copy_styles_insn(data, funcs["resolveStyles"])
    s14_matches: list[int] = []
    pos = rs_start
    pat_len2 = bytes.fromhex("e1037fb2")
    while True:
        idx = data.find(pat_len2, pos, rs_end)
        if idx == -1:
            break
        if (
            idx + 0xE0 <= rs_end
            and data[idx - 0x98 : idx - 0x94] == bytes.fromhex("e10340b2")
            and data[idx - 0x44 : idx - 0x40] == bytes.fromhex("e10375b2")
            and data[idx + 0x54 : idx + 0x58] == bytes.fromhex("e10376b2")
            and any(word(o) == copy_styles for o in range(idx + 0x9C, min(idx + 0xE0, rs_end), 4))
        ):
            s14_matches.append(idx + 0x6C)
        pos = idx + 1
    if len(s14_matches) != 1:
        raise RuntimeError(f"Expected 1 match for Site 14 (resolveStyles Selection), got {len(s14_matches)}")
    s14_off = s14_matches[0]
    s14_va = VM_BASE + s14_off

    # 16, 19, 20, 21. render.resolveStyles -> locate the SchemeColors frame slot from the `mov x24, #5`
    # palette copy whose `pal + 0x40` load opens UserPrompt (`Bold` -> Site #21), followed by ToolName
    # (`pal + 0xD0` -> `pal + 0x10`, Site #19), ToolArgs (`pal + 0x120`, Site #20), and PromptChevron (Site #16).
    zero_loop_x5 = bytes.fromhex("450180d29f7c81a89f7c81a89f7c81a89f7c81a8a50400d165ffffb59f0000f9")
    pal_candidates: list[tuple[int, int, int]] = []  # (pal_sp, up_off, up_add_len)
    for o in range(rs_start, min(rs_start + 0x600, rs_end - 0x20), 4):
        if word(o) != 0xD28000B8:  # mov x24, #5 (368B SchemeColors copy)
            continue
        dst_reg = (word(o + 8) >> 5) & 0x1F  # stp q16, q17, [xD], #0x20
        pal_sp = None
        for back in range(o - 4, max(rs_start, o - 24), -4):
            dec = _decode_sp_add(data, back)
            if dec is not None and dec[1] == dst_reg:
                pal_sp = dec[2]
                break
        if pal_sp is None:
            continue
        for uo in range(o + 0x18, min(o + 0x400, rs_end - 0x80), 4):
            d27 = _decode_x27_sp_add(data, uo)
            if (
                d27 is not None
                and d27[1] == pal_sp + 0x40
                and word(uo + d27[0]) == 0xA9400F62  # ldp x2, x3, [x27]
            ):
                pal_candidates.append((pal_sp, uo, d27[0]))
                break
    unique_ups = {(p, u, l) for p, u, l in pal_candidates}
    if len(unique_ups) != 1:
        raise RuntimeError(f"resolveStyles: expected one UserPrompt color load after SchemeColors copy, found {len(unique_ups)}")
    pal_sp, up_off, _ = unique_ups.pop()
    z_off = data.find(zero_loop_x5, up_off, rs_end)
    if z_off == -1:
        raise RuntimeError("Site 16 (resolveStyles zero_loop_x5) not found")
    s16_off = z_off - 0x2C
    s16_va = VM_BASE + s16_off

    # 17 & 18. render.glamourStyle (v1.5.14+) / render.glamourStyleForScheme (v1.5.13) ->
    # decouple inline `code` (Code.Color) from palette[+0x020] (Accent) to palette[+0x0d0] (ToolFg, ANSI 3)
    if "glamourStyle" in funcs:
        gs_name = "render.glamourStyle"
        gs_start, gs_end = funcs["glamourStyle"]
        gs_pal_off = _go_frame(data, (gs_start, gs_end)) + 8
        gs_acc_off = gs_pal_off + 0x20
        gs_tool_off = gs_pal_off + 0xD0
        w_acc_ldr = 0xF94003E1 | ((gs_acc_off // 8) << 10)
        w_tool_ldr = 0xF94003E1 | ((gs_tool_off // 8) << 10)
        w_acc_ldp = 0xA94007E0 | ((gs_acc_off // 8) << 15)
        w_tool_ldp = 0xA94007E0 | ((gs_tool_off // 8) << 15)
        s17_matches = [
            o
            for o in range(gs_start, gs_end - 0x34, 4)
            if word(o) in (w_acc_ldr, w_tool_ldr)
            and word(o + 4) & 0xFF00001F == 0xB4000001
            and word(o + 0x18) == 0xB27C03E0
            and word(o + 0x30) in (w_acc_ldp, w_tool_ldp)
        ]
        if len(s17_matches) != 1:
            raise RuntimeError(f"Expected 1 match for Site 17 ({gs_name} Code.Color check), got {len(s17_matches)}")
        s17_off = s17_matches[0]
        s18_off = s17_off + 0x30
        s17_orig, s17_patched = struct.pack("<I", w_acc_ldr), struct.pack("<I", w_tool_ldr)
        s18_orig, s18_patched = struct.pack("<I", w_acc_ldp), struct.pack("<I", w_tool_ldp)
    else:
        gs_name = "render.glamourStyleForScheme"
        gs_start, gs_end = funcs["glamourStyleForScheme"]
        s17_matches = [
            o
            for o in range(gs_start, gs_end - 0x24, 4)
            if word(o) in (0xF9402FE1, 0xF94087E1)
            and word(o + 4) & 0xFF00001F == 0xB4000001
            and word(o + 8) == 0xB27C03E0
            and word(o + 0x20) in (0xA94587E0, 0xA95087E0)
        ]
        if len(s17_matches) != 1:
            raise RuntimeError(f"Expected 1 match for Site 17 ({gs_name} Code.Color check), got {len(s17_matches)}")
        s17_off = s17_matches[0]
        s18_off = s17_off + 0x20
        s17_orig, s17_patched = bytes.fromhex("e12f40f9"), bytes.fromhex("e18740f9")
        s18_orig, s18_patched = bytes.fromhex("e08745a9"), bytes.fromhex("e08750a9")
    s17_va = VM_BASE + s17_off
    s18_va = VM_BASE + s18_off

    # 19 & 20. render.resolveStyles ->
    #   Site 19: Styles[+0x0288] (ToolName `Bash`/`Edit`/`Read`) reads palette[+0x010] (colorless Bold)
    #   Site 20: Styles[+0x0510] (ToolArgs `(xxx)` & CoT header) uses native terminal Faint (\x1b[2m)
    s19_hits = [
        (o, d[0], d[1])
        for o in range(up_off + 0x80, min(up_off + 0x160, rs_end - 8), 4)
        if (d := _decode_x27_sp_add(data, o)) is not None
        and d[1] in (pal_sp + 0xD0, pal_sp + 0x10)
        and word(o + d[0]) == 0xA9400F62  # ldp x2, x3, [x27]
    ]
    if len(s19_hits) != 1:
        raise RuntimeError(f"resolveStyles: expected one ToolName color load after UserPrompt, found {len(s19_hits)}")
    s19_off, _, _ = s19_hits[0]
    s19_va = VM_BASE + s19_off
    if ((pal_sp + 0xD0) >> 12) != ((pal_sp + 0x10) >> 12):
        raise RuntimeError(f"resolveStyles: ToolName palette slots {hex(pal_sp + 0xD0)} and {hex(pal_sp + 0x10)} cross 4KB boundary")
    s19_orig = struct.pack("<I", 0x910003FB | (((pal_sp + 0xD0) & 0xFFF) << 10))
    s19_patched = struct.pack("<I", 0x910003FB | (((pal_sp + 0x10) & 0xFFF) << 10))

    s20_loads = [
        (o, d[0])
        for o in range(s19_off + 0x80, min(s19_off + 0x180, rs_end - 0x50), 4)
        if (d := _decode_x27_sp_add(data, o)) is not None
        and d[1] == pal_sp + 0x120
        and word(o + d[0]) == 0xA9400F62  # ldp x2, x3, [x27]
    ]
    if len(s20_loads) != 1:
        raise RuntimeError(f"resolveStyles: expected one ToolArgs color load after ToolName, found {len(s20_loads)}")
    ta_off = s20_loads[0][0]
    s20_pat_folded = fold_lipgloss_copy_x5_x4(0x20)
    s20_hits = [
        o
        for o in range(ta_off + 0x10, min(ta_off + 0x60, rs_end - 36), 4)
        if bytes(data[o : o + 36]) in (LIPGLOSS_COPY_LOOP_X5_X4_ORIG, s20_pat_folded)
    ]
    if len(s20_hits) != 1:
        raise RuntimeError(f"resolveStyles: expected one ToolArgs copy loop after pal+0x120 load, found {len(s20_hits)}")
    s20_off = s20_hits[0]
    s20_va = VM_BASE + s20_off

    # 21. render.resolveStyles -> Styles[+0x0000] (UserPrompt) Regular weight + adaptive 256-color background
    lc_start, _ = funcs["lipglossColor"]
    itab_va = decode_adrp_add(data, lc_start + 0xD0)
    ext_color_type_va = struct.unpack_from("<Q", data, itab_va - VM_BASE + 8)[0]
    bg_byte_va = _halloween_logo_slices(data, funcs)[0][2] + 23
    if data[bg_byte_va - VM_BASE] != 0:
        raise RuntimeError(f"bar-color slot {hex(bg_byte_va)} is not zero-initialized in __DATA,__data")
    bg_byte_imm12 = bg_byte_va & 0xFFF

    s21_hits = [
        o
        for o in range(up_off + 0x30, min(up_off + 0x80, rs_end - 20), 4)
        if word(o) in (0xB24003E1, 0xB27503E1)
        and word(o + 4) & 0x9F00001F == 0x90000002
        and word(o + 8) & 0xFFC003FF == 0x91000042
        and word(o + 12) & 0x9F00001F == 0x90000003
        and word(o + 16) & 0xFFC003FF == 0x91000063
    ]
    if len(s21_hits) != 1:
        raise RuntimeError(f"resolveStyles: UserPrompt no longer sets Bold where Site 21 expects it (found {len(s21_hits)})")
    s21_off = s21_hits[0]
    s21_va = VM_BASE + s21_off
    s21_orig = bytes(data[s21_off : s21_off + 20])
    s21_patched = (
        bytes.fromhex("e10375b2")
        + encode_adrp_add(s21_va + 4, ext_color_type_va, 2)
        + encode_adrp_add(s21_va + 12, bg_byte_va, 3)
    )
    if s21_orig == s21_patched:
        s21_orig = None

    # 22, 24, 25. render.renderUserPrompt
    rup_start, rup_end = funcs["renderUserPrompt"]
    s24_off = find_unique_anchor(
        data,
        funcs["renderUserPrompt"],
        bytes.fromhex("430800d1e38301f9"),
        "Site 24 (renderUserPrompt rule block)",
    )
    s24_va = VM_BASE + s24_off
    s24_orig = bytes(data[s24_off : s24_off + 72])
    rup_styles_off = _go_frame(data, funcs["renderUserPrompt"]) + 8
    w_slice, w_rule_ptr, w_rule_len = (
        struct.unpack_from("<I", data, s24_off + 0x5C)[0],
        struct.unpack_from("<I", data, s24_off + 0x6C)[0],
        struct.unpack_from("<I", data, s24_off + 0x70)[0],
    )
    if (
        w_slice & 0xFFC003FF != 0x910003E0
        or w_rule_ptr & 0xFFC003FF != 0xF90003E0
        or w_rule_len & 0xFFC003FF != 0xF90003E1
    ):
        raise RuntimeError("renderUserPrompt: rule slice or string spill slots moved")
    rup_slice_slot = (w_slice >> 10) & 0xFFF
    rup_rule_ptr_slot = ((w_rule_ptr >> 10) & 0xFFF) * 8
    rup_rule_len_slot = ((w_rule_len >> 10) & 0xFFF) * 8
    ldrb_w5_x4 = struct.pack("<I", 0x39400085 | (bg_byte_imm12 << 10))
    strb_w5_x4 = struct.pack("<I", 0x39000085 | (bg_byte_imm12 << 10))
    add_x4_styles = struct.pack("<I", 0x910003E4 | (rup_styles_off << 10))
    zero_rule_slots = struct.pack(
        "<III",
        _str_sp(31, rup_slice_slot),
        _str_sp(31, rup_rule_ptr_slot),
        _str_sp(31, rup_rule_len_slot),
    )
    s24_patched = (
        encode_adrp(s24_va, bg_byte_va, 4)
        + ldrb_w5_x4
        + bytes.fromhex("bf000071a61d8052c500851a")
        + strb_w5_x4
        + add_x4_styles
        + bytes.fromhex("050085d2850000f9823c00f9")
        + zero_rule_slots
        + bytes.fromhex("10000014")
        + bytes.fromhex("1b5b326d3e201b5b32326d000a0a0a00")
    )
    if s24_orig == s24_patched:
        s24_orig = None
    chev_va = s24_va + 56
    nl3_va = s24_va + 68

    add_x27_slice = 0x910003FB | (rup_slice_slot << 10)
    s22_pat_at = lambda off: encode_adr(VM_BASE + off, chev_va, 1) + bytes.fromhex("1f2003d5620180d2")
    s22_matches = [
        o
        for o in range(rup_start + 12, rup_end - 24, 4)
        if struct.unpack_from("<III", data, o - 12) == (add_x27_slice, 0xA9007F7F, 0xAA1F03E0)
        and struct.unpack_from("<I", data, o + 12)[0] & 0xFFE0FFFF == 0xAA0003E3
        and branch_target(struct.unpack_from("<I", data, o + 20)[0], o + 20) == funcs["concatstring2"][0]
        and (
            bytes(data[o : o + 12]) == s22_pat_at(o)
            or (
                struct.unpack_from("<I", data, o + 8)[0] == 0xB27F03E2
                and bytes(data[decode_adrp_add(data, o) - VM_BASE :][:2]) == b"> "
            )
        )
    ]
    if len(s22_matches) != 1:
        raise RuntimeError(f"Expected 1 match for Site 22 (renderUserPrompt first line), got {len(s22_matches)}")
    s22_off = s22_matches[0]
    s22_va = VM_BASE + s22_off
    s22_patched = s22_pat_at(s22_off)
    s22_orig = _recoverable(data, s22_off, s22_patched)

    joins = _calls_to(data, funcs["renderUserPrompt"], funcs["stringsJoin"][0])
    if len(joins) != 1 or struct.unpack_from("<I", data, joins[0] + 4 + 0x24)[0] != 0xA97FFBFD:
        raise RuntimeError("renderUserPrompt: expected one strings.Join before the final rule concat")
    s25_off = joins[0] + 4
    s25_va = VM_BASE + s25_off
    s25_orig = struct.pack("<I", _ldr_sp(2, rup_rule_len_slot))
    s25_patched = bytes.fromhex("09000014")

    # 26-29. render.StickyPrompt & ConversationModel
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
        ((ldr_x(2, 27), LDR_X_ANY_OFFSET),),
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
        + encode_adrp(s34_va + 48, bg_byte_va, 27)
        + strb_w5_x27
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
            name=f"{gs_name} -> inline `code` check uses palette[+0x0d0] (ANSI 3)",
            va=s17_va,
            offset=s17_off,
            original=s17_orig,
            patched=s17_patched,
        ),
        PatchSite(
            domain="palette-typography",
            name=f"{gs_name} -> inline `code` color uses palette[+0x0d0] (ANSI 3)",
            va=s18_va,
            offset=s18_off,
            original=s18_orig,
            patched=s18_patched,
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
    copy_styles = _copy_styles_insn(data, funcs["resolveStyles"])
    rco, rsl, rol = funcs["renderCommandOutput"], funcs["renderStyledLines"], funcs["renderOutputLines"]
    rco_styles = _styles_in_frame(data, rco, copy_styles)
    rsl_styles, rol_styles = _styles_param(data, rco, rsl, copy_styles), _styles_param(data, rco, rol, copy_styles)
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
    """In flush, `tbnz wN, #0, <enable>` (view.ReportFocus) on the first frame: always take it."""
    label = "tea.(*cursedRenderer).flush"
    load_off, _ = _find_mode_string_load(data, func_bounds, b"h", label)
    enable_block = load_off - 8
    start, end = func_bounds

    def is_guard(off: int) -> bool:
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
    s41, set_off = _resolve_mode_guard(data, funcs["rendererStart"], b"h", "tea.(*cursedRenderer).start")
    s42, reset_off = _resolve_mode_guard(data, funcs["rendererClose"], b"l", "tea.(*cursedRenderer).close")
    s43 = _resolve_first_frame_guard(data, funcs["rendererFlush"])
    s44, s45 = (
        PatchSite(
            "color-scheme",
            f"ansi focus mode string -> DEC 2031 ({name})",
            VM_BASE + off,
            off,
            b"\x1b[?" + FOCUS_MODE + suffix,
            b"\x1b[?" + COLOR_SCHEME_MODE + suffix,
        )
        for name, off, suffix in (("enable", set_off, b"h"), ("disable", reset_off, b"l"))
    )

    rbc = funcs["RequestBackgroundColor"][0]
    add_x0, add_x1 = struct.unpack_from("<I", data, rbc + 4)[0], struct.unpack_from("<I", data, rbc + 12)[0]
    if add_x0 & 0x1F != 0 or add_x1 & 0x1F != 1:
        raise RuntimeError("tea.RequestBackgroundColor no longer returns (x0 = type, x1 = &zerobase)")
    bg_msg_va, zerobase_va = decode_adrp_add(data, rbc), decode_adrp_add(data, rbc + 8)
    go_type = _section_file_bounds(data, "__DATA_CONST", "__go_type")
    bg_name = b"*tea.backgroundColorMsg"
    bg_rec = [i - 2 for i in _find_all(data, bg_name, go_type) if data[i - 1] == len(bg_name)]
    if len(bg_rec) != 1:
        raise RuntimeError("tea.backgroundColorMsg type name not found")
    types_base = bg_rec[0] - struct.unpack_from("<i", data, bg_msg_va - VM_BASE + 40)[0]
    dark_va = VM_BASE + go_type_descriptor(data, "*uv.DarkColorSchemeEvent", types_base)
    light_va = VM_BASE + go_type_descriptor(data, "*uv.LightColorSchemeEvent", types_base)

    t_start, _ = funcs["translateInputEvent"]
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


def _resolve_code_theme_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[PatchSite, ...]:
    """Sites #58a-#58f: flicker-free dark comments and adaptive light-mode code syntax highlighting."""
    ro_lo, ro_hi = _section_file_bounds(data, "__TEXT", "__rodata")
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: struct.pack(f"<{len(ws)}I", *ws)

    # 58a. chroma `native` style comment gray, off the 246/247 tie.
    start = data.find(b'<style name="native">', ro_lo, ro_hi)
    end = data.find(b"</style>", start, ro_hi) if start >= 0 else -1
    if start < 0 or end < 0:
        raise RuntimeError("chroma's `native` style is no longer embedded")
    hits = [o for needle in CODE_COMMENT_GRAY for o in _find_all(data, needle, (start, end))]
    if len(hits) != 1:
        raise RuntimeError(f"`native` style: expected one comment entry at #999999, found {len(hits)}")
    s58a_off = hits[0]
    stock, patched = CODE_COMMENT_GRAY
    s58a = PatchSite(
        "code-theme",
        "chroma `native` style -> comments #979797, nearest 246 alone (no 246/247 coin flip)",
        VM_BASE + s58a_off,
        s58a_off,
        _recoverable(data, s58a_off, patched, stock if bytes(data[s58a_off : s58a_off + len(stock)]) == stock else patched),
        patched,
    )

    bg_byte_va = _halloween_logo_slices(data, funcs)[0][2] + 23
    bg_imm12 = bg_byte_va & 0xFFF
    github_off = data.find(b"github", ro_lo, ro_hi)
    light_off = data.find(b"light", ro_lo, ro_hi)
    if github_off < 0 or light_off < 0:
        raise RuntimeError("code-theme: `github` or `light` string missing in __rodata")
    github_va = VM_BASE + github_off
    light_va = VM_BASE + light_off

    cave_off = _code_theme_leaf_base(data)
    cave_va = VM_BASE + cave_off
    qh_off = funcs["quickHighlight"][0]
    qh_va = VM_BASE + qh_off
    ss_off = funcs["sharedStyles"][0]
    ss_va = VM_BASE + ss_off

    cb_leaf_off = cave_off
    hc_leaf_off = cb_leaf_off + 72
    mk_leaf_off = hc_leaf_off + 68
    mc_leaf_off = mk_leaf_off + 28
    cb_leaf_va, hc_leaf_va = VM_BASE + cb_leaf_off, VM_BASE + hc_leaf_off
    mk_leaf_va, mc_leaf_va = VM_BASE + mk_leaf_off, VM_BASE + mc_leaf_off

    # 58c. ansi.(*CodeBlockElement).Render -> `bl quick.Highlight`
    cb_bounds = funcs["codeBlockRender"]
    cb_calls = [
        o
        for o in range(cb_bounds[0] + 16, cb_bounds[1], 4)
        if branch_target(word(o), o) in (qh_off, cb_leaf_off)
        and all((word(o - 16 + i * 4) & 0xFFC003FF) == (0xF94003E0 | (6 + i)) for i in range(4))
    ]
    if len(cb_calls) != 1:
        raise RuntimeError(f"CodeBlockElement.Render: expected 1 quick.Highlight call, found {len(cb_calls)}")
    s58c_off = cb_calls[0]
    s58c_va = VM_BASE + s58c_off

    # 58d. render.HighlightCode -> `bl render.SharedStyles`
    hc_bounds = funcs["highlightCode"]
    hc_calls = [
        o
        for o in range(hc_bounds[0] + 4, hc_bounds[1], 4)
        if branch_target(word(o), o) in (ss_off, hc_leaf_off)
        and (word(o - 4) & 0xFFC07FFF) == 0xA94007E0
    ]
    if len(hc_calls) != 1:
        raise RuntimeError(f"render.HighlightCode: expected 1 SharedStyles call, found {len(hc_calls)}")
    s58d_off = hc_calls[0]
    s58d_va = VM_BASE + s58d_off

    # 58e. render.newMarkdownInputs -> `ldr x9, [x9]`
    nmi_bounds = funcs["newMarkdownInputs"]
    nmi_hits = [
        o
        for o in range(nmi_bounds[0] + 16, nmi_bounds[1] - 12, 4)
        if word(o - 16) == 0xC8DFFD29
        and word(o - 12) == 0xB5000069
        and (word(o - 8) & 0x9F00001F) == 0x90000009
        and (word(o - 4) & 0xFFC003FF) == 0x91000129
        and (word(o) == 0xF9400129 or branch_target(word(o), o) == mk_leaf_off)
        and (word(o + 4) & 0xFFC003FF) == 0xF90003E9
        and word(o + 8) == 0xD503201F
        and (word(o + 12) & 0x9F00001F) == 0x9000000A
    ]
    if len(nmi_hits) != 1:
        raise RuntimeError(f"render.newMarkdownInputs: expected 1 themeGen load, found {len(nmi_hits)}")
    s58e_off = nmi_hits[0]
    s58e_va = VM_BASE + s58e_off

    # 58f. render.(*markdownCache).render -> `ldr x14, [x14]`
    mcr_bounds = funcs["markdownCacheRender"]
    mcr_hits = [
        o
        for o in range(mcr_bounds[0] + 20, mcr_bounds[1] - 8, 4)
        if word(o - 20) == 0xC8DFFDCE
        and word(o - 16) == 0xB500006E
        and (word(o - 12) & 0x9F00001F) == 0x9000000E
        and (word(o - 8) & 0xFFC003FF) == 0x910001CE
        and (word(o - 4) & 0xFFC003FF) == 0xF94003EF
        and (word(o) == 0xF94001CE or branch_target(word(o), o) == mc_leaf_off)
        and word(o + 4) == 0xEB0F01DF
        and (word(o + 8) & 0xFF00001F) == 0x54000001
    ]
    if len(mcr_hits) != 1:
        raise RuntimeError(f"markdownCache.render: expected 1 themeGen check load, found {len(mcr_hits)}")
    s58f_off = mcr_hits[0]
    s58f_va = VM_BASE + s58f_off

    bne = lambda insns: 0x54000001 | ((insns & 0x7FFFF) << 5)
    ldrb = lambda rt, rn, imm12: 0x39400000 | (imm12 << 10) | (rn << 5) | rt

    cb_leaf = (
        pack(0xF100193F, bne(16))
        + encode_adrp(cb_leaf_va + 8, bg_byte_va, 10)
        + pack(
            ldrb(10, 10, bg_imm12),
            0x7103F95F,
            bne(12),
            0xB940010A,
            0x528C2DCB,
            0x72AD2E8B,
            0x6B0B015F,
            bne(7),
            0x7940090A,
            0x528CAECB,
            0x6B0B015F,
            bne(3),
        )
        + encode_adrp_add(cb_leaf_va + 60, github_va, 8)
        + encode_b(cb_leaf_va + 68, qh_va)
    )

    hc_leaf = (
        pack(0xF100203F, bne(15))
        + encode_adrp(hc_leaf_va + 8, bg_byte_va, 10)
        + pack(
            ldrb(10, 10, bg_imm12),
            0x7103F95F,
            bne(11),
            0xF940000A,
            0xD28CAE8B,
            0xF2ADAE4B,
            0xF2CDCD2B,
            0xF2ED8C2B,
            0xEB0B015F,
            bne(4),
        )
        + encode_adrp_add(hc_leaf_va + 52, light_va, 0)
        + pack(0xD28000A1)
        + encode_b(hc_leaf_va + 64, ss_va)
    )

    mk_leaf = (
        pack(0xF9400129)
        + encode_adrp(mk_leaf_va + 4, bg_byte_va, 10)
        + pack(
            ldrb(10, 10, bg_imm12),
            0x7103F95F,
            0x9A9F17EA,
            0xCA0AFD29,
        )
        + encode_b(mk_leaf_va + 24, s58e_va + 4)
    )

    mc_leaf = (
        pack(0xF94001CE)
        + encode_adrp(mc_leaf_va + 4, bg_byte_va, 12)
        + pack(
            ldrb(12, 12, bg_imm12),
            0x7103F99F,
            0x9A9F17EC,
            0xCA0CFDCE,
        )
        + encode_b(mc_leaf_va + 24, s58f_va + 4)
    )

    cave_code = cb_leaf + hc_leaf + mk_leaf + mc_leaf
    if len(cave_code) != 196 or len(cave_code) > CODE_THEME_LEAF_ROOM:
        raise RuntimeError(f"code-theme leaves size mismatch ({len(cave_code)}B > {CODE_THEME_LEAF_ROOM}B)")

    return (
        s58a,
        PatchSite(
            "code-theme",
            "__TEXT fill -> adaptive light/dark code-theme & markdown-cache leaves",
            cave_va,
            cave_off,
            b"\x00" * len(cave_code),
            cave_code,
        ),
        PatchSite(
            "code-theme",
            "ansi.(*CodeBlockElement).Render -> adaptive `github` Chroma theme on light terminals",
            s58c_va,
            s58c_off,
            encode_bl(s58c_va, qh_va),
            encode_bl(s58c_va, cb_leaf_va),
        ),
        PatchSite(
            "code-theme",
            "render.HighlightCode -> adaptive `light` (`github`) code preview on light terminals",
            s58d_va,
            s58d_off,
            encode_bl(s58d_va, ss_va),
            encode_bl(s58d_va, hc_leaf_va),
        ),
        PatchSite(
            "code-theme",
            "render.newMarkdownInputs -> include light/dark polarity in markdownCache key",
            s58e_va,
            s58e_off,
            pack(0xF9400129),
            encode_b(s58e_va, mk_leaf_va),
        ),
        PatchSite(
            "code-theme",
            "render.(*markdownCache).render -> verify light/dark polarity before caching markdown",
            s58f_va,
            s58f_off,
            pack(0xF94001CE),
            encode_b(s58f_va, mc_leaf_va),
        ),
    )
