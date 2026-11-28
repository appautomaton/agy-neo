"""Pending line resolvers: breathing Gemini star, running light, gap, elapsed aside, verbs, and star tool marks."""

from __future__ import annotations

import struct

from .asm import (
    NOP,
    VM_BASE,
    PatchSite,
    _adrp_add_at,
    _calls_to,
    _find_all,
    _go_frame,
    _ldr_sp,
    _recoverable,
    _section_file_bounds,
    _slice_loads,
    _sp_slot,
    _str_sp,
    _text_tail_cave,
    _words,
    assert_unreachable,
    branch_target,
    decode_adrp_add,
    encode_adrp_add,
    encode_b,
    encode_b_cond,
    encode_b_ne,
    encode_bl,
)
from .caves import (
    ELAPSED_CODE,
    GAP_LEAF_ROOM,
    LIGHT_LEAF_ROOM,
    _elapsed_base,
    _gap_leaf_base,
    _halloween_logo_slices,
    _light_detour_base,
)
from .symbols import all_known_symbols

SPINNER_STOCK = "⣾ ⣷ ⣯ ⣟ ⡿ ⢿ ⣻ ⣽ ".encode()
GEMINI_BLUE, GEMINI_PURPLE, GEMINI_ROSE = 0x4796E3, 0x9177C7, 0xCA6673
LONG_TURN, STAGE_SECONDS, TURN_STAGES = 60, 12, 16
SPINNER_BREATH = (
    ("∙", .20, 0), ("∙", .30, 0), ("⋅", .40, .1), ("⋅", .50, .2), ("✦", .60, .4), ("✦", .80, .7),
    ("✦", 1.0, 1.0), ("✦", .85, .8), ("✦", .70, .5), ("✦", .60, .2), *(("✦", .50, 0),) * 10,
    ("✦", .40, 0), ("⋅", .35, 0), ("∙", .25, 0), ("∙", .20, 0),
)
GEMINI_BAND_DARK = ("#8CBDF0", "#B4C4F4", "#D9CDF5", "#C2AEEA", "#A48FD6")
GEMINI_BAND_LIGHT = ("#2F6FBF", "#4A62C2", "#6553BD", "#7A4DB5", "#8A5CB8")
PALETTE_DIM = 0x130
PENDING_LIGHT_STEP = (80, 100)

ELLIPSIS = "…"
ELAPSED_FORMAT = b" \x1b[38;2;153;153;153m(%[2]s)%-[1]*.0[2]s\x1b[39m"
ELAPSED_EMPTY_FORMAT = b"%-[1]*.0[2]s"
ELAPSED_STATES = {3: " ⋅ thinking", 4: " ⋅ running"}
ELAPSED_LONG_THOUGHT = " ⋅ deep in thought"
EFFORT_WORDS = (("(Low)", "low"), ("(Medium)", "medium"), ("(High)", "high"), ("(XHigh)", "xhigh"), ("(Max)", "max"))
EFFORT_PHRASE = " with {} effort"
STATUS_RESERVE = 36
LABEL_RESERVE = 10
MOV_X6_XZR = 0xAA1F03E6

PENDING_VERBS = (
    "Stargazing", "Starhopping", "Constellating", "Twinkling", "Glimmering", "Scintillating",
    "Shimmering", "Gleaming", "Radiating", "Kindling", "Dawning", "Starweaving",
    "Eclipsing", "Transiting", "Culminating", "Precessing", "Gravitating", "Accreting",
    "Spiraling", "Drifting", "Wayfinding", "Charting", "Triangulating", "Luminescing",
)

TOOL_MARKS = {"●": "⋆", "○": "⊹"}
SWARM_MARK = "✦"
TOOL_MARK_FUNCS = (
    "markTool", "markStatus", "markRunningDot", "markTask", "markSubagent", "markBackground",
    "markMilestone", "markWorkflowAgent", "markWorkflowCall", "markWorkflow", "markStepRow",
)


def _pending_line_fn(funcs: dict[str, tuple[int, int]]) -> tuple[str, tuple[int, int]]:
    """Return `(method_name, bounds)` for `pendingLineLayout` (v1.5.19+) or `pendingLineView` (<=v1.5.18)."""
    if "pendingLineLayout" in funcs:
        return "pendingLineLayout", funcs["pendingLineLayout"]
    return "pendingLineView", funcs["pendingLineView"]


def _breath_frame(glyph: str, light: float, hue: float) -> bytes:
    mix = lambda a, b, t: tuple(round(x + (y - x) * t) for x, y in zip(a, b))
    rgb = lambda h: ((h >> 16) & 255, (h >> 8) & 255, h & 255)
    tone = mix(rgb(GEMINI_BLUE), rgb(GEMINI_PURPLE), hue)
    r, g, b = mix((0, 0, 0), tone, light / 0.5) if light < 0.5 else mix(tone, (255, 255, 255), (light - 0.5) * 0.9)
    return f"\x1b[38;2;{r};{g};{b}m{glyph}\x1b[m ".encode()


def _turn_color(t: float) -> tuple[int, int, int]:
    """The Gemini gradient at t in [0, 1]: blue, purple at the middle, rose at the end."""
    rgb = lambda h: ((h >> 16) & 255, (h >> 8) & 255, h & 255)
    a, b, u = (GEMINI_BLUE, GEMINI_PURPLE, t * 2) if t <= 0.5 else (GEMINI_PURPLE, GEMINI_ROSE, t * 2 - 1)
    return tuple(round(x + (y - x) * u) for x, y in zip(rgb(a), rgb(b)))


def _gemini_fill(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[int, bytes, dict]:
    """Read-only strings and tables for Sites #49, #56 and #57, laid out in dead `halloween.paint`."""
    frames = list(dict.fromkeys(_breath_frame(*f) for f in SPINNER_BREATH))
    colors = [c.encode() for c in GEMINI_BAND_DARK + GEMINI_BAND_LIGHT]
    rgba = b"".join(bytes((*_turn_color(i / (TURN_STAGES - 1)), 255)) for i in range(TURN_STAGES))
    if any(not 0 < len(v) < 16 or not v.isascii() for v in PENDING_VERBS):
        raise RuntimeError("each pending-line verb must be 1-15 ASCII bytes")
    verbs = b"".join((bytes([len(v)]) + v.encode()).ljust(16, b"\x00") for v in PENDING_VERBS)
    marks = [*(m.encode() for m in TOOL_MARKS.values()), SWARM_MARK.encode()]
    raw = verbs + rgba + b"".join(frames) + b"".join(colors) + b"".join(marks)
    blob = raw.ljust((len(raw) + 15) & ~15, b"\x00")
    paint_start, paint_end = funcs["halloweenPaint"]
    if len(blob) > paint_end - paint_start:
        raise RuntimeError(f"halloween.paint has {paint_end - paint_start}B; Sites #49/#56/#57 data needs {len(blob)}B")
    at: dict = {"verbs": VM_BASE + paint_start, "rgba": VM_BASE + paint_start + len(verbs)}
    pos = at["rgba"] + len(rgba)
    for x in frames + colors + marks:
        at[x] = pos
        pos += len(x)
    return paint_start, blob, at


def _turn_start(data: bytes | bytearray, rf: tuple[int, int]) -> tuple[int, int, int]:
    """(offset of refreshActivityLabel's Compacting test, VA of its stamp branch, model offset of the start)."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    stamp = [
        o
        for o, w in _words(data, (rf[0], rf[1] - 4))
        if w in (0xF1001C7F, 0xF100007F) and word(o + 4) & 0xFF00001E == 0x54000000
    ]
    if len(stamp) != 1:
        raise RuntimeError(f"refreshActivityLabel: expected one Compacting test, found {len(stamp)}")
    stamp_va = branch_target(word(stamp[0] + 4), stamp[0] + 4) + VM_BASE
    lo_add, hi_add = word(stamp_va - VM_BASE + 4), word(stamp_va - VM_BASE + 8)
    if lo_add & 0xFFC0001F != 0x9100001B or hi_add & 0xFFC003FF != 0x9140037B:
        raise RuntimeError("refreshActivityLabel: the Compacting branch no longer addresses its start field")
    return stamp[0], stamp_va, ((hi_add >> 10) & 0xFFF) << 12 | ((lo_add >> 10) & 0xFFF)


def _aside_tiers() -> list[tuple[bytes, int, int]]:
    """Progressive aside tier table `(format_bytes, base_cols, fallback_id)` in strict topological order (`fb < id`)."""
    fmt_for = lambda st: ELAPSED_FORMAT.replace(b")%", st.encode() + b")%")
    assert len(EFFORT_WORDS) == 5, "select_aside indices assume 5 EFFORT_WORDS entries"
    tiers: list[tuple[bytes, int, int]] = [
        (ELAPSED_EMPTY_FORMAT, 0, 0),
        (ELAPSED_FORMAT, 3, 0),
        (fmt_for(ELAPSED_STATES[4]), 3 + len(ELAPSED_STATES[4]), 1),
        (fmt_for(ELAPSED_STATES[3]), 3 + len(ELAPSED_STATES[3]), 1),
    ]
    for _, shown in EFFORT_WORDS:
        st = ELAPSED_STATES[3] + EFFORT_PHRASE.format(shown)
        tiers.append((fmt_for(st), 3 + len(st), 3))
    tiers.append((fmt_for(ELAPSED_LONG_THOUGHT), 3 + len(ELAPSED_LONG_THOUGHT), 3))
    for _, shown in EFFORT_WORDS:
        st = ELAPSED_STATES[3] + EFFORT_PHRASE.format(shown)
        tiers.append((fmt_for(st), 3 + len(st), 9))
    for i, (_, shown) in enumerate(EFFORT_WORDS):
        st = ELAPSED_LONG_THOUGHT + EFFORT_PHRASE.format(shown)
        tiers.append((fmt_for(st), 3 + len(st), 10 + i))
    for idx, (_, base_cols, fb) in enumerate(tiers):
        if idx > 0 and not (0 <= fb < idx and base_cols < 256):
            raise RuntimeError(f"aside tier {idx} violates strict topological fallback order")
    return tiers


def _model_label_path(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> dict:
    """Field offsets from the conversation model to the model's label, read from agy's own accessors."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    imm = lambda w: ((w >> 10) & 0xFFF) * 8
    mv = [
        imm(w)
        for _, w in _words(data, (funcs["messageListViewportHeight"][0], funcs["messageListViewportHeight"][0] + 0x30))
        if w & 0xFFC003FF == 0xF9400001
    ]
    st = [imm(w) for _, w in _words(data, funcs["managerStore"]) if w & 0xFFC003FF == 0xF9400000]
    cl = funcs["currentModelLabel"]
    lab = [
        (imm(word(o)), ((word(o + 8) >> 15) & 0x7F) * 8)
        for o, w in _words(data, (cl[0], cl[1] - 8))
        if w & 0xFFC003FF == 0xF9400001
        and word(o + 4) & 0xFF00001F == 0xB4000001
        and word(o + 8) & 0xFFC07FFF == 0xA9400820
    ]
    if len(mv) != 1 or len(st) != 1 or len(lab) != 1:
        raise RuntimeError("the model label's path through ConversationModel -> Manager -> Store -> Config moved")
    return {"manager": mv[0], "store": st[0], "config": lab[0][0], "label": lab[0][1]}


def _elapsed_detours(
    data: bytes | bytearray,
    funcs: dict[str, tuple[int, int]],
    fmt_off: int,
    width_slot: int,
    dur_len_slot: int,
    secs_slot: int,
    conv: int,
    fmt_load: int,
) -> dict:
    """Site #50i: unified adaptive aside selector (`select_aside`) in `__TEXT` fill + tier table in `halloween.paint`."""
    del fmt_off
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    pv_name, pv = _pending_line_fn(funcs)
    rf, cl = funcs["refreshActivityLabel"], funcs["compactingLabel"]
    frame = _go_frame(data, cl)
    m_slot = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (pv[0], pv[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    _, _, start = _turn_start(data, rf)
    kind = start - 0x10
    stores = [
        o
        for o, w in _words(data, (rf[0], rf[1] - 4))
        if w & 0xFFC0001F == 0x9140001B
        and word(o + 4) & 0xFFC003E0 == 0xF9000360
        and (((w >> 10) & 0xFFF) << 12) + ((word(o + 4) >> 10) & 0xFFF) * 8 == kind
    ]
    if m_slot is None or not stores:
        raise RuntimeError(f"elapsedSuffix: {pv_name}'s m spill or the model's state kind moved")
    if frame + m_slot > 0x7FF8 or (frame + m_slot) % 8 or kind >> 24 or (kind & 0xFFF) % 8:
        raise RuntimeError("elapsedSuffix: the caller's m or the state kind is out of reach of one load")
    tiers = _aside_tiers()
    base = _elapsed_base(data)
    va = VM_BASE + base
    gemini_off, gemini_blob, _ = _gemini_fill(data, funcs)
    paint_end = funcs["halloweenPaint"][1]
    data_off = gemini_off + len(gemini_blob)
    data_va = VM_BASE + data_off
    match_va = data_va
    table_va = match_va + 16 * (len(EFFORT_WORDS) + 1)
    fmts_va = table_va + 8 * len(tiers)
    fmt_pos: dict[bytes, int] = {}
    unique_fmts: list[bytes] = []
    pos = fmts_va
    for fmt_bytes, _, _ in tiers:
        if fmt_bytes not in fmt_pos:
            fmt_pos[fmt_bytes] = pos
            unique_fmts.append(fmt_bytes)
            pos += len(fmt_bytes)
    label = _model_label_path(data, funcs)
    movz = lambda rd, imm: 0xD2800000 | (imm << 5) | rd
    cmp = lambda rn, imm: 0xF100001F | (imm << 10) | (rn << 5)
    adr = lambda pc, target, rd: 0x10000000 | ((target - pc) & 3) << 29 | (((target - pc) >> 2) & 0x7FFFF) << 5 | rd
    cbz_r = lambda rt, pc, target: 0xB4000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | rt

    def effort(at_va: int, match_table_va: int) -> bytes:
        ldr = lambda rt, rn, off: 0xF9400000 | (off // 8) << 10 | rn << 5 | rt
        cbz = lambda rt, i, j: 0xB4000000 | ((j - i) & 0x7FFFF) << 5 | rt
        bcond = lambda i, j, c: 0x54000000 | ((j - i) & 0x7FFFF) << 5 | c
        LOOP, NONE, OUT = 15, 22, 23
        words = [
            0xAA1F03EC, ldr(10, 10, label["manager"]), cbz(10, 2, OUT),
            ldr(10, 10, label["store"]), cbz(10, 4, OUT),
            ldr(10, 10, label["config"]), cbz(10, 6, OUT),
            0xA9400000 | (label["label"] // 8) << 15 | 13 << 10 | 10 << 5 | 11,
            cmp(13, 8), bcond(9, OUT, 0xB),
            0x8B0D016B, 0xF85F816E,
            None, None, movz(12, 1),
            0xA8C125AA, cbz(9, 16, NONE), 0x8A0901C9, 0xEB0A013F, bcond(19, OUT, 0x0),
            0x9100058C, 0x14000000 | ((LOOP - 21) & 0x3FFFFFF),
            0xAA1F03EC, 0xD61F01E0,
        ]
        words[12:14] = struct.unpack("<II", encode_adrp_add(at_va + 12 * 4, match_table_va, 13))
        if len(words) != 24:
            raise RuntimeError("the effort matcher's layout drifted")
        return pack(*words)

    width_va = va
    fmt_va = width_va + 12
    sel_va = fmt_va + 20

    width_entry = (
        pack(adr(width_va, width_va + 8, 15))
        + encode_b(width_va + 4, sel_va)
        + encode_b(width_va + 8, VM_BASE + conv)
    )
    fmt_entry = (
        pack(adr(fmt_va, fmt_va + 8, 15))
        + encode_b(fmt_va + 4, sel_va)
        + pack(0xAA0103E0, 0xAA0203E1)
        + encode_b(fmt_va + 16, VM_BASE + fmt_load + 12)
    )

    sel = bytearray()
    cur = lambda: sel_va + len(sel)
    sel += pack(
        _ldr_sp(10, frame + m_slot),
        0x91400000 | ((kind >> 12) << 10) | (10 << 5) | 27,
        0xF9400366 | (((kind & 0xFFF) // 8) << 10),
        0xAA0F03E5,
        movz(12, 1),
        cmp(6, 4), movz(8, 2), 0x9A8C010C,
        cmp(6, 3),
    )
    bne_loop_at = len(sel)
    sel += b"BNEL"
    sel += pack(adr(cur(), cur() + 8, 15))
    b_eff_at = len(sel)
    sel += b"BEFF"
    sel += pack(_ldr_sp(9, secs_slot), cmp(9, LONG_TURN))
    bge_long_at = len(sel)
    sel += b"BGEL"
    sel += pack(0x91000D8C)
    b_loop_at = len(sel)
    sel += b"BLOP"
    is_long_va = cur()
    sel += pack(
        0x91003988,
        cmp(12, 0), movz(12, 9), 0x9A88018C,
    )
    loop_setup_va = cur()
    sel += encode_adrp_add(cur(), table_va, 10)
    sel += pack(_ldr_sp(1, width_slot), _ldr_sp(2, dur_len_slot))
    loop_va = cur()
    sel += pack(0x8B0C0D49)
    cbz_empty_at = len(sel)
    sel += b"CBZE"
    sel += pack(0x39401927, 0x8B0200E7, 0xEB070020)
    bgt_hit_at = len(sel)
    sel += b"BGTH"
    sel += pack(0x39401D2C)
    sel += encode_b(cur(), loop_va)
    empty_hit_va = cur()
    sel += pack(0xAA0103E0)
    hit_va = cur()
    sel += pack(0xB940012B, 0x79400922, 0x8B0B0141, 0xD61F00A0)

    eff_va = sel_va + len(sel)
    eff = effort(eff_va, match_va)
    if len(eff) != 4 * 24:
        raise RuntimeError(f"the effort matcher takes {len(eff)}B, not the 96B laid out")

    sel[bne_loop_at : bne_loop_at + 4] = encode_b_cond(sel_va + bne_loop_at, loop_setup_va, 0x1)
    sel[b_eff_at : b_eff_at + 4] = encode_b(sel_va + b_eff_at, eff_va)
    sel[bge_long_at : bge_long_at + 4] = encode_b_cond(sel_va + bge_long_at, is_long_va, 0xA)
    sel[b_loop_at : b_loop_at + 4] = encode_b(sel_va + b_loop_at, loop_setup_va)
    sel[cbz_empty_at : cbz_empty_at + 4] = pack(cbz_r(12, sel_va + cbz_empty_at, empty_hit_va))
    sel[bgt_hit_at : bgt_hit_at + 4] = encode_b_cond(sel_va + bgt_hit_at, hit_va, 0xC)

    matches = b""
    for suffix, _ in EFFORT_WORDS:
        raw = suffix.encode()
        if len(raw) > 8:
            raise RuntimeError(f"effort suffix {suffix} is longer than the 8 bytes the matcher compares")
        mask = ((1 << 64) - 1) ^ ((1 << (8 * (8 - len(raw)))) - 1)
        matches += struct.pack("<QQ", int.from_bytes(raw.rjust(8, b"\0"), "little") & mask, mask)
    matches += bytes(16)
    records = b"".join(
        struct.pack("<IHBB", fmt_pos[fmt_bytes] - table_va, len(fmt_bytes), base_cols, fb)
        for fmt_bytes, base_cols, fb in tiers
    )
    code = width_entry + fmt_entry + bytes(sel) + eff
    if len(code) > ELAPSED_CODE:
        raise RuntimeError(f"elapsedSuffix's detours take {len(code)}B, more than the {ELAPSED_CODE}B laid out")
    data_raw = matches + records + b"".join(unique_fmts)
    data_blob = data_raw.ljust((len(data_raw) + 3) & ~3, b"\0")
    if data_off + len(data_blob) > paint_end:
        raise RuntimeError(f"halloween.paint has {paint_end - data_off}B left; elapsedSuffix data needs {len(data_blob)}B")
    return {"width": width_va, "format": fmt_va, "code": code, "code_va": va, "data": data_blob, "data_off": data_off}


def _resolve_spinner_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #49a-#49l: breathing Gemini star, Gemini band over blue word, one space after frame, blank gap row."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    read = lambda va, n: bytes(data[va - VM_BASE : va - VM_BASE + n])
    slice_at = lambda va: struct.unpack_from("<QQQ", data, va - VM_BASE)
    sites: list[PatchSite] = []

    def site(name: str, off: int, original: bytes | None, patched: bytes) -> None:
        orig = None if original is None else _recoverable(data, off, patched, original)
        sites.append(PatchSite("palette-typography", name, VM_BASE + off, off, orig, patched))

    def stock_or_none(off: int, patched: bytes) -> bytes | None:
        current = bytes(data[off : off + len(patched)])
        return None if current == patched else current

    pv_name, pv = _pending_line_fn(funcs)

    # Halloween registration
    h0 = funcs["halloweenInit0"]
    reg = [
        o
        for o in range(h0[0], h0[1] - 16, 4)
        if _adrp_add_at(data, o, 0) is not None
        and _adrp_add_at(data, o + 8, 1) is not None
        and (branch_target(word(o + 16), o + 16) == funcs["themeRegister"][0] or bytes(data[o + 16 : o + 20]) == NOP)
    ]
    if len(reg) != 1:
        raise RuntimeError("halloween.init.0 no longer registers one theme value")
    theme_itab, theme_value, reg_call = _adrp_add_at(data, reg[0], 0), _adrp_add_at(data, reg[0] + 8, 1), reg[0] + 16

    rows = _halloween_logo_slices(data, funcs)
    table_va = rows[0][0]
    if len(SPINNER_BREATH) > rows[0][1] + rows[1][1]:
        raise RuntimeError("Halloween's logo tables hold fewer slots than the breath has frames")

    hr = funcs["halloweenRunningLight"]
    bands = [slice_at(va) for _, va in _slice_loads(data, hr)]
    if len(bands) != 2 or any(n != cap or n != len(GEMINI_BAND_DARK) for _, n, cap in bands):
        raise RuntimeError("halloween.RunningLight no longer returns two 5-color tables")
    (light_va, _, _), (dark_va, _, _) = bands

    # 49a. Read-only strings/tables in dead `halloween.paint`
    cave, blob, at = _gemini_fill(data, funcs)
    frames = [_breath_frame(*f) for f in SPINNER_BREATH]
    site(
        "halloween.paint -> the breathing star's frames, the Gemini band, the long-turn colors, the pending line's verbs, and the tool marks",
        cave,
        stock_or_none(cave, blob),
        blob,
    )

    # 49b. Halloween's logo rows -> 24 frames
    table = b"".join(struct.pack("<QQ", at[f], len(f)) for f in frames)
    site("halloween logo rows -> the breathing star's 24 frames", table_va - VM_BASE, read(table_va, len(table)), table)

    # 49c. Spinner frame slice
    ro_bounds = _section_file_bounds(data, "__TEXT", "__rodata")
    data_bounds = _section_file_bounds(data, "__DATA", "__data")
    stock_run = _find_all(data, SPINNER_STOCK, ro_bounds)
    if len(stock_run) != 1:
        raise RuntimeError(f"Expected one braille spinner run, found {len(stock_run)}")
    stock_arr = _find_all(data, b"".join(struct.pack("<QQ", VM_BASE + stock_run[0] + 4 * i, 4) for i in range(8)), data_bounds)
    if len(stock_arr) != 1:
        raise RuntimeError(f"Expected one braille frame table, found {len(stock_arr)}")
    stock_hdr = struct.pack("<QQQ", VM_BASE + stock_arr[0], 8, 8)
    our_hdr = struct.pack("<QQQ", table_va, len(frames), len(frames))
    hdrs = _find_all(data, stock_hdr, data_bounds) + _find_all(data, our_hdr, data_bounds)
    if len(hdrs) != 1:
        raise RuntimeError(f"Expected one spinner frame slice, found {len(hdrs)}")
    site("spinner frame slice -> 24 frames of the breathing star", hdrs[0], stock_hdr, our_hdr)

    # 49d. Unregister Halloween theme
    site(
        "halloween.init.0 -> Halloween is not registered (its logo rows hold the spinner frames)",
        reg_call,
        encode_bl(VM_BASE + reg_call, VM_BASE + funcs["themeRegister"][0]),
        NOP,
    )

    # 49e. Gemini band colors in Halloween's tables
    for va, band in ((dark_va, GEMINI_BAND_DARK), (light_va, GEMINI_BAND_LIGHT)):
        patched = b"".join(struct.pack("<QQ", at[c.encode()], len(c)) for c in band)
        bg = "dark" if band is GEMINI_BAND_DARK else "light"
        site(f"halloween running-light colors ({bg} background) -> the Gemini band", va - VM_BASE, read(va, len(patched)), patched)

    # 49f. renderPendingLight -> always theme path as Halloween
    rp = funcs["renderPendingLight"]
    calls = _calls_to(data, rp, funcs["themerenderRunningLight"][0])
    if len(calls) != 1 or word(calls[0] - 0x28) & 0xFF00001F != 0xB4000009:
        raise RuntimeError("renderPendingLight no longer tests its theme just before lighting with it")
    merge = calls[0] - 0x24

    def gate(o: int) -> bytes:
        return (
            encode_adrp_add(VM_BASE + o, theme_itab, 9)
            + encode_adrp_add(VM_BASE + o + 8, theme_value, 12)
            + encode_b(VM_BASE + o + 16, VM_BASE + merge)
        )

    gates = [
        o
        for o in range(rp[0], merge - 20, 4)
        if (word(o) & 0xFF00001F == 0xB4000009 and word(o + 4) & 0xFFC003FF == 0x3940012C)
        or bytes(data[o : o + 20]) == gate(o)
    ]
    if len(gates) != 1:
        raise RuntimeError(f"renderPendingLight: expected one theme-settings test, found {len(gates)}")
    site(
        "model.(*ConversationModel).renderPendingLight -> always light with the theme path, as Halloween",
        gates[0],
        stock_or_none(gates[0], gate(gates[0])),
        gate(gates[0]),
    )

    # 49g. renderPendingLight band step 80ms -> 100ms
    movz_simple = lambda rd, imm: 0xD2800000 | (imm << 5) | rd
    steps = [
        o + 4
        for o in range(rp[0], rp[1] - 4, 4)
        if word(o) == movz_simple(0, 40)
        and word(o + 4) in (movz_simple(4, PENDING_LIGHT_STEP[0]), movz_simple(4, PENDING_LIGHT_STEP[1]))
    ]
    if len(steps) != 2:
        raise RuntimeError(f"renderPendingLight: expected two medium-speed steps, found {len(steps)}")
    for o, speed in zip(steps, ("`medium`", "the default")):
        site(
            f"model.(*ConversationModel).renderPendingLight -> at {speed} speed the band moves a column per {PENDING_LIGHT_STEP[1]} ms",
            o,
            pack(movz_simple(4, PENDING_LIGHT_STEP[0])),
            pack(movz_simple(4, PENDING_LIGHT_STEP[1])),
        )

    # 49h. runningLightAt: base under the band walks 3 frames up to pendingLineView / pendingLineLayout
    hexes = {
        _adrp_add_at(data, o + 4, 0)
        for o in range(funcs["lipglossColor"][0], funcs["lipglossColor"][1] - 8, 4)
        if word(o) == 0xAA0003E1
    }
    hexes.discard(None)
    if len(hexes) != 1:
        raise RuntimeError("lipgloss.Color no longer boxes a hex as one color.Color type")
    rgba_itab = hexes.pop()
    la, tr = funcs["themeRunningLightAt"], funcs["themerenderRunningLight"]
    for callee, caller in ((la, tr), (tr, rp), (rp, pv)):
        if not _calls_to(data, caller, callee[0]):
            raise RuntimeError(f"{hex(VM_BASE + callee[0])} is no longer called from {hex(VM_BASE + caller[0])}")
    m_slot = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (pv[0], pv[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    ms_slot = next((sl[1] for _, w in _words(data, (la[0], la[0] + 0x40)) if (sl := _sp_slot(w, 0xF90003E0)) and sl[0] == 2), None)
    if m_slot is None or ms_slot is None:
        raise RuntimeError(f"{pv_name}'s m spill or runningLightAt's time spill moved")
    walk = _go_frame(data, la) + _go_frame(data, tr) + _go_frame(data, rp) + m_slot
    _, _, start = _turn_start(data, funcs["refreshActivityLabel"])
    if walk > 0x7FF8 or walk % 8 or start >> 24 or (start & 0xFFF) % 8:
        raise RuntimeError("runningLightAt: the model or its turn start is out of reach of one load")
    epoch = (1969 * 365 + 1969 // 4 - 1969 // 100 + 1969 // 400 - (1884 * 365 + 1884 // 4 - 1884 // 100 + 1884 // 400)) * 86400
    movz = lambda rd, imm, sh=0: 0xD2800000 | (sh // 16) << 21 | (imm << 5) | rd
    movk = lambda rd, imm, sh: 0xF2800000 | (sh // 16) << 21 | (imm << 5) | rd
    la_ldp = 0xA9400C02 | ((PALETTE_DIM // 8) << 15)
    light_va = VM_BASE + _light_detour_base(data)

    def light(back: int) -> bytes:
        code = pack(
            _ldr_sp(9, walk),
            0x91400000 | ((start >> 12) << 10) | (9 << 5) | 27,
            0xF9400369 | (((start & 0xFFF) // 8) << 10),
            0xB4000009 | (16 << 5),
            0xD35EF929,
            movz(10, epoch & 0xFFFF), movk(10, epoch >> 16, 16),
            0xCB0A0129,
            _ldr_sp(10, ms_slot), movz(11, 1000), 0x9ACB094A,
            0xCB090149,
            0xF1000129 | (LONG_TURN << 10),
            0x9A9FC129,
            movz(11, STAGE_SECONDS), 0x9ACB0929,
            movz(11, TURN_STAGES - 1), 0xEB0B013F, 0x9A8B3129,
        )
        assert len(code) == 4 * 19
        here = light_va + len(code)
        code += encode_adrp_add(here, at["rgba"], 3) + pack(0x8B090863)
        code += encode_adrp_add(here + 12, rgba_itab, 2)
        return code + encode_b(here + 20, back)

    def base_load(o: int, n_nops: int) -> bytes:
        return encode_b(VM_BASE + o, light_va) + NOP * n_nops

    dims_v14 = [
        o
        for o in range(la[0], la[1] - 0x10, 4)
        if word(o + 8) == 0xB4000042
        and word(o + 12) == 0xF9400442
        and (
            (word(o) & 0xFFC003FF == 0x910003FB and word(o + 4) == 0xA9400F62)
            or (word(o) >> 26 == 0x05 and bytes(data[o + 4 : o + 8]) == NOP)
        )
    ]
    dims_v13 = [
        o - 0x1C
        for o in range(la[0] + 0x1C, la[1] - 4, 4)
        if (word(o) == la_ldp and word(o - 4) >> 26 == 0x25 and word(o - 0x1C) & 0x9F00001F == 0x9000001B)
        or (word(o - 0x1C) >> 26 == 0x05 and bytes(data[o - 0x18 : o + 4]) == NOP * 7)
    ]
    if len(dims_v14) == 1 and not dims_v13:
        dim_off, dim_len, dim_nops = dims_v14[0], 8, 1
    elif len(dims_v13) == 1 and not dims_v14:
        dim_off, dim_len, dim_nops = dims_v13[0], 0x20, 7
    else:
        raise RuntimeError(f"themerender.runningLightAt: expected one DimFg base load, found v14={len(dims_v14)} v13={len(dims_v13)}")
    detour = light(VM_BASE + dim_off + dim_len)
    if len(detour) > LIGHT_LEAF_ROOM:
        raise RuntimeError(f"the stage-color leaf takes {len(detour)}B; it has {LIGHT_LEAF_ROOM}B before Site #50i")
    dim_patched = base_load(dim_off, dim_nops)
    site(
        "themerender.runningLightAt -> the band's base is the turn's stage color, not palette[+0x130]",
        dim_off,
        stock_or_none(dim_off, dim_patched),
        dim_patched,
    )
    site(
        "__TEXT fill -> runningLightAt's leaf: seconds into the turn -> a color from blue through purple to rose",
        light_va - VM_BASE,
        bytes(len(detour)),
        detour,
    )

    # 49i. One space between the star and the word.
    cats: list[int] = []
    for c in _calls_to(data, pv, funcs["concatstring2"][0]):
        if (
            word(c - 24) == 0xAA0103E2
            and (va := _adrp_add_at(data, c - 20, 3)) is not None
            and data[va - VM_BASE] == 0x20
            and word(c - 12) in (0xB24003E4, 0xAA1F03E4)
            and bytes(data[c - 8 : c]) == bytes.fromhex("e10300aae0031faa")
        ):
            cats.append(c - 12)
        elif (
            (va := _adrp_add_at(data, c - 12, 3)) is not None
            and data[va - VM_BASE] == 0x20
            and word(c - 4) in (0xB24003E4, 0xAA1F03E4)
            and word(c - 24) == 0xAA1F03E0
        ):
            cats.append(c - 4)
    if len(cats) != 1:
        raise RuntimeError(f"{pv_name}: expected one `frame + \" \"`, found {len(cats)}")
    o = cats[0]
    site(
        f"model.(*ConversationModel).{pv_name} -> the frame keeps its one space; no second",
        o,
        stock_or_none(o, pack(0xAA1F03E4)),
        pack(0xAA1F03E4),
    )

    # 49j. populateLayout reserves the pending row twice (gap + line).
    pl = funcs["populateLayout"]
    deco = funcs["pendingDecoration"][0]
    deco_rows = [c for c in _calls_to(data, pl, deco)]
    adds: list[tuple[int, int]] = []
    for c in deco_rows:
        for o in range(c + 4, min(pl[1] - 20, c + 0xC0), 4):
            w0 = word(o)
            if w0 & 0xFFFFFC1F != 0xF100001F:
                continue
            r = (w0 >> 5) & 0x1F
            if word(o + 4) != (0x9A9F17E0 | r):
                continue
            for delta in (8, 12, 16):
                wa = word(o + delta)
                if wa & 0xFFE0FC00 == 0x8B000000:
                    rd, rn, rm = wa & 0x1F, (wa >> 5) & 0x1F, (wa >> 16) & 0x1F
                    if r in (rn, rm) and rn != rm and rd in (rn, rm):
                        other = rm if rn == r else rn
                        adds.append((o + delta, 0x8B000400 | (r << 16) | (other << 5) | rd))
                        break
                elif wa & 0xFFE0FC00 == 0x8B000400 and ((wa >> 16) & 0x1F) == r:
                    adds.append((o + delta, wa))
                    break
    if len(deco_rows) != 1 or len(adds) != 1:
        raise RuntimeError(f"populateLayout: expected one pending-row reservation, found {len(adds)}")
    add_off, add_patched = adds[0]
    site(
        "model.(*ConversationModel).populateLayout -> the pending row is reserved twice: the gap, then the line",
        add_off,
        stock_or_none(add_off, pack(add_patched)),
        pack(add_patched),
    )

    # 49k. Tail decoration join + gap leaf.
    # - v1.5.18 (`pendingLineView`): `bl pendingDecoration; cbnz x1, join(c+0x14); ldr x1,[sp,#len]; ldr x0,[sp,#ptr]; b out`.
    # - v1.5.19 (`pendingLineLayout`): returns `(line, ok, rowOffset, startCol, endCol)`.
    #   `bl pendingDecoration; cbnz x1, join(c+0x1c); ldrb w2,[sp,#ok]; ldr x1,[sp,#len]; ldr x0,[sp,#ptr]; mov x3,xzr; b after_deco`.
    #   `join` starts with `str x2, [sp, #rows_slot]` (saving `deco_rows`), calls `concatstring3` at `join+0x24`,
    #   and computes `rowOffset = ok ? [sp, #rows_slot] : 0`. Our gap leaf stores `(deco_len != 0 ? deco_rows : 0) + 1`
    #   into `[sp, #rows_slot]` so `frameScrollIndicatorSpan` and `scrollIndicatorAt` hit-test the exact row shifted by our blank row.
    tails = [c for c in _calls_to(data, pv, deco)]
    if len(tails) != 1:
        raise RuntimeError(f"{pv_name}: expected one pendingDecoration call, found {len(tails)}")
    c = tails[0]
    if word(c + 4) & 0xFF00001F != 0xB5000001:  # cbnz x1, join
        raise RuntimeError(f"{pv_name}: expected `cbnz x1, join` right after pendingDecoration")
    join = branch_target(word(c + 4), c + 4)
    nn_pos = data.find(b"\n\n", ro_bounds[0], ro_bounds[1])
    if nn_pos == -1 or nn_pos >= _text_tail_cave(data)[0]:
        raise RuntimeError("no blank line in __TEXT's data to open the pending block with")
    nn = nn_pos
    leaf = _gap_leaf_base(data)
    cbnz = lambda pc, target, rt: struct.pack("<I", 0xB5000000 | (((target - pc) // 4) & 0x7FFFF) << 5 | rt)

    if join == c + 0x1C:
        # v1.5.19+ pendingLineLayout (scroll-indicator span)
        call3 = join + 0x24
        p_sl, l_sl = _sp_slot(word(join + 0x14), 0xF94003E0), _sp_slot(word(join + 0x18), 0xF94003E0)
        if p_sl is None or p_sl[0] != 5 or l_sl is None or l_sl[0] != 6:
            raise RuntimeError(f"{pv_name} no longer loads its spilled line in the decoration join")
        ptr_slot, len_slot = p_sl[1], l_sl[1]
        ok_ldrb = word(call3 + 4)
        rows_sl = _sp_slot(word(call3 + 12), 0xF94003E0)
        if (
            branch_target(word(call3), call3) != funcs["concatstring3"][0]
            or word(c + 0x18) >> 26 != 0x05
            or word(join + 4) != 0xAA0103E2
            or (ok_ldrb & 0xFFC003FF) != 0x394003E2  # ldrb w2, [sp, #ok_slot]
            or rows_sl is None
            or rows_sl[0] != 7  # ldr x7, [sp, #rows_slot]
        ):
            raise RuntimeError(f"{pv_name}'s tail no longer matches the decoration + scroll-span layout")
        rows_slot = rows_sl[1]
        if word(join) != _str_sp(2, rows_slot) and word(join) >> 26 != 0x05:
            raise RuntimeError(f"{pv_name}'s join no longer opens with `str x2, [sp, #rows_slot]`")
        code = (
            pack(
                0xF100003F,              # cmp x1, #0                (deco.len != 0?)
                0x9A9F1047,              # csel x7, x2, xzr, ne      (x7 = deco.len != 0 ? deco.rows : 0)
                0x910004E7,              # add x7, x7, #1            (rowOffset = deco.rows + 1)
                _str_sp(7, rows_slot),   # str x7, [sp, #rows_slot]
                0xAA0103E2,              # mov x2, x1                (deco.len)
                0xAA0003E1,              # mov x1, x0                (deco.ptr)
            )
            + encode_adrp_add(VM_BASE + leaf + 24, VM_BASE + nn, 3)  # x3 = "\n\n"
            + pack(
                0xB24003E4,              # orr x4, xzr, #1           (sep.len = 1)
                _ldr_sp(5, ptr_slot),    # ldr x5, [sp, #ptr_slot]
                _ldr_sp(6, len_slot),    # ldr x6, [sp, #len_slot]
                0xF100005F,              # cmp x2, #0
                0xFA4018C4,              # ccmp x6, #0, #4, ne
                0x9A840484,              # cinc x4, x4, ne           (sep.len = 2 when both non-empty)
                0xAA1F03E0,              # mov x0, xzr
            )
            + encode_b(VM_BASE + leaf + 60, VM_BASE + call3)
        )
        # Preserve x0, x1, x2 (= 0) while checking line.len in x7; empty-both keeps (x0, x1="") and loads ok/rowOffset=0.
        tail = pack(_ldr_sp(7, len_slot)) + cbnz(c + 12, join, 7) + pack(ok_ldrb, 0xAA1F03E3)
    elif join == c + 0x14:
        # <=v1.5.18 pendingLineView
        call3 = join + 0x20
        p_sl, l_sl = _sp_slot(word(join + 0x10), 0xF94003E0), _sp_slot(word(join + 0x14), 0xF94003E0)
        if p_sl is None or p_sl[0] != 5 or l_sl is None or l_sl[0] != 6:
            raise RuntimeError(f"{pv_name} no longer loads its spilled line in the decoration join")
        ptr_slot, len_slot = p_sl[1], l_sl[1]
        if (
            branch_target(word(call3), call3) != funcs["concatstring3"][0]
            or word(c + 16) >> 26 != 0x05
            or (word(join) != 0xAA0103E2 and word(join) >> 26 != 0x05)
        ):
            raise RuntimeError(f"{pv_name}'s tail no longer joins decoration, newline and line")
        code = (
            pack(0xAA0103E2, 0xAA0003E1)
            + encode_adrp_add(VM_BASE + leaf + 8, VM_BASE + nn, 3)
            + pack(
                0xB24003E4,
                _ldr_sp(5, ptr_slot),
                _ldr_sp(6, len_slot),
                0xF100005F,
                0xFA4018C4,
                0x9A840484,
                0xAA1F03E0,
            )
            + encode_b(VM_BASE + leaf + 44, VM_BASE + call3)
        )
        tail = pack(_ldr_sp(2, len_slot)) + cbnz(c + 12, join, 2)
    else:
        raise RuntimeError(f"{pv_name}: unexpected decoration join distance {join - c:#x}")

    if len(code) > GAP_LEAF_ROOM:
        raise RuntimeError(f"the pending gap's leaf takes {len(code)}B; it has {GAP_LEAF_ROOM}B")
    site(
        f"__TEXT fill -> {pv_name}'s leaf: a blank row above the line, under any decoration",
        leaf,
        bytes(len(code)),
        code,
    )
    site(
        f"model.(*ConversationModel).{pv_name} -> a non-empty line takes the decoration's join too",
        c + 8,
        stock_or_none(c + 8, tail),
        tail,
    )
    jump = encode_b(VM_BASE + join, VM_BASE + leaf)
    site(
        f"model.(*ConversationModel).{pv_name} -> the join sets up in the gap's leaf",
        join,
        stock_or_none(join, jump),
        jump,
    )

    # 49l. RunningLightWindow swings short text back and forth too.
    rlw = funcs["runningLightWindow"]
    gate_rlw = [
        o
        for o, w in _words(data, (rlw[0], rlw[0] + 0x40))
        if w == 0xF100641F and word(o + 4) & 0xFF00001F == 0x5400000A
    ]
    if len(gate_rlw) != 1:
        raise RuntimeError("RunningLightWindow no longer tests for 25 columns")
    short, tail_rlw = gate_rlw[0] + 8, branch_target(word(gate_rlw[0] + 4), gate_rlw[0] + 4) + 0x28
    swing_stock = (
        0xB4000182, 0x9AC20C23, 0xB4000506, 0x9AC60C7B, 0x9B068F63,
        0xCB040063, 0xD1000C60, 0xAA0403E1, 0xB24003E2, 0xF85F83FD,
    )
    swing = (
        pack(
            word(short), 0x9AC20C23,
            0x8B0600C5, 0xD10008A5,
            0x9AC50C7B, 0x9B058F63,
            0xCB0300A5, 0xEB06007F, 0x9A85B063,
        )
        + encode_b(VM_BASE + short + 36, VM_BASE + tail_rlw)
    )
    if word(tail_rlw) != 0xCB040063 or tuple(struct.unpack_from("<10I", data, short)) not in (
        swing_stock,
        struct.unpack("<10I", swing),
    ):
        raise RuntimeError("RunningLightWindow's branches no longer have the shape the swing rewrites")
    site(
        "render.RunningLightWindow -> short text swings back and forth too, at its own step",
        short,
        stock_or_none(short, swing),
        swing,
    )
    return tuple(sites)


def _resolve_elapsed_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #50a-#50j: single ellipsis, turn-wide timer, progressive elapsed aside, and phase-timer suppression."""
    pv_name, pv = _pending_line_fn(funcs)
    rf, ac, cl = (funcs[k] for k in ("refreshActivityLabel", "activityCandidate", "compactingLabel"))
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    sites: list[PatchSite] = []

    def site(name: str, off: int, patched: bytes) -> None:
        sites.append(PatchSite("pending-line", name, VM_BASE + off, off, _recoverable(data, off, patched), patched))

    # 50a. `...` -> `…` in pendingLineView / pendingLineLayout (+ fitPendingLabel on v1.5.16+)
    ell = ELLIPSIS.encode()
    ro_lo, ro_hi = _section_file_bounds(data, "__TEXT", "__rodata")
    ell_pos = data.find(ell, ro_lo, ro_hi)
    if ell_pos == -1 or ell_pos >= _text_tail_cave(data)[0]:
        raise RuntimeError("no `…` in __TEXT to point the pending line's ellipsis at")
    ell_va = VM_BASE + ell_pos
    find_dots = lambda bounds: [
        o
        for o, w in _words(data, (bounds[0], bounds[1] - 12))
        if w & 0x9F00001F == 0x90000003
        and (va := _adrp_add_at(data, o, 3)) is not None
        and bytes(data[va - VM_BASE : va - VM_BASE + 3]) in (b"...", ell)
        and word(o + 8) == 0xB24007E4
    ]
    dots = find_dots(pv)
    if len(dots) not in (1, 2):
        raise RuntimeError(f"{pv_name}: expected 1 or 2 `text + \"...\"`, found {len(dots)}")
    site(f"model.(*ConversationModel).{pv_name} -> `…` after the text, not `...`", dots[0], encode_adrp_add(VM_BASE + dots[0], ell_va, 3))
    if "fitPendingLabel" in funcs:
        fpl = funcs["fitPendingLabel"]
        fpl_dots = find_dots(fpl)
        if not fpl_dots or word(fpl_dots[0] - 8) & 0xFF00001F != 0xB5000004:
            raise RuntimeError(f"fitPendingLabel: expected `text + \"...\"` after `cbnz x4`, found {len(fpl_dots)}")
        site("model.fitPendingLabel -> `…` after the text, not `...`", fpl_dots[0], encode_adrp_add(VM_BASE + fpl_dots[0], ell_va, 3))

    # 50j (v1.5.16+). Suppress upstream per-phase `activityPhaseTimer` shimmer suffix.
    if "activityPhaseTimerElapsed" in funcs:
        el_calls = _calls_to(data, pv, funcs["activityPhaseTimerElapsed"][0])
        if len(el_calls) != 1:
            raise RuntimeError(f"{pv_name}: expected one activityPhaseTimer.elapsed call, found {len(el_calls)}")
        el_c = el_calls[0]
        skips = [
            o
            for o in range(max(pv[0], el_c - 0x60), el_c - 12, 4)
            if (word(o) & 0xFFF80000 == 0x36000000 or bytes(data[o : o + 4]) == NOP)
            and word(o + 4) == 0xAA1F03E1
            and word(o + 8) == 0xAA1F03E0
            and word(o + 12) >> 26 == 0x05
        ]
        if len(skips) != 1:
            raise RuntimeError(f"{pv_name}: expected one activityPhaseTimer gate before elapsed, found {len(skips)}")
        site(f"model.(*ConversationModel).{pv_name} -> suppress upstream phase timer (keep turn-wide aside)", skips[0], NOP)

    # 50b. refreshActivityLabel: stamp start for every busy state
    stamp, stamp_va, start_field = _turn_start(data, rf)
    site(
        "model.(*ConversationModel).refreshActivityLabel -> stamp the start for every busy state",
        stamp,
        pack(0xF100007F) + encode_b_ne(VM_BASE + stamp + 4, stamp_va),
    )

    # 50c. activityCandidate: Compacting takes plain label
    seven_eq = [
        o + 4
        for o, w in _words(data, (ac[0], ac[1] - 12))
        if w == 0xF1001C1F
        and (word(o + 4) & 0xFF00001F == 0x54000000 or bytes(data[o + 4 : o + 8]) == NOP)
        and word(o + 12) >> 26 == 0x05
    ]
    seven_ne = [
        o + 4
        for o, w in _words(data, (ac[0], ac[1] - 4))
        if w == 0xF1001C1F and (word(o + 4) & 0xFF00001F == 0x54000001 or word(o + 4) >> 26 == 0x05)
    ]
    if len(seven_eq) == 1 and not seven_ne:
        site("model.(*ConversationModel).activityCandidate -> Compacting shows its plain label", seven_eq[0], NOP)
    elif len(seven_ne) == 1 and not seven_eq:
        br = seven_ne[0]
        site(
            "model.(*ConversationModel).activityCandidate -> Compacting shows its plain label",
            br,
            encode_b(VM_BASE + br, VM_BASE + branch_target(word(br), br)),
        )
    else:
        raise RuntimeError(f"activityCandidate: expected one Compacting test, found eq={len(seven_eq)} ne={len(seven_ne)}")

    # 50d + 50i. Rebuild compactingLabel -> elapsedSuffix(m, pad)
    fmt_calls = _calls_to(data, cl, funcs["fmtDuration"][0])
    if len(fmt_calls) != 1:
        raise RuntimeError("compactingLabel no longer calls fmtDuration once")
    f = fmt_calls[0]
    entry, sub, secs, lab, conv, fmt_load = cl[0] + 0x1C, f - 0x6C, f - 0x24, f - 0x18, f + 0x20, f + 0x48
    head_len = 4 * 11
    fmt_off = entry + head_len
    patched_cl = bytes(data[fmt_off : fmt_off + len(ELAPSED_FORMAT)]) == ELAPSED_FORMAT
    slot = lambda off: _sp_slot(word(off), 0xF90003E0)
    if patched_cl:
        a_slot, b_slot, l_slot, p_slot = slot(entry + 0x14), slot(entry + 0x18), slot(entry), slot(lab + 4)
        shape_ok = b_slot is not None and b_slot[0] == 31 and p_slot is not None and p_slot[0] == 31
    else:
        a_slot, b_slot, p_slot, l_slot = slot(entry), slot(entry + 4), slot(lab + 4), slot(lab + 8)
        shape_ok = (
            a_slot is not None and a_slot[0] == 2
            and b_slot is not None and b_slot[0] == 5
            and p_slot is not None and p_slot[0] == 0
            and l_slot is not None and l_slot[0] == 1
            and word(lab - 8) == 0xB2400BE0 and word(lab - 4) == 0xAA1F03E1
            and branch_target(word(lab), lab) == funcs["agentStateLabel"][0]
            and branch_target(word(sub), sub) == funcs["timeSub"][0]
            and slot(secs) is not None and slot(secs)[0] == 6
            and word(conv - 8) == _ldr_sp(0, p_slot[1]) and word(conv - 4) == _ldr_sp(1, l_slot[1])
            and branch_target(word(conv), conv) == funcs["convTstring"][0]
            and word(fmt_load + 8) & 0xFFE0001F == 0xD2800001
        )
    if not shape_ok or a_slot is None or l_slot is None:
        raise RuntimeError("compactingLabel: unexpected shape around its fmtDuration call")
    dur_len = _sp_slot(word(f + 8), 0xF90003E0)
    if _sp_slot(word(f + 4), 0xF90003E0) is None or dur_len is None or dur_len[0] != 1:
        raise RuntimeError("compactingLabel: fmtDuration's result is no longer spilled right after the call")
    dur_len = dur_len[1]
    ints = {decode_adrp_add(data, o + 4) for o in _calls_to(data, funcs["fmtDuration"], funcs["convT64"][0])}
    if len(ints) != 1:
        raise RuntimeError("fmtDuration: expected one boxed integer type")
    if start_field >> 24 or (start_field & 0xFFF) + 0x10 > 0x7FF8:
        raise RuntimeError(f"start field {start_field:#x} is out of reach of one `add` and `ldr`")
    hi, lo = start_field >> 12, start_field & 0xFFF
    ld = lambda rt, off: 0xF9400360 | (((lo + off) // 8) << 10) | rt
    cbnz_sub = lambda rt, at: 0xB5000000 | ((((sub - at) // 4) & 0x7FFFF) << 5) | rt
    head = (
        pack(
            _str_sp(1, l_slot[1]),
            0x9140001B | (hi << 10),
            ld(2, 0x10), ld(1, 0x8), ld(0, 0),
            _str_sp(2, a_slot[1]), _str_sp(31, b_slot[1]),
            cbnz_sub(0, entry + 28), cbnz_sub(1, entry + 32),
            MOV_X6_XZR,
        )
        + encode_b(VM_BASE + entry + 40, VM_BASE + secs)
    )
    if sub - fmt_off < len(ELAPSED_FORMAT):
        raise RuntimeError("compactingLabel: no room for the format before Time.Sub")
    body = bytearray(data[entry : fmt_load + 12])

    def put(off: int, blob: bytes) -> None:
        body[off - entry : off - entry + len(blob)] = blob

    put(entry, head + ELAPSED_FORMAT.ljust(sub - fmt_off, b"\x00"))
    put(sub, encode_bl(VM_BASE + sub, VM_BASE + funcs["timeSince"][0]))
    put(lab - 8, pack(0xD503201F, 0xD503201F, 0xD503201F, _str_sp(31, p_slot[1]), 0xD503201F))
    detours = _elapsed_detours(data, funcs, fmt_off, l_slot[1], dur_len, slot(secs)[1], conv, fmt_load)
    put(
        conv - 8,
        encode_b(VM_BASE + conv - 8, detours["width"])
        + NOP
        + encode_bl(VM_BASE + conv, VM_BASE + funcs["convT64"][0])
        + encode_adrp_add(VM_BASE + conv + 4, next(iter(ints)), 6),
    )
    put(fmt_load, encode_b(VM_BASE + fmt_load, detours["format"]) + NOP + NOP)
    if not patched_cl:
        assert_unreachable(data, cl, (entry + 8, sub), "compactingLabel's zero-start branch and moves")
    sites.append(
        PatchSite(
            "pending-line",
            "model.compactingLabel -> elapsedSuffix(m, pad): ` (8s ⋅ thinking)`, faint, of the time since the start",
            VM_BASE + entry,
            entry,
            None if patched_cl else bytes(data[entry : fmt_load + 12]),
            bytes(body),
        )
    )
    code_off = detours["code_va"] - VM_BASE
    sites.append(
        PatchSite(
            "pending-line",
            "__TEXT fill -> elapsedSuffix's two detours and effort matcher",
            detours["code_va"],
            code_off,
            bytes(len(detours["code"])),
            detours["code"],
        )
    )
    data_off, data_blob = detours["data_off"], detours["data"]
    sites.append(
        PatchSite(
            "pending-line",
            "halloween.paint -> elapsedSuffix's effort tables and state formats",
            VM_BASE + data_off,
            data_off,
            _recoverable(data, data_off, data_blob),
            data_blob,
        )
    )

    # 50e-50g. pendingLineView / pendingLineLayout: always run right-hand layout, reserve budgets, call elapsedSuffix.
    m_slot = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (pv[0], pv[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    if m_slot is None:
        raise RuntimeError(f"{pv_name}: the receiver spill is gone")
    reserve = [
        o
        for o, w in _words(data, pv)
        if w & 0xFFC00000 == 0xD1000000
        and ((w >> 5) & 0x1F) != 31
        and ((w >> 10) & 0xFFF) in (3, STATUS_RESERVE, LABEL_RESERVE, 50)
    ]
    if len(reserve) != 2:
        raise RuntimeError(f"{pv_name}: expected 2 `width - 3` truncation budgets, found {len(reserve)}")
    trunc_reserve = reserve[-1]
    gate = [
        o
        for o in range(trunc_reserve - 0x40, trunc_reserve, 4)
        if word(o) & 0xFF00001F == 0xB4000001 or bytes(data[o : o + 4]) == NOP
    ]
    if len(gate) != 1:
        raise RuntimeError(f"{pv_name}: the right-hand status test is gone")
    repeats = [o for o in _calls_to(data, pv, funcs["stringsRepeat"][0]) if o > trunc_reserve]
    repeats += [o for o in _calls_to(data, pv, cl[0]) if o > trunc_reserve]
    if len(repeats) != 1:
        raise RuntimeError(f"{pv_name}: expected one padding `strings.Repeat` after the truncation")
    rp = repeats[0]
    fit_name = "statusSlot.fitWithScroll" if pv_name == "pendingLineLayout" else "statusSlot.fit"

    site(f"model.(*ConversationModel).{pv_name} -> lay out text, suffix, status even with no status", gate[0], NOP)
    site(
        f"model.(*ConversationModel).{pv_name} -> {fit_name} gives {STATUS_RESERVE} columns to the suffix",
        reserve[0],
        pack((word(reserve[0]) & 0xFFC003FF) | (STATUS_RESERVE << 10)),
    )
    site(
        f"model.(*ConversationModel).{pv_name} -> the text gives {LABEL_RESERVE} columns to the bare timer",
        trunc_reserve,
        pack((word(trunc_reserve) & 0xFFC003FF) | (LABEL_RESERVE << 10)),
    )

    # 50g:
    # - v1.5.18 (`pendingLineView`): `cmp xR, #0` at `rp - 20`, followed by `csel; adrp; add; orr; bl Repeat` (20B @ rp - 16).
    # - v1.5.19 (`pendingLineLayout`): `cmp xR, #0` at `rp - 24`, `csel` at `rp - 20`, `str xR, [sp, #pad_slot]` at `rp - 16`
    #   (spills clamped `pad` for `startCol = leftWidth + pad` after concatstring5), then `adrp; add; orr; bl Repeat`.
    #   Patch 24B @ rp - 20: clamp into x1, spill x1 to [sp, #pad_slot], load m, zero pointer args x2/x5 (§5.5), call elapsedSuffix.
    if word(rp - 24) & 0xFFFFFC1F == 0xF100001F:
        pad_rn = (word(rp - 24) >> 5) & 0x1F
        pad_spill = _sp_slot(word(rp - 16), 0xF90003E0)
        if pad_spill is None or pad_spill[0] not in (pad_rn, 1):
            raise RuntimeError(f"{pv_name}: expected pad spill at rp-16 before strings.Repeat")
        pad_slot = pad_spill[1]
        site(
            f"model.(*ConversationModel).{pv_name} -> padding comes from elapsedSuffix(m, pad)",
            rp - 20,
            pack(
                0x9A9FA001 | (pad_rn << 5),   # csel x1, xPad, xzr, ge
                _str_sp(1, pad_slot),         # str  x1, [sp, #pad_slot] (preserves scroll startCol)
                _ldr_sp(0, m_slot),           # ldr  x0, [sp, #m_slot]
                0xAA1F03E2,                   # mov  x2, xzr (*time.Location = nil)
                0xAA1F03E5,                   # mov  x5, xzr (*time.Location = nil)
            )
            + encode_bl(VM_BASE + rp, VM_BASE + cl[0]),
        )
    elif word(rp - 20) & 0xFFFFFC1F == 0xF100001F:
        pad_rn = (word(rp - 20) >> 5) & 0x1F
        site(
            f"model.(*ConversationModel).{pv_name} -> padding comes from elapsedSuffix(m, pad)",
            rp - 16,
            pack(0x9A9FA001 | (pad_rn << 5), _ldr_sp(0, m_slot), 0xAA1F03E2, 0xAA1F03E5)
            + encode_bl(VM_BASE + rp, VM_BASE + cl[0]),
        )
    else:
        raise RuntimeError(f"{pv_name}: expected `cmp xPad, #0` at rp-20 or rp-24 before strings.Repeat")
    return tuple(sites)


def _resolve_verb_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #56a-#56b: a verb per turn on the pending line for generating, thinking and running a tool."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    ac = funcs["activityCandidate"]
    _, _, start_field = _turn_start(data, funcs["refreshActivityLabel"])
    _, _, at = _gemini_fill(data, funcs)

    four = [
        o
        for o, w in _words(data, (ac[0], ac[1] - 12))
        if (w == 0xF100101F or (w >> 26 == 0x05 and branch_target(w, o) in (o + 16, o + 24)))
        and word(o + 8) == 0xF1001C1F
    ]
    if len(four) != 1:
        raise RuntimeError(f"activityCandidate: expected one Running test before the Compacting one, found {len(four)}")
    o4 = four[0]
    m_spill = next((((w >> 15) & 0x7F) * 8 for _, w in _words(data, (ac[0], ac[0] + 0x30)) if w & 0xFFC07FFF == 0xA90007E0), None)
    v14_layout = (word(o4 + 12) & 0xFF00001F == 0x54000000 or bytes(data[o4 + 12 : o4 + 16]) == NOP) and word(o4 + 20) >> 26 == 0x05
    if v14_layout:
        cave = o4 + 24
        label_entry = o4 + 16
        label = branch_target(word(o4 + 20), o4 + 20)
    else:
        cave = o4 + 16
        label_entry = branch_target(word(o4 + 12), o4 + 12)
        label = label_entry
    if m_spill is None or label is None:
        raise RuntimeError("activityCandidate: the receiver spill or the label branch moved")
    derive = branch_target(word(o4 + 4), o4 + 4)
    patched = bytes(data[o4 : o4 + 4]) == encode_b(VM_BASE + o4, VM_BASE + cave)
    if patched:
        derive = None
    elif derive is None or word(o4 + 4) & 0xFF00001F != 0x54000000:
        raise RuntimeError("activityCandidate: the Running test no longer branches on equal")
    lab_calls = _calls_to(data, (label, min(label + 0x20, ac[1])), funcs["agentStateLabel"][0])
    if len(lab_calls) != 1:
        raise RuntimeError("activityCandidate: expected one AgentState.Label call on the label path")
    epilogue = [word(lab_calls[0] + 4 + 4 * i) for i in range(3)]
    if epilogue[2] != 0xD65F03C0 or epilogue[0] != 0xF85F83FD:
        raise RuntimeError("activityCandidate: the label path no longer returns right after the call")
    if start_field >> 24 or (start_field & 0xFFF) > 0xFFF:
        raise RuntimeError(f"turn start {start_field:#x} is out of reach of two `add`s")
    n = len(PENDING_VERBS)
    body = (
        pack(0xD1000801, 0xF100083F)
        + encode_b_cond(VM_BASE + cave + 8, VM_BASE + label_entry, 0x8)
        + pack(
            _ldr_sp(2, m_spill),
            0x91000000 | ((start_field & 0xFFF) << 10) | (2 << 5) | 27,
            0x91400000 | ((start_field >> 12) << 10) | (27 << 5) | 27,
            0xF9400363,
            0x92407463,
            0xD2800004 | (1000 << 5), 0x9AC40863,
            0xD2800004 | (n << 5),
            0x9AC40865, 0x9B048CA3,
        )
        + encode_adrp_add(VM_BASE + cave + 0x34, at["verbs"], 0)
        + pack(0x8B031000, 0x38401401, *epilogue)
    )
    end = cave + len(body)
    if not patched:
        if end > derive:
            raise RuntimeError(f"activityCandidate: the dead Compacting branch holds {derive - cave}B, the verb needs {len(body)}B")
        assert_unreachable(
            data, ac, (cave, derive), "activityCandidate's Compacting branch",
            ignore=(o4 + 12,) if v14_layout else (),
        )
    return (
        PatchSite(
            "pending-line",
            "model.(*ConversationModel).activityCandidate -> past Thinking, go pick the verb",
            VM_BASE + o4,
            o4,
            bytes(data[o4 : o4 + 4]) if not patched else None,
            encode_b(VM_BASE + o4, VM_BASE + cave),
        ),
        PatchSite(
            "pending-line",
            f"model.(*ConversationModel).activityCandidate -> generating, thinking, running: one of {n} verbs per turn",
            VM_BASE + cave,
            cave,
            bytes(data[cave:end]) if not patched else None,
            body,
        ),
    )


def _resolve_tool_mark_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #57: `⋆` for `●` and `⊹` for `○` in transcript/step status marks, plus `✦` for Swarm's status row."""
    _, _, at = _gemini_fill(data, funcs)
    text_end = _text_tail_cave(data)[0]
    all_symbols = all_known_symbols()
    star = {}
    solid_va = None
    for circle, mark in TOOL_MARKS.items():
        loads = set()
        lo, hi = funcs["markRunningDot"]
        for o in range(lo, hi - 8, 4):
            va = _adrp_add_at(data, o, struct.unpack_from("<I", data, o)[0] & 0x1F)
            if va is not None and (
                va == at[mark.encode()]
                or (0 <= va - VM_BASE < text_end and bytes(data[va - VM_BASE : va - VM_BASE + 3]) == circle.encode())
                or (0 <= va - VM_BASE <= len(data) - 3 and bytes(data[va - VM_BASE : va - VM_BASE + 3]) == mark.encode())
            ):
                loads.add(va)
        if len(loads) != 1:
            raise RuntimeError(f"render.RunningDot no longer loads one `{circle}`")
        circle_va = loads.pop()
        if circle == "●":
            solid_va = circle_va
        star[circle_va] = at[mark.encode()]
    star.update({v: v for v in list(star.values())})
    sites = []
    for name in TOOL_MARK_FUNCS:
        if name not in funcs:
            continue
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
            sites.append(
                PatchSite(
                    "tool-marks",
                    f"{all_symbols[name].rsplit('/', 1)[1]} @+{o - lo:#x} -> `{glyph}`",
                    VM_BASE + o,
                    o,
                    _recoverable(data, o, patched),
                    patched,
                )
            )
            found += 1
        if not found:
            raise RuntimeError(f"{all_symbols[name]} no longer loads a status circle")
    if "markSwarmRow" in funcs:
        lo, hi = funcs["markSwarmRow"]
        swarm_va = at[SWARM_MARK.encode()]
        found = 0
        for o in range(lo, hi - 8, 4):
            rd = struct.unpack_from("<I", data, o)[0] & 0x1F
            va = _adrp_add_at(data, o, rd)
            if va not in (solid_va, swarm_va):
                continue
            patched = encode_adrp_add(VM_BASE + o, swarm_va, rd)
            sites.append(
                PatchSite(
                    "tool-marks",
                    f"{all_symbols['markSwarmRow'].rsplit('/', 1)[1]} @+{o - lo:#x} -> `{SWARM_MARK}`",
                    VM_BASE + o,
                    o,
                    _recoverable(data, o, patched),
                    patched,
                )
            )
            found += 1
        if not found:
            raise RuntimeError(f"{all_symbols['markSwarmRow']} no longer loads a status circle")
    return tuple(sites)
