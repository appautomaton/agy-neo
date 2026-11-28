"""Chain-of-thought rendering, live thinking, thought grouping, and thought-block resolvers."""

from __future__ import annotations

import struct

from .asm import (
    NOP,
    VM_BASE,
    PatchSite,
    _adrp_add_at,
    _calls_to,
    _decode_sp_add,
    _recoverable,
    _words,
    assert_unreachable,
    branch_target,
    decode_branch_target,
    encode_adr,
    encode_adrp_add,
    encode_b,
    encode_bl,
    find_unique_anchor,
)

THOUGHT_MARK = "∴ ".encode()


def _find_step_content_s8(data: bytes | bytearray, sc: tuple[int, int]) -> tuple[int, int, int]:
    """Locate stepContent's expanded CoT test (`tbz wR, #0, span`) right after the `"Thought Process"` fallback.

    Returns `(s8_off, hdr_ptr_reg, exp_reg)`: `hdr_ptr_reg` holds the header string pointer (`x2` on
    v1.5.15, `x0` on v1.5.16+ after `plannerThinkingDuration` extraction); `exp_reg` holds `expanded`.
    """
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    hits: list[tuple[int, int, int]] = []
    for o in range(sc[0], sc[1] - 24, 4):
        if word(o) != 0xB2400FE1:  # orr x1, xzr, #0xf  (len("Thought Process") == 15)
            continue
        hdr_reg = word(o + 4) & 0x1F
        va = _adrp_add_at(data, o + 4, hdr_reg)
        if va is None or bytes(data[va - VM_BASE : va - VM_BASE + 15]) != b"Thought Process":
            continue
        if word(o + 12) & 0xFF8003FF != 0x910003FB or word(o + 16) & 0xFFC003E0 != 0x39400360:
            continue
        exp_reg = word(o + 16) & 0x1F
        if word(o + 20) & 0xFFF8001F != (0x36000000 | exp_reg):
            continue
        hits.append((o + 20, hdr_reg, exp_reg))
    if len(hits) != 1:
        raise RuntimeError(f"stepContent: expected one expanded CoT test after `Thought Process`, found {len(hits)}")
    return hits[0]


def _resolve_cot_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]], nl3_va: int
) -> tuple[tuple[PatchSite, ...], PatchSite]:
    """Sites #9-#11 & #23: Persistent expanded CoT (`∴ Thought...`, flush-left `Faint+Italic` paragraphs, `\\n\\n` spacing)."""
    sc = funcs["stepContent"]
    s8_off, _, _ = _find_step_content_s8(data, sc)

    # 9. render.stepContent -> fold Styles[+0x0510] stack copy loop & mutate "▾" (0xe2 96 be) to "∴" (0xe2 88 b4)
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    s9_hits = [
        o
        for o in range(s8_off + 0x60, min(sc[1] - 36, s8_off + 0xB0), 4)
        if word(o) in (0xD2800158, 0xD2800298)
        and word(o + 4) == 0xACC14470
        and word(o + 8) == 0xAC814450
    ]
    if len(s9_hits) != 1:
        raise RuntimeError(f"stepContent: expected one Styles[+0x0510] CoT header copy loop after Site 8, found {len(s9_hits)}")
    s9_off = s9_hits[0]
    s9_va = VM_BASE + s9_off

    # 10 & 11. omit 2-space paragraph prefix & style CoT body paragraphs with Faint + Italic (\x1b[2;3m)
    tbr = funcs["thoughtBodyRows"]
    cats = _calls_to(data, tbr, funcs["concatstring2"][0])
    if len(cats) != 1:
        raise RuntimeError(f"thoughtBodyRows: expected one `concatstring2`, found {len(cats)}")
    cat = cats[0]
    if struct.unpack_from("<I", data, cat - 4)[0] not in (0xB27F03E2, 0xAA1F03E2):
        raise RuntimeError("thoughtBodyRows: expected 2-byte prefix length before `concatstring2`")
    s10_off = cat - 4
    sp5 = _decode_sp_add(data, cat + 12)
    if sp5 is None or sp5[1] != 5 or sp5[2] != 8:
        raise RuntimeError("thoughtBodyRows: expected `add x5, sp, #8` for Style receiver")
    sp6 = _decode_sp_add(data, cat + 12 + sp5[0])
    if sp6 is None or sp6[1] != 6:
        raise RuntimeError("thoughtBodyRows: expected `add x6, sp, #...` for Styles[+0x510]")
    s11_off = cat + 12 + sp5[0] + sp6[0]
    cot_fn = "render.thoughtBodyRows"
    s10_va = VM_BASE + s10_off
    s11_va = VM_BASE + s11_off

    # 23. render.stripMarkdownFormatting -> collapse "\n\n\n" to "\n\n"
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
            name=f"{cot_fn} -> omit 2-space leading indent on CoT body paragraphs",
            va=s10_va,
            offset=s10_off,
            original=bytes.fromhex("e2037fb2"),
            patched=bytes.fromhex("e2031faa"),
        ),
        PatchSite(
            domain="cot-rendering",
            name=f"{cot_fn} -> style CoT body paragraphs with Faint + Italic (\\x1b[2;3m)",
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


def _resolve_thinking_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #51a-#51g: the running thought in the conversation, `∴ ` before it, and `Thinking` below."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    sites: list[PatchSite] = []

    def site(domain: str, name: str, off: int, patched: bytes, original: bytes | None = None) -> None:
        sites.append(PatchSite(domain, name, VM_BASE + off, off, _recoverable(data, off, patched, original), patched))

    def cond(at: int, target: int, base: int) -> int:
        return base | ((((target - at) // 4) & 0x7FFFF) << 5)

    # 51a-c. textDrip.flush
    fl = funcs["dripFlush"]
    cuts = _calls_to(data, fl, funcs["cutAtRuneBoundary"][0])
    logs = _calls_to(data, fl, funcs["logCtxlogf"][0])
    if len(cuts) != 1 or len(logs) != 1:
        raise RuntimeError("textDrip.flush no longer cuts and logs once each")
    c, log_end = cuts[0], logs[0] + 4
    gt, le, cbz, gate = c + 0x10, c + 0x20, c + 0x2C, c + 0x50
    cave = gate + 4
    if word(gt) & 0xFF00001F != 0x5400000C or word(c + 0x0C) != 0xEB05001F:
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
         + pack(cond(cave, partial, 0xB4000000))
         + encode_b(VM_BASE + cave + 4, VM_BASE + exit_)
         + THOUGHT_MARK)
    mark_va = VM_BASE + cave + 8

    # 51d-e. stepContent's live line
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
        if word(load) & 0xFFC003FF != 0x914003FB or word(load + 4) & 0xFFC003FF != 0xF9400362 \
                or word(load + 12) & 0xFFC003FF != 0xF9400363:
            raise RuntimeError("stepContent: the live line no longer loads its `(8s)`")
    site("cot-rendering", "render.stepContent -> the running thought leads with `∴ `, without its own `(8s)`",
         load, adrp_add + pack(0xD2800003 | (len(THOUGHT_MARK) << 5), 0xD503201F))
    swap = (cat - 0x18, cat - 0x14, cat - 0x10, cat - 0x04)
    lit_len, lit_ptr = word(swap[0]), word(swap[3])
    if (word(swap[1]), word(swap[2])) == (0xAA0003E3, 0xAA0103E4):
        lit_len, lit_ptr = (lit_len & ~0x1F) | 4, (lit_ptr & ~0x1F) | 3
    elif (word(swap[1]), word(swap[2])) != (0xAA0103E2, 0xAA0003E1):
        raise RuntimeError("stepContent: unexpected concatenation of the live line")
    if lit_len & 0xFFC0001F != 0xF9400004 or lit_ptr & 0xFFC0001F != 0xF9400003:
        raise RuntimeError("stepContent: the lit snippet is no longer reloaded from the stack")
    site("cot-rendering", "render.stepContent -> the mark before the snippet, not the suffix after it",
         cat - 0x18, pack(lit_len, 0xAA0103E2, 0xAA0003E1, word(cat - 0x0C), word(cat - 0x08), lit_ptr))

    # 51f. activityCandidate
    ac = funcs["activityCandidate"]
    three_ne = [o + 4 for o, w in _words(data, (ac[0], ac[1] - 4))
                if w == 0xF1000C1F and (word(o + 4) & 0xFF00001F == 0x54000001 or word(o + 4) >> 26 == 0x05)]
    three_eq = [o + 4 for o, w in _words(data, (ac[0], ac[1] - 4))
                if w == 0xF1000C1F and (word(o + 4) & 0xFF00001F == 0x54000000 or bytes(data[o + 4 : o + 8]) == NOP)]
    if len(three_ne) == 1 and not three_eq:
        br = three_ne[0]
        site("pending-line", "model.(*ConversationModel).activityCandidate -> Thinking shows its label, not the thought",
             br, encode_b(VM_BASE + br, VM_BASE + branch_target(word(br), br)))
    elif len(three_eq) == 1 and not three_ne:
        site("pending-line", "model.(*ConversationModel).activityCandidate -> Thinking shows its label, not the thought",
             three_eq[0], NOP)
    else:
        raise RuntimeError(f"activityCandidate: expected one Thinking test, found ne={len(three_ne)} eq={len(three_eq)}")

    # 51g. render.isInFlightThinkingOnly
    inf = funcs["isInFlightThinkingOnly"][0]
    answer_no = bytes.fromhex("e0031faac0035fd6")
    head = bytes(data[inf : inf + 8])
    if head != answer_no and head[:4] != bytes.fromhex("900b40f9"):
        raise RuntimeError("isInFlightThinkingOnly no longer opens with its stack check")
    site("cot-rendering", "render.isInFlightThinkingOnly -> false (keep live thoughts visible while running)",
         inf, answer_no)
    return tuple(sites)


def _resolve_thought_grouping_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #52a-#52c: thoughts are never folded into tool groups."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    up = funcs["canUpgradeTrailingThought"][0]
    answer_no = bytes.fromhex("e0031faac0035fd6")
    head = bytes(data[up : up + 8])
    if head != answer_no and head[:4] != bytes.fromhex("900b40f9"):
        raise RuntimeError("canUpgradeTrailingThoughtToToolGroup no longer opens with its stack check")

    fl = funcs["findLastToolGroup"]
    high = [o for o, w in _words(data, (fl[0], fl[1] - 0x1C))
            if word(o + 0x1C) & 0xFFFFFC00 == 0xF9400000
            and word(o + 0x08) & 0xFFFFFFE0 == 0xB94000C0
            and word(o + 0x0C) & 0xFFFFFFE0 == 0xD28D2D00
            and word(o + 0x10) & 0xFFFFFFE0 == 0xF2AD0CE0
            and (w == 0xF10010FF or branch_target(w, o) == o + 0x1C and w >> 26 == 0x05)]
    if len(high) != 1:
        raise RuntimeError(f"findLastToolGroupAbsIdx: expected one `high` test before the thought check, found {len(high)}")
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


def _resolve_thought_block_sites(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> tuple[PatchSite, ...]:
    """Sites #53c-#53e & #54a-#54i: orthogonal `/thinking` × `verbosity`."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
    calls = lambda o, sym: word(o) >> 26 == 0x25 and branch_target(word(o), o) == funcs[sym][0]
    sc = funcs["stepContent"]
    sites: list[PatchSite] = []

    def site(name: str, off: int, patched: bytes) -> None:
        sites.append(PatchSite("cot-rendering", name, VM_BASE + off, off, _recoverable(data, off, patched), patched))

    def cond(at: int, target: int, base: int) -> int:
        return base | ((((target - at) // 4) & 0x7FFFF) << 5)

    def tbz(at: int, target: int, rt: int, bit: int = 0) -> int:
        disp = (target - at) // 4
        if not -0x2000 <= disp < 0x2000:
            raise RuntimeError(f"tbz target {hex(VM_BASE + target)} out of range from {hex(VM_BASE + at)}")
        return 0x36000000 | ((bit >> 5) << 31) | ((bit & 0x1F) << 19) | ((disp & 0x3FFF) << 5) | (rt & 0x1F)

    def entered_from_outside(lo: int, hi: int, bounds: tuple[int, int]) -> bool:
        return any(not lo <= o < hi and (t := branch_target(word(o), o)) is not None and lo < t < hi
                   for o in range(bounds[0], bounds[1], 4))

    gates = [o + 8 for o, w in _words(data, (sc[0], sc[1] - 8))
             if w & 0xFFFFFC1F == 0x71002C1F and word(o + 4) & 0xFF00001F == 0x54000001
             and (word(o + 8) & 0xFF000000 == 0xB5000000
                  and branch_target(word(o + 8), o + 8) == branch_target(word(o + 4), o + 4)
                  or word(o + 8) >> 26 == 0x05)]
    if len(gates) != 1:
        raise RuntimeError(f"stepContent: expected one live/full CoT gate, found {len(gates)}")
    gate = gates[0]
    full, live = branch_target(word(gate - 4), gate - 4), gate + 4

    if word(full + 0x2C) & 0xFFFFFC1F != 0x71002C1F or word(full + 0x20) & 0xFF00001F != 0x54000009 \
            or word(full + 0x28) & 0xFF00001F != 0x54000000 \
            or word(full + 0x30) & 0xFF00001F != 0x54000001:
        raise RuntimeError("stepContent: the full CoT branch no longer bails out of running steps as expected")
    bail = branch_target(word(full + 0x20), full + 0x20)
    if branch_target(word(full + 0x28), full + 0x28) != bail or bail != full + 0x34:
        raise RuntimeError("stepContent: the full CoT branch no longer bails out of running steps in one place")
    bails = [full + 0x20, full + 0x28]
    after_bail = branch_target(word(full + 0x30), full + 0x30)
    if after_bail < bail + 0x14:
        raise RuntimeError("stepContent: inline running-step bail-out is too small for Site #53c")

    s8, hdr_reg, _ = _find_step_content_s8(data, sc)
    span = branch_target(word(s8), s8)

    if word(s8 - 8) & 0xFF8003FF != 0x910003FB or word(s8 - 4) & 0xFFC003E0 != 0x39400360:
        raise RuntimeError("stepContent: the expanded flag is no longer loaded via `add x27, sp, ...; ldrb wR, [x27, ...]`")
    exp_hi, exp_ld = word(s8 - 8), word(s8 - 4) & ~0x1F
    live_exps = [
        o + 12 for o, w in _words(data, (live, full - 12))
        if w == exp_hi and (word(o + 4) & ~0x1F) == exp_ld
        and (word(o + 8) & 0xFFF8001F) == (0x36000000 | (word(o + 4) & 0x1F))
    ]
    if len(live_exps) != 1:
        raise RuntimeError(f"stepContent: expected one expanded check in the live CoT branch, found {len(live_exps)}")
    live_exp = live_exps[0]
    if branch_target(word(live_exp), live_exp) != bail:
        one_liner = branch_target(word(live_exp - 4), live_exp - 4)
        if one_liner is None or one_liner <= live_exp or entered_from_outside(live_exp - 4, one_liner, sc):
            raise RuntimeError("stepContent: the live expanded CoT branch is entered from elsewhere")

    expected_bails = sorted([*bails, *(live_exps if branch_target(word(live_exp), live_exp) == bail else ())])
    if {s for o in range(sc[0], sc[1], 4) if (s := branch_target(word(o), o)) is not None and bail <= s < bail + 0x14} != {bail} \
            or [o for o in range(sc[0], sc[1], 4) if branch_target(word(o), o) == bail] != expected_bails:
        raise RuntimeError("stepContent: the running-step bail-out is reached from elsewhere")

    joins = [o for o in _calls_to(data, (s8, sc[1]), funcs["stringsJoin"][0])
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
    st_ptr, st_len = (hptr & ~0x1F & ~0x00400000) | 0, (hlen & ~0x1F & ~0x00400000) | 1
    stores = [o for o, w in _words(data, (s8, span - 12))
              if w == st_ptr and word(o - 4) == word(j + 0x24) and word(o + 8) == st_len and word(o + 4) == word(j + 0x04)]
    if len(stores) != 1:
        raise RuntimeError(f"stepContent: expected one store of the CoT header, found {len(stores)}")
    body = stores[0] + 12

    hdr_calls = [o for o in range(span + 0x40, min(sc[1] - 0x54, span + 0x80), 4)
                 if calls(o, "fmtSprintf") or calls(o, "concatstring2")]
    if len(hdr_calls) != 1 or not calls(hdr_calls[0] + 0x50, "styleRender"):
        raise RuntimeError("stepContent: the collapsed CoT header is no longer `Render(Sprintf(...))`")
    hdr_call = hdr_calls[0]
    if calls(hdr_call, "fmtSprintf") and (
        not any(calls(o, "convTstring") for o in range(span, hdr_call, 4))
        or entered_from_outside(span, hdr_call, sc)
    ):
        raise RuntimeError("stepContent: the collapsed CoT header code changed")
    snips = _calls_to(data, sc, funcs["collapsedThinkingSnippet"][0])
    if len(snips) != 1:
        raise RuntimeError(f"stepContent: expected one collapsed thinking snippet, found {len(snips)}")
    c = snips[0]
    if not calls(c + 0x28, "concatstring2") or not calls(c + 0xA4, "concatstring3") \
            or word(c + 0x10) not in (0xB27F03E2, 0xAA1F03E2) or word(c + 0x8C) not in (0xB24003E4, 0xAA1F03E4):
        raise RuntimeError("stepContent: the collapsed CoT snippet is no longer joined as `header\\n  snippet`")
    has_answer = c - 0x78
    if branch_target(word(has_answer), has_answer) != c - 0x18 \
            or not (word(has_answer) & 0xFF00001F == 0xB4000002 or word(has_answer) >> 26 == 0x05):
        raise RuntimeError("stepContent: the collapsed CoT snippet is no longer skipped beside an answer")

    durs = _calls_to(data, (full, span), funcs["fmtDuration"][0])
    if len(durs) != 2:
        raise RuntimeError("stepContent: the CoT header no longer formats its duration in two places")
    if word(durs[0] - 4) == 0xAA0103E0 and word(durs[1] - 4) == 0xAA0103E0:
        tok, plain = durs[0] - 4, durs[1] - 4
    else:
        tok, plain = durs[0], durs[1]
    tok_at = tok - 0x0C
    w_br = word(tok_at + 8)
    if w_br & 0xFF000000 == 0xB4000000 and branch_target(w_br, tok_at + 8) == plain:
        tok_reg = w_br & 0x1F
        tok_load = (word(tok_at), word(tok_at + 4))
        if tok_load[0] & 0xFF8003FF != 0x910003FB or (tok_load[1] & 0x1F) != tok_reg:
            raise RuntimeError("stepContent: unexpected token-count load before `cbz`")
    elif word(tok_at) == exp_hi and (word(tok_at + 4) & ~0x1F) == exp_ld and branch_target(w_br, tok_at + 8) == span + 0x20:
        tok_reg = word(tok_at + 4) & 0x1F
        tok_load = (word(span + 0x24), word(span + 0x28))
    elif branch_target(w_br, tok_at + 8) == span + 0x44:
        tok_reg = 2
        tok_load = (word(span + 0x4C), word(span + 0x50))
    else:
        raise RuntimeError("stepContent: the CoT header no longer tests its token count")
    exp_load = (exp_hi, exp_ld | tok_reg)

    v = lambda o: VM_BASE + o
    collapsed = (pack(0xAA0003E3 | (hdr_reg << 16), 0xAA0103E4)
                 + encode_adr(v(span + 0x08), v(span + 0x18), 1)
                 + pack(0xD2800082, 0xAA1F03E0)
                 + encode_b(v(span + 0x14), v(hdr_call)) + THOUGHT_MARK + NOP)
    tokens = (pack(tbz(span + 0x20, plain, tok_reg), *tok_load,
                   cond(span + 0x2C, plain, 0xB4000000 | tok_reg))
              + encode_b(v(span + 0x30), v(tok)))
    assert (len(collapsed), len(tokens)) == (0x20, 0x14)

    site("render.stepContent -> a running thought in the full branch: empty header, straight to the body", bail,
         pack(word(j + 0x24), st_ptr | 31, word(j + 0x04), st_len | 31) + encode_b(v(bail + 16), v(body)))
    site("render.stepContent -> the CoT block is body, then its `∴ Thought for` line", j + 0x08,
         pack(hlen, word(j + 0x0C), word(j + 0x10), word(j + 0x14), 0xAA0103E2, 0xAA0003E1, word(j + 0x20), word(j + 0x24), hptr))
    site("render.stepContent -> an expanded running thought uses the headerless full block", live_exp,
         encode_b(v(live_exp), v(bail)))
    site("render.stepContent -> a collapsed thought's header is `∴ <header>`", span, collapsed)
    site("render.stepContent -> the collapsed header's `Sprintf` becomes `concatstring2`", hdr_call,
         encode_bl(v(hdr_call), VM_BASE + funcs["concatstring2"][0]))
    site("render.stepContent -> the CoT header asks whether the thought is expanded before its token count", tok_at,
         pack(*exp_load) + encode_b(v(tok_at + 8), v(span + 0x20)))
    site("render.stepContent -> collapsed thoughts leave out the token count; expanded ones keep it", span + 0x20, tokens)
    site("render.stepContent -> the collapsed snippet loses its two-space indent", c + 0x10, pack(0xAA1F03E2))
    site("render.stepContent -> the collapsed snippet joins its header on one line", c + 0x8C, pack(0xAA1F03E4))
    site("render.stepContent -> a collapsed thought keeps its snippet beside an answer", has_answer,
         encode_b(v(has_answer), v(c - 0x18)))

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
    snippet = (pack(0xD2800142) + NOP * 2 + encode_bl(v(f + 0x58), VM_BASE + funcs["indexByteString"][0])
               + pack(0xF9401BE1, 0xF100001F, 0x9A81A001, 0xF94023E0)
               + encode_b(v(f + 0x6C), v(f + 0x98)) + b" ()\0"
               + encode_adr(v(f + 0x74), v(f + 0x70), 1)
               + pack(0xD2800042, 0x91000825, 0xD2800026, 0xAA1F03E0)
               + encode_bl(v(f + 0x88), VM_BASE + funcs["concatstring3"][0]) + pack(*epilogue)
               + bytes(data[f + 0x98 : f + 0xA8])
               + pack(cond(f + 0xA8, f + 0x8C, 0xB4000001), 0xAA0003E3, 0xAA0103E4)
               + encode_b(v(f + 0xB4), v(f + 0x74)))
    assert len(snippet) == 0x6C
    site("render.collapsedThinkingSnippet -> fit to the width minus the collapsed CoT header", width_at, pack(0xD1006042))
    site("render.collapsedThinkingSnippet -> ` (<first line>)` instead of the last paragraph", f + 0x4C, snippet)
    return tuple(sites)
