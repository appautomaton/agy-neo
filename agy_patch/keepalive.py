"""Native `modelapiccpa.(*keepAlives)` prompt-cache keepalive & 52-bit telemetry resolver."""

from __future__ import annotations

import struct

from .asm import (
    NOP,
    VM_BASE,
    PatchSite,
    _calls_to,
    _find_all,
    _go_struct_type,
    _go_types_base,
    _noptrbss_bounds,
    _section_file_bounds,
    _sp_slot,
    branch_target,
    encode_adrp,
    encode_adrp_add,
    encode_b,
    encode_b_cond,
    encode_b_ne,
    encode_bl,
    go_type_descriptor,
)


def _resolve_keepalive_sites(
    data: bytes | bytearray, funcs: dict[str, tuple[int, int]]
) -> tuple[PatchSite, ...]:
    """Unify OAuth and local gateway onto native `modelapiccpa.(*keepAlives)` and export telemetry to StatusLineData."""
    word = lambda o: struct.unpack_from("<I", data, o)[0]
    pack = lambda *ws: struct.pack(f"<{len(ws)}I", *ws)
    movz = lambda rd, imm, sh=0: 0xD2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd
    movk = lambda rd, imm, sh: 0xF2800000 | ((sh // 16) << 21) | ((imm & 0xFFFF) << 5) | rd
    stock_or_none = lambda off, patched: None if bytes(data[off : off + len(patched)]) == patched else bytes(data[off : off + len(patched)])
    ret_bytes = bytes.fromhex("c0035fd6")
    sites: list[PatchSite] = []

    # 1. Gateway session affinity: preserve GenerateContentRequest.SessionId on gateway requests.
    set_role_off = funcs["setToolResultRoleToUser"][0]
    gw_targets = (
        (("buildGatewayHTTPRequest", "codeassistclient.(*CodeAssistClient).buildGatewayHTTPRequest"),)
        if "buildGatewayHTTPRequest" in funcs
        else (
            ("StreamGenerateContentFromGateway", "codeassistclient.(*CodeAssistClient).StreamGenerateContentFromGateway"),
            ("GenerateContentFromGateway", "codeassistclient.(*CodeAssistClient).GenerateContentFromGateway"),
        )
    )
    for sym_key, label in gw_targets:
        calls = _calls_to(data, funcs[sym_key], set_role_off)
        if len(calls) != 1:
            raise RuntimeError(f"{label}: expected 1 call to setToolResultRoleToUser, found {len(calls)}")
        cbz_off = calls[0] + 8
        w_cbz = word(cbz_off)
        target = branch_target(w_cbz, cbz_off)
        if target is None or not (0x0C <= target - cbz_off <= 0x40):
            raise RuntimeError(f"{label}: expected short cbz/b guard after setToolResultRoleToUser at {hex(VM_BASE + cbz_off)}")
        orig_cbz = pack(0xB4000000 | ((((target - cbz_off) // 4) & 0x7FFFF) << 5))
        patched_b = encode_b(VM_BASE + cbz_off, VM_BASE + target)
        if bytes(data[cbz_off : cbz_off + 4]) not in (orig_cbz, patched_b):
            raise RuntimeError(f"{label}: unexpected guard word {hex(w_cbz)} at {hex(VM_BASE + cbz_off)}")
        sites.append(
            PatchSite(
                "cache-keepalive",
                f"{label} -> preserve GenerateContentRequest.SessionId on gateway requests",
                VM_BASE + cbz_off,
                cbz_off,
                orig_cbz,
                patched_b,
            )
        )

    # 2. Route nil FeatureProvider (and nil featureProviderResolver on v1.5.13) through modelapiccpa.keepAlivePings.
    gen_bounds = funcs["ccpaGenerate"]
    kp_bounds = funcs["keepAlivePings"]
    kp_calls = _calls_to(data, gen_bounds, kp_bounds[0])
    if len(kp_calls) != 1:
        raise RuntimeError(f"modelapiccpa.(*Client).Generate: expected 1 call to keepAlivePings, found {len(kp_calls)}")
    kp_call = kp_calls[0]
    ldr_fp_data = _sp_slot(word(kp_call - 4), 0xF94003E0)
    w_post1, w_post2 = word(kp_call + 4), word(kp_call + 8)
    if (w_post1 & 0xFFC003FF) == 0x394003E1:
        w_credits = w_post1
    elif w_post1 == 0xAA0003E1 and (w_post2 & 0xFFC003FF) == 0x394003E0:
        w_credits = w_post2
    else:
        w_credits = 0
    if ldr_fp_data is None or ldr_fp_data[0] != 1 or not w_credits:
        raise RuntimeError("modelapiccpa.(*Client).Generate: unexpected stack loads around keepAlivePings call")
    fp_data_sp = ldr_fp_data[1]
    credits_sp = (w_credits >> 10) & 0xFFF

    cbnz_guards = [
        o
        for o in range(gen_bounds[0], kp_call - 12, 4)
        if (word(o) & 0xFF000000) == 0xB5000000 and branch_target(word(o), o) == o + 0x10
    ]
    if len(cbnz_guards) not in (1, 2):
        raise RuntimeError(f"modelapiccpa.(*Client).Generate: expected 1 or 2 cbnz feature-provider guards, found {len(cbnz_guards)}")
    g2_body = cbnz_guards[-1] + 4
    g2_patched = (
        pack(
            0xF90003FF | ((fp_data_sp // 8) << 10),
            0x390003FF | (credits_sp << 10),
        )
        + encode_b(VM_BASE + g2_body + 8, VM_BASE + kp_call)
    )
    if len(cbnz_guards) == 2:
        g1_body = cbnz_guards[0] + 4
        g1_patched = pack(0xAA1F03E0, 0xAA1F03E1) + encode_b(VM_BASE + g1_body + 8, VM_BASE + g2_body)
        sites.append(
            PatchSite(
                "cache-keepalive",
                "modelapiccpa.(*Client).Generate -> route nil featureProviderResolver through keepAlivePings",
                VM_BASE + g1_body,
                g1_body,
                stock_or_none(g1_body, g1_patched),
                g1_patched,
            )
        )
    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.(*Client).Generate -> route nil FeatureProvider through keepAlivePings",
            VM_BASE + g2_body,
            g2_body,
            stock_or_none(g2_body, g2_patched),
            g2_patched,
        )
    )

    # 3a. Skip keepalive registration for all subagents (`parent_cascade_id != ""`).
    br_bounds = funcs["keepAlivesBeforeRequest"]
    sub_guards = [
        (o + 4, branch_target(word(t), t))
        for o in range(br_bounds[0], min(br_bounds[1], br_bounds[0] + 0x100), 4)
        if (word(o) & 0xFF00001F) == 0xB4000004
        and (main_flow := branch_target(word(o), o)) is not None
        and 0x100 <= main_flow - o <= 0x280
        for t in (main_flow - 4,)
        if (word(t) & 0xFFF8001F) == 0x37000003
    ]
    if len(sub_guards) != 1 or sub_guards[0][1] is None:
        raise RuntimeError(f"keepAlives.beforeRequest: expected 1 parent_cascade_id guard, found {sub_guards}")
    sub_skip_off, sub_early_ret = sub_guards[0]
    sub_skip_patched = encode_b(VM_BASE + sub_skip_off, VM_BASE + sub_early_ret)
    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.(*keepAlives).beforeRequest -> skip keepalive on all subagents (parent_cascade_id set)",
            VM_BASE + sub_skip_off,
            sub_skip_off,
            stock_or_none(sub_skip_off, sub_skip_patched),
            sub_skip_patched,
        )
    )

    # 3b. Preserve full prompt prefix by NOPing `bl trimLastBlock`.
    tlb_start, tlb_end = funcs["trimLastBlock"]
    tlb_sites = [
        o + 4
        for o in range(br_bounds[0], br_bounds[1] - 8, 4)
        if word(o) in (0xAA0103E0, 0xF9001004)
        and (branch_target(word(o + 4), o + 4) == tlb_start or bytes(data[o + 4 : o + 8]) == NOP)
        and (_sp_slot(word(o + 8), 0xF94003E0) or (None, None))[0] == 1
    ]
    if len(tlb_sites) != 1:
        raise RuntimeError(f"keepAlives.beforeRequest: expected 1 trimLastBlock call site, found {len(tlb_sites)}")
    tlb_call = tlb_sites[0]
    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.(*keepAlives).beforeRequest -> skip trimLastBlock to preserve full prompt prefix",
            VM_BASE + tlb_call,
            tlb_call,
            encode_bl(VM_BASE + tlb_call, VM_BASE + tlb_start),
            NOP,
        )
    )

    # 4. Reserve two contiguous unused Halloween __noptrbss uint64 globals (`g_hash`, `g_val`).
    noptr_lo, noptr_hi = _noptrbss_bounds(data)
    hi_start, hi_end = funcs["halloweenInit"]
    hw_slots: list[tuple[int, int, int]] = []
    for o in range(hi_start, hi_end - 12, 4):
        bt = branch_target(word(o), o)
        if (bt is not None and (word(o) >> 26) == 0x25) or word(o) == 0xAA1F03E0:
            w_adrp, w_str = word(o + 4), word(o + 8)
            if (w_adrp & 0x9F00001F) == 0x9000001B and (w_str & 0xFFC003FF) == 0xF9000360:
                immlo = (w_adrp >> 29) & 0x3
                immhi = (w_adrp >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = ((VM_BASE + o + 4) & ~0xFFF) + (imm << 12)
                gva = page + (((w_str >> 10) & 0xFFF) * 8)
                if noptr_lo <= gva < noptr_hi:
                    hw_slots.append((o, bt if bt is not None else funcs["lipglossColor"][0], gva))
    if len(hw_slots) != 2 or hw_slots[1][2] != hw_slots[0][2] + 8:
        raise RuntimeError(f"halloween.init: expected 2 adjacent __noptrbss uint64 stores, found {hw_slots}")
    g_hash_va, g_val_va = hw_slots[0][2], hw_slots[1][2]
    for idx, (bl_off, bl_tgt, _) in enumerate(hw_slots):
        role = "session hash" if idx == 0 else "packed telemetry"
        sites.append(
            PatchSite(
                "cache-keepalive",
                f"halloween.init -> reserve __noptrbss uint64 ({role})",
                VM_BASE + bl_off,
                bl_off,
                encode_bl(VM_BASE + bl_off, VM_BASE + bl_tgt),
                pack(0xAA1F03E0),
            )
        )

    # 5. Go reflection metadata for `modelapiccpa.keepAlive` and `types.StatusLineData`.
    types_base = _go_types_base(data, funcs)
    _, _, _, ka_fields = _go_struct_type(data, "*modelapiccpa.keepAlive", types_base)
    ka_map = {nm: byte_off for _, nm, _, _, byte_off in ka_fields}
    for req_nm in ("refreshedAt", "pingsSent", "pingsLeft"):
        if req_nm not in ka_map:
            raise RuntimeError(f"modelapiccpa.keepAlive missing field {req_nm!r}: {list(ka_map)}")
    ref_off, sent_off, left_off = ka_map["refreshedAt"], ka_map["pingsSent"], ka_map["pingsLeft"]
    if ref_off % 8 or sent_off % 8 or left_off % 8:
        raise RuntimeError(f"modelapiccpa.keepAlive unaligned offsets: {ka_map}")

    _, sl_size, sl_ptrb, sl_fields = _go_struct_type(data, "*types.StatusLineData", types_base)
    sl_by_name = {nm: (slot_off, fn_va, ft_va, byte_off) for slot_off, nm, fn_va, ft_va, byte_off in sl_fields}
    if "SessionID" not in sl_by_name or "TerminalWidth" not in sl_by_name:
        raise RuntimeError("types.StatusLineData missing SessionID or TerminalWidth")
    session_id_off = sl_by_name["SessionID"][3]
    int_type_va = sl_by_name["TerminalWidth"][2]
    last_slot_off, last_nm, _, _, keepalive_field_off = sl_fields[-1]
    if last_nm not in ("statusLineDataInternal", "CacheKeepalive") or keepalive_field_off < sl_ptrb or keepalive_field_off + 8 > sl_size:
        raise RuntimeError(
            f"types.StatusLineData trailing slot unusable: field={last_nm!r} off={hex(keepalive_field_off)} "
            f"ptrbytes={hex(sl_ptrb)} size={hex(sl_size)}"
        )
    orig_internal_type_va = VM_BASE + go_type_descriptor(data, "*types.statusLineDataInternal", types_base)
    go_type = _section_file_bounds(data, "__DATA_CONST", "__go_type")
    internal_nm = b"statusLineDataInternal"
    internal_recs = [
        VM_BASE + i - 2
        for i in _find_all(data, internal_nm, go_type)
        if data[i - 1] == len(internal_nm) and data[i - 2] == 0x08
    ]
    if len(internal_recs) != 1:
        raise RuntimeError(f"Expected 1 abi.Name for statusLineDataInternal, found {len(internal_recs)}")
    orig_internal_name_va = internal_recs[0]

    # 6. Assemble cave contents inside trimLastBlock.
    cave_va = VM_BASE + tlb_start
    kp_start, kp_end = kp_bounds
    if kp_end - kp_start < 0x88 or word(kp_start + 0x0C) != 0xF81D0FFE or word(kp_start + 0x74) != 0xD65F03C0:
        raise RuntimeError("modelapiccpa.keepAlivePings frame layout changed")
    kp_call_pc = kp_start + 0x38
    if word(kp_call_pc) != 0xD63F0060 and branch_target(word(kp_call_pc), kp_call_pc) != funcs["osGetenv"][0]:
        raise RuntimeError("modelapiccpa.keepAlivePings: expected call at +0x38")
    kp_set_x0_va = VM_BASE + kp_start + 0x68

    parse_tail_va = cave_va
    parse_tail_code = (
        pack(
            0x39400403,
            0x7100C063,
            0x7100247F,
            0x54000068,
            movz(4, 10),
            0x9B040C42,
        )
        + encode_b(parse_tail_va + 24, kp_set_x0_va)
    )

    entry_live_va = parse_tail_va + len(parse_tail_code)
    entry_exhausted_va = entry_live_va + 8
    entry_failed_va = entry_exhausted_va + 8
    entry_clear_va = entry_failed_va + 8
    writer_common_va = entry_clear_va + 8

    stubs_code = (
        pack(movz(8, 1)) + encode_b(entry_live_va + 4, writer_common_va)
        + pack(movz(8, 2)) + encode_b(entry_exhausted_va + 4, writer_common_va)
        + pack(movz(8, 3)) + encode_b(entry_failed_va + 4, writer_common_va)
        + pack(0xAA1F03E8) + encode_b(entry_clear_va + 4, writer_common_va)
    )

    wall_to_int = 0xDD7B17F80
    unix_to_int = 0xE7791F700
    traj_h_ldr = 0xB94000C7 | (((g_hash_va & 0xFFF) // 4) << 10)
    traj_h_str = 0xB90000C3 | (((g_hash_va & 0xFFF) // 4) << 10)
    traj_h_clr = 0xB90000DF | (((g_hash_va & 0xFFF) // 4) << 10)
    sid_h_ldr = 0xB94000C7 | ((((g_hash_va + 4) & 0xFFF) // 4) << 10)
    sid_h_str = 0xB90000C3 | ((((g_hash_va + 4) & 0xFFF) // 4) << 10)
    g_val_str0 = 0xF900013F | (((g_val_va & 0xFFF) // 8) << 10)
    g_val_str2 = 0xF9000122 | (((g_val_va & 0xFFF) // 8) << 10)

    def assemble_block(base_va: int, spec: list) -> bytes:
        labels: dict[str, int] = {}
        idx = 0
        for item in spec:
            if isinstance(item, str):
                labels[item] = idx
            else:
                idx += 1
        out_words: list[int] = []
        pc_idx = 0
        for item in spec:
            if isinstance(item, str):
                continue
            if callable(item):
                item = item(base_va + pc_idx * 4, {k: base_va + v * 4 for k, v in labels.items()})
            out_words.append(item if isinstance(item, int) else struct.unpack("<I", item)[0])
            pc_idx += 1
        return pack(*out_words)

    cbz_x = lambda rt, tgt: lambda pc, L: 0xB4000000 | ((((L[tgt] - pc) // 4) & 0x7FFFF) << 5) | rt
    cbnz_x = lambda rt, tgt: lambda pc, L: 0xB5000000 | ((((L[tgt] - pc) // 4) & 0x7FFFF) << 5) | rt
    b_cond = lambda cond, tgt: lambda pc, L: encode_b_cond(pc, L[tgt], cond)
    adrp_op = lambda rd, target_va: lambda pc, L: encode_adrp(pc, target_va, rd)
    tbz_bit63 = lambda rt, tgt: lambda pc, L: 0xB6F80000 | ((((L[tgt] - pc) // 4) & 0x3FFF) << 5) | rt
    cbnz_w = lambda rt, tgt: lambda pc, L: 0x35000000 | ((((L[tgt] - pc) // 4) & 0x7FFFF) << 5) | rt

    writer_spec: list = [
        0xA9410BE1,
        cbz_x(2, "ret"),
        movz(3, 0x9DC5),
        movk(3, 0x811C, 16),
        movz(4, 0x0193),
        movk(4, 0x0100, 16),
        "hash_loop",
        0x38401425,
        0x4A050063,
        0x1B047C63,
        0xF1000442,
        b_cond(0x1, "hash_loop"),
        0x7100007F,
        0x1A9F1463,
        adrp_op(6, g_hash_va),
        adrp_op(9, g_val_va),
        cbnz_x(8, "non_clear"),
        traj_h_ldr,
        0x6B0300FF,
        b_cond(0x1, "ret"),
        g_val_str0,
        0xD65F03C0,
        "non_clear",
        0xF94013E1,
        cbz_x(1, "ret"),
        0xF9400025 | ((sent_off // 8) << 10),
        cbnz_x(5, "verify_traj"),
        traj_h_str,
        0x2A0303E7,
        b_cond(0xE, "pack_entry"),
        "verify_traj",
        traj_h_ldr,
        0x6B0300FF,
        b_cond(0x1, "ret"),
        "pack_entry",
        0xA9400C22 | (((ref_off // 8) & 0x3F) << 15),
        tbz_bit63(2, "no_mono"),
        0xD35EF844,
        movz(5, wall_to_int & 0xFFFF),
        movk(5, (wall_to_int >> 16) & 0xFFFF, 16),
        movk(5, (wall_to_int >> 32) & 0xFFFF, 32),
        0x8B050083,
        "no_mono",
        movz(5, unix_to_int & 0xFFFF),
        movk(5, (unix_to_int >> 16) & 0xFFFF, 16),
        movk(5, (unix_to_int >> 32) & 0xFFFF, 32),
        0xEB050062,
        0x9A9FC042,
        0xD3408442,
        0xF9400023 | ((sent_off // 8) << 10),
        0xF100007F,
        0x9A9FC063,
        movz(5, 255),
        0xF103FC7F,
        0x9A859063,
        0xF9400024 | ((left_off // 8) << 10),
        0xF100009F,
        0x9A9FC084,
        0xF103FC9F,
        0x9A859084,
        0xAA038842,
        0xAA04A842,
        0xAA08C842,
        g_val_str2,
        "ret",
        0xD65F03C0,
    ]
    writer_code = assemble_block(writer_common_va, writer_spec)

    sl_read_va = writer_common_va + len(writer_code)
    g_val_ldr8 = 0xF9400128 | (((g_val_va & 0xFFF) // 8) << 10)
    sl_store_ka = 0xF9000008 | ((keepalive_field_off // 8) << 10)
    sl_load_sid = 0xA9400801 | (((session_id_off // 8) & 0x3F) << 15)

    sl_spec: list = [
        cbz_x(0, "ret"),
        sl_load_sid,
        cbz_x(2, "ret"),
        movz(3, 0x9DC5),
        movk(3, 0x811C, 16),
        movz(4, 0x0193),
        movk(4, 0x0100, 16),
        "hash_loop",
        0x38401425,
        0x4A050063,
        0x1B047C63,
        0xF1000442,
        b_cond(0x1, "hash_loop"),
        0x7100007F,
        0x1A9F1463,
        adrp_op(6, g_hash_va),
        adrp_op(9, g_val_va),
        sid_h_ldr,
        cbnz_w(7, "check_sid"),
        sid_h_str,
        b_cond(0xE, "matched"),
        "check_sid",
        0x6B0300FF,
        b_cond(0x0, "matched"),
        sid_h_str,
        traj_h_clr,
        g_val_str0,
        0xD65F03C0,
        "matched",
        g_val_ldr8,
        sl_store_ka,
        "ret",
        0xD65F03C0,
    ]
    sl_code = assemble_block(sl_read_va, sl_spec)

    env_bytes = b"AGY_CACHE_MAX_TOUCHES"
    env_va = sl_read_va + len(sl_code)
    env_padded = env_bytes + b"\x00" * ((4 - len(env_bytes) % 4) % 4)

    field_name = b"CacheKeepalive"
    field_tag = b'json:"cache_keepalive,omitempty"'
    abi_name_va = env_va + len(env_padded)
    abi_name_bytes = bytes([0x03, len(field_name)]) + field_name + bytes([len(field_tag)]) + field_tag
    abi_name_padded = abi_name_bytes + b"\x00" * ((4 - len(abi_name_bytes) % 4) % 4)

    cave_payload = parse_tail_code + stubs_code + writer_code + sl_code + env_padded + abi_name_padded
    if len(cave_payload) > tlb_end - tlb_start:
        raise RuntimeError(f"keepalive cave needs {len(cave_payload)}B, trimLastBlock has {tlb_end - tlb_start}B")

    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.trimLastBlock -> keepalive telemetry helpers and CacheKeepalive abi.Name",
            cave_va,
            tlb_start,
            stock_or_none(tlb_start, cave_payload),
            cave_payload,
        )
    )

    # 7. Rebuild keepAlivePings body (+0x18..+0x6c, 84B).
    kp_body_off = kp_start + 0x18
    kp_body_va = VM_BASE + kp_body_off
    kp_body_code = (
        pack(0xA903FFFF)
        + encode_adrp_add(kp_body_va + 0x04, env_va, 0)
        + pack(movz(1, len(env_bytes)))
        + NOP * 4
        + encode_bl(VM_BASE + kp_call_pc, VM_BASE + funcs["osGetenv"][0])
        + pack(
            movz(2, 4),
            0xB4000141,
            0x39400003,
            0xAA1F03E2,
            0x7100C063,
            0x7100247F,
            0x540000A8,
            0x2A0303E2,
            0xF100043F,
        )
        + encode_b_ne(kp_body_va + 0x48, parse_tail_va)
        + NOP
        + pack(0xAA0203E0)
    )
    assert len(kp_body_code) == 0x54
    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.keepAlivePings -> read AGY_CACHE_MAX_TOUCHES (default 4, 0 disables)",
            kp_body_va,
            kp_body_off,
            stock_or_none(kp_body_off, kp_body_code),
            kp_body_code,
        )
    )

    # 8. Tail-hook scheduleNextPingLocked, ping's 4 mapdelete exits, stopLocked, and BuildStatusLineData.
    def find_rets(bounds: tuple[int, int], expected_targets: set[int]) -> list[int]:
        return [
            o
            for o in range(bounds[0], bounds[1], 4)
            if word(o) == 0xD65F03C0
            or ((word(o) >> 26) == 0x05 and branch_target(word(o), o) in expected_targets)
        ]

    cave_entry_offs = {
        entry_live_va - VM_BASE,
        entry_exhausted_va - VM_BASE,
        entry_failed_va - VM_BASE,
        entry_clear_va - VM_BASE,
        sl_read_va - VM_BASE,
    }

    sched_rets = find_rets(funcs["scheduleNextPingLocked"], cave_entry_offs)
    if len(sched_rets) != 1:
        raise RuntimeError(f"scheduleNextPingLocked: expected 1 ret, found {len(sched_rets)}")
    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.(*keepAlives).scheduleNextPingLocked -> publish live keepalive telemetry",
            VM_BASE + sched_rets[0],
            sched_rets[0],
            ret_bytes,
            encode_b(VM_BASE + sched_rets[0], entry_live_va),
        )
    )

    mapdel_off = funcs["mapdeleteFaststr"][0]
    ping_bounds = funcs["keepAlivesPing"]
    ping_del_calls = _calls_to(data, ping_bounds, mapdel_off)
    if len(ping_del_calls) != 4:
        raise RuntimeError(f"keepAlives.ping: expected 4 mapdelete_faststr calls, found {len(ping_del_calls)}")
    all_ping_rets = find_rets(ping_bounds, cave_entry_offs)
    for idx, del_call in enumerate(ping_del_calls):
        ret_off = next((r for r in all_ping_rets if 0 < r - del_call <= 0x60), None)
        if ret_off is None:
            raise RuntimeError(f"keepAlives.ping: no ret within 0x60B after mapdelete at {hex(VM_BASE + del_call)}")
        exhausted = any(
            (word(o) & 0xFFC00000) == 0xF9000000 and (((word(o) >> 10) & 0xFFF) * 8) == left_off
            for o in range(max(ping_bounds[0], del_call - 0x30), del_call, 4)
        )
        target_va = entry_exhausted_va if exhausted else entry_failed_va
        tag = "exhausted" if exhausted else f"failed #{idx + 1}"
        sites.append(
            PatchSite(
                "cache-keepalive",
                f"modelapiccpa.(*keepAlives).ping -> publish {tag} keepalive telemetry",
                VM_BASE + ret_off,
                ret_off,
                ret_bytes,
                encode_b(VM_BASE + ret_off, target_va),
            )
        )

    stop_bounds = funcs["keepAlivesStopLocked"]
    stop_del_calls = _calls_to(data, stop_bounds, mapdel_off)
    stop_rets = find_rets(stop_bounds, cave_entry_offs)
    stop_hit_ret = next((r for r in stop_rets if stop_del_calls and 0 < r - stop_del_calls[0] <= 0x20), None)
    if len(stop_del_calls) != 1 or stop_hit_ret is None:
        raise RuntimeError("keepAlives.stopLocked: expected 1 mapdelete_faststr exit")
    sites.append(
        PatchSite(
            "cache-keepalive",
            "modelapiccpa.(*keepAlives).stopLocked -> clear keepalive telemetry on stop",
            VM_BASE + stop_hit_ret,
            stop_hit_ret,
            ret_bytes,
            encode_b(VM_BASE + stop_hit_ret, entry_clear_va),
        )
    )

    # 9. Expose CacheKeepalive on types.StatusLineData and populate it on BuildStatusLineData return.
    orig_sf = struct.pack("<QQ", orig_internal_name_va, orig_internal_type_va)
    patched_sf = struct.pack("<QQ", abi_name_va, int_type_va)
    if last_nm == "statusLineDataInternal" and bytes(data[last_slot_off : last_slot_off + 16]) != orig_sf:
        raise RuntimeError("types.StatusLineData trailing StructField has unexpected Name/Typ pointers")
    sites.append(
        PatchSite(
            "cache-keepalive",
            'types.StatusLineData -> map trailing +0x148 slot to CacheKeepalive `json:"cache_keepalive,omitempty"`',
            VM_BASE + last_slot_off,
            last_slot_off,
            orig_sf,
            patched_sf,
        )
    )

    bsl_rets = find_rets(funcs["BuildStatusLineData"], cave_entry_offs)
    if len(bsl_rets) != 1:
        raise RuntimeError(f"store.BuildStatusLineData: expected 1 ret, found {len(bsl_rets)}")
    sites.append(
        PatchSite(
            "cache-keepalive",
            "store.BuildStatusLineData -> populate StatusLineData.CacheKeepalive from in-process telemetry",
            VM_BASE + bsl_rets[0],
            bsl_rets[0],
            ret_bytes,
            encode_b(VM_BASE + bsl_rets[0], sl_read_va),
        )
    )

    return tuple(sites)
