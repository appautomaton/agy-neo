"""Mach-O parsing, Go ABI reflection helpers, and ARM64 instruction encoders/decoders."""

from __future__ import annotations

import struct
from typing import NamedTuple

VM_BASE = 0x100000000
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
GOPCLN_MAGIC_120 = 0xFFFFFFF1

NOP = bytes.fromhex("1f2003d5")
LIPGLOSS_COPY_LOOP_X5_X4_ORIG = bytes.fromhex(
    "580180d2b044c1ac904481acb044c1ac904481ac180700d178ffffb5b90040f9990000f9"
)

# `ldr Xt, [Xn, #imm]` with the offset masked out. Struct fields move between releases (v1.5.6 grew
# ConversationModel by 0x20 and the store's model by 0x158), so an anchor that loads a field should
# match the load, not the field's offset.
LDR_X_ANY_OFFSET = 0xFFC003FF


class PatchSite(NamedTuple):
    domain: str
    name: str
    va: int
    offset: int
    original: bytes | None  # None when variable bytes (e.g. external bl) require custom matcher
    patched: bytes


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


def encode_b_cond(pc_va: int, target_va: int, cond: int) -> bytes:
    """Encode a 32-bit ARM64 PC-relative `b.<cond>` instruction."""
    delta = target_va - pc_va
    if delta % 4 != 0:
        raise ValueError(f"Unaligned b.cond target: {hex(pc_va)} -> {hex(target_va)}")
    return struct.pack("<I", 0x54000000 | (((delta // 4) & 0x7FFFF) << 5) | cond)


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
    data: bytes | bytearray,
    func_bounds: tuple[int, int],
    span: tuple[int, int],
    label: str,
    ignore: tuple[int, ...] = (),
) -> None:
    """Refuse a code cave that any branch from elsewhere in its function can reach."""
    start, end = func_bounds
    for off in range(start, end, 4):
        if span[0] <= off < span[1] or off in ignore:
            continue
        target = branch_target(struct.unpack_from("<I", data, off)[0], off)
        if target is not None and span[0] <= target < span[1]:
            raise RuntimeError(f"{label}: {hex(VM_BASE + off)} branches into it at {hex(VM_BASE + target)}")


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


def _adrp_add_at(data: bytes | bytearray, off: int, rd: int) -> int | None:
    """Target VA of `adrp xR; add xR, xR, #lo` at `off`, else None."""
    w0, w1 = struct.unpack_from("<II", data, off)
    if w0 & 0x9F00001F != 0x90000000 | rd or w1 & 0xFFC003FF != 0x91000000 | (rd << 5) | rd:
        return None
    return decode_adrp_add(data, off)


def _slice_loads(data: bytes | bytearray, bounds: tuple[int, int]) -> list[tuple[int, int]]:
    """(offset, global VA) of every `adrp x27; add x27, x27, #lo; ldp xA, xB, [x27]` in `bounds`."""
    return [
        (o, va)
        for o in range(bounds[0], bounds[1] - 8, 4)
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
    return struct.pack(
        "<II",
        0x914003E0 | ((sp_off >> 12) << 10) | rd,
        0x91000000 | ((sp_off & 0xFFF) << 10) | (rd << 5) | rd,
    )


def _decode_x27_sp_add(data: bytes | bytearray, off: int) -> tuple[int, int] | None:
    """Decode `add x27, sp, #imm` (4B) or `add x27, sp, #lo; add x27, x27, #hi, lsl #12` (8B) -> (size, sp_off)."""
    w0 = struct.unpack_from("<I", data, off)[0]
    if w0 & 0xFFC003FF == 0x910003FB:  # add x27, sp, #lo
        lo = (w0 >> 10) & 0xFFF
        w1 = struct.unpack_from("<I", data, off + 4)[0]
        if w1 & 0xFFC003FF == 0x9140037B:  # add x27, x27, #hi, lsl #12
            return 8, (((w1 >> 10) & 0xFFF) << 12) + lo
        return 4, lo
    dec = _decode_sp_add(data, off)
    if dec is not None and dec[1] == 27:
        return dec[0], dec[2]
    return None


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


def _frame_size(data: bytes | bytearray, bounds: tuple[int, int]) -> int:
    """The frame a Go function reserves (`sub x20, sp, #frame` in its prologue)."""
    for off in range(bounds[0], bounds[0] + 32, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if w & 0xFFC003FF == 0xD10003F4:
            return (w >> 10) & 0xFFF
    raise RuntimeError(f"No `sub x20, sp, #frame` prologue at {hex(VM_BASE + bounds[0])}")


def _find_all(data: bytes | bytearray, needle: bytes, bounds: tuple[int, int] | None = None) -> list[int]:
    lo, hi = bounds if bounds is not None else (0, len(data))
    hits, i = [], data.find(needle, lo, hi)
    while i != -1:
        hits.append(i)
        i = data.find(needle, i + 1, hi)
    return hits


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


def _section_file_bounds(data: bytes | bytearray, segname: str, sectname: str) -> tuple[int, int]:
    """File offsets `[start, end)` of Mach-O section `(segname, sectname)` (non-zerofill)."""
    want_seg, want_sec = segname.encode("ascii"), sectname.encode("ascii")
    pos = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_SEGMENT_64 and bytes(data[pos + 8 : pos + 24]).rstrip(b"\x00") == want_seg:
            for i in range(struct.unpack_from("<I", data, pos + 64)[0]):
                sp = pos + 72 + i * 80
                if bytes(data[sp : sp + 16]).rstrip(b"\x00") == want_sec:
                    _, size, off = struct.unpack_from("<QQI", data, sp + 32)
                    if off > 0 and size > 0:
                        return off, off + size
        pos += cmdsize
    raise RuntimeError(f"Mach-O section ({segname}, {sectname}) not found")


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


def _noptrbss_bounds(data: bytes | bytearray) -> tuple[int, int]:
    """Virtual address bounds `[start_va, end_va)` of Mach-O `__DATA,__noptrbss`."""
    pos = 32
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_SEGMENT_64:
            for i in range(struct.unpack_from("<I", data, pos + 64)[0]):
                sect = pos + 72 + i * 80
                if bytes(data[sect : sect + 16]).rstrip(b"\x00") == b"__noptrbss":
                    addr, size = struct.unpack_from("<QQ", data, sect + 32)
                    return addr, addr + size
        pos += cmdsize
    raise RuntimeError("Mach-O __noptrbss section not found")


def _read_abi_name(data: bytes | bytearray, off: int) -> tuple[int, str, str]:
    """Decode a Go `internal/abi.Name` at file offset `off` -> (hdr_flags, name, tag)."""
    hdr = data[off]
    pos = off + 1
    ln = shift = 0
    while True:
        b = data[pos]
        pos += 1
        ln |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    name = bytes(data[pos : pos + ln]).decode("utf-8", "replace")
    pos += ln
    tag = ""
    if hdr & 0x02:
        tln = shift = 0
        while True:
            b = data[pos]
            pos += 1
            tln |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        tag = bytes(data[pos : pos + tln]).decode("utf-8", "replace")
    return hdr, name, tag


def _go_types_base(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> int:
    """Recover `moduledata.types` file offset from `tea.RequestBackgroundColor`."""
    go_type = _section_file_bounds(data, "__DATA_CONST", "__go_type")
    rbc = funcs["RequestBackgroundColor"][0]
    bg_msg_va = decode_adrp_add(data, rbc)
    bg_name = b"*tea.backgroundColorMsg"
    bg_rec = [i - 2 for i in _find_all(data, bg_name, go_type) if data[i - 1] == len(bg_name)]
    if len(bg_rec) != 1:
        raise RuntimeError("tea.backgroundColorMsg type name not found")
    return bg_rec[0] - struct.unpack_from("<i", data, bg_msg_va - VM_BASE + 40)[0]


def go_type_descriptor(data: bytes | bytearray, name: str, types_base: int) -> int:
    """Return the file offset of the zero-size struct type whose abi.Type.Str names `name`."""
    go_type = _section_file_bounds(data, "__DATA_CONST", "__go_type")
    raw = name.encode()
    records = [i - 2 for i in _find_all(data, raw, go_type) if data[i - 1] == len(raw)]
    found = []
    for rec in records:
        name_off = struct.pack("<i", rec - types_base)
        for i in _find_all(data, name_off, go_type):
            desc = i - 40
            if desc % 8 == 0 and struct.unpack_from("<Q", data, desc)[0] == 0 and data[desc + 23] & 0x1F == 25:
                found.append(desc)
    if len(found) != 1:
        raise RuntimeError(f"Expected one zero-size struct type named {name}, found {len(found)}")
    return found[0]


def _go_struct_type(
    data: bytes | bytearray, star_name: str, types_base: int
) -> tuple[int, int, int, list[tuple[int, str, int, int, int]]]:
    """Locate a Go `abi.StructType` named `star_name` (e.g. `*types.StatusLineData`).

    Returns `(desc_off, size, ptrbytes, [(slot_off, field_name, fn_va, ft_va, byte_off), ...])`.
    """
    go_type = _section_file_bounds(data, "__DATA_CONST", "__go_type")
    raw = star_name.encode("utf-8")
    matches = []
    for i in _find_all(data, raw, go_type):
        if data[i - 1] == len(raw):
            rec = i - 2
            noff = struct.pack("<i", rec - types_base)
            for p in _find_all(data, noff, go_type):
                desc = p - 40
                if desc >= types_base and desc % 8 == 0:
                    sz, ptrb, _, tflag, _, _, kind = struct.unpack_from("<QQIBBBB", data, desc)
                    if (kind & 0x1F) == 25 and (tflag & 0x02):
                        matches.append((desc, sz, ptrb))
    if len(matches) != 1:
        raise RuntimeError(f"Expected one struct type {star_name}, found {len(matches)}")
    desc, sz, ptrb = matches[0]
    _, fptr_va, flen, _ = struct.unpack_from("<QQQQ", data, desc + 48)
    foff = fptr_va - VM_BASE
    fields: list[tuple[int, str, int, int, int]] = []
    for idx in range(flen):
        slot_off = foff + idx * 24
        fn_va, ft_va, byte_off = struct.unpack_from("<QQQ", data, slot_off)
        _, fnm, _ = _read_abi_name(data, fn_va - VM_BASE)
        fields.append((slot_off, fnm, fn_va, ft_va, byte_off))
    return desc, sz, ptrb, fields
