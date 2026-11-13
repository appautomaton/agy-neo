#!/usr/bin/env python3
"""Mach-O Go __lrodata_gopcln symbol, call-graph, and string literal inspector for agy (darwin/arm64).

Eliminates ad-hoc binary scraping by parsing the Go 1.20+ pclntab directly to:
  1. List matching Go function symbols with virtual addresses, file offsets, and byte sizes.
  2. Decode direct ARM64 `BL` call targets (`--calls`).
  3. Extract Go string literals loaded via `ADRP + ADD` (+ optional `MOV #len`) pairs (`--strings`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import struct
import sys
from typing import NamedTuple


VM_BASE = 0x100000000
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
GOPCLN_MAGIC_120 = 0xFFFFFFF1
DEFAULT_BINARY = pathlib.Path.home() / ".local/bin/agy"
CACHE_DIR = pathlib.Path(__file__).resolve().parent / ".cache"


class Section(NamedTuple):
    name: str
    addr: int
    size: int
    offset: int


class GoFunc(NamedTuple):
    name: str
    va: int
    file_off: int
    size: int


def parse_macho_sections(data: bytes | memoryview) -> list[Section]:
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise RuntimeError(f"Not a 64-bit Mach-O binary (magic={hex(magic)})")

    pos = 32
    sections: list[Section] = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            sect_pos = pos + 72
            for _ in range(nsects):
                sectname = bytes(data[sect_pos : sect_pos + 16]).rstrip(b"\x00").decode("ascii", "replace")
                addr, size, offset = struct.unpack_from("<QQI", data, sect_pos + 32)
                sections.append(Section(sectname, addr, size, offset))
                sect_pos += 80
        pos += cmdsize
    return sections


def va_to_foff(sections: list[Section], va: int) -> int | None:
    for s in sections:
        if s.addr <= va < s.addr + s.size:
            return s.offset + (va - s.addr)
    return None


def parse_gopclntab(data: bytes) -> tuple[list[Section], list[GoFunc], dict[int, str]]:
    sections = parse_macho_sections(data)
    hdr_hash = hashlib.blake2b(data[:4096], digest_size=8).hexdigest()
    cache_file = CACHE_DIR / f"pclntab-{len(data)}-{hdr_hash}.json"
    if cache_file.exists():
        try:
            raw_funcs = json.loads(cache_file.read_text())
            funcs = [GoFunc(name=n, va=va, file_off=fo, size=sz) for n, va, fo, sz in raw_funcs]
            addr_to_name = {f.va: f.name for f in funcs}
            return sections, funcs, addr_to_name
        except Exception:
            pass

    text_sec = next((s for s in sections if s.name == "__text"), None)
    pcln_sec = next((s for s in sections if s.name in ("__lrodata_gopcln", "__gopclntab")), None)
    if text_sec is None or pcln_sec is None:
        raise RuntimeError("Missing __text or __lrodata_gopcln section")

    gopcln_off = pcln_sec.offset
    magic = struct.unpack_from("<I", data, gopcln_off)[0]
    if magic != GOPCLN_MAGIC_120:
        raise RuntimeError(f"Unsupported Go pclntab magic: {hex(magic)}")

    nfunctab = struct.unpack_from("<Q", data, gopcln_off + 8)[0]
    text_start = struct.unpack_from("<Q", data, gopcln_off + 24)[0] or text_sec.addr
    funcnametab_off = gopcln_off + struct.unpack_from("<Q", data, gopcln_off + 32)[0]
    functab_off = gopcln_off + struct.unpack_from("<Q", data, gopcln_off + 64)[0]
    text_file_base = text_sec.offset

    funcs = []
    addr_to_name = {}

    for i in range(nfunctab):
        entry_off, fdata_off = struct.unpack_from("<II", data, functab_off + i * 8)
        name_rel = struct.unpack_from("<i", data, functab_off + fdata_off + 4)[0]
        name_start = funcnametab_off + name_rel
        name_end = data.find(b"\x00", name_start)
        name = data[name_start:name_end].decode("utf-8", "replace")
        next_entry_off = struct.unpack_from("<I", data, functab_off + (i + 1) * 8)[0]
        va = text_start + entry_off
        size = next_entry_off - entry_off
        fn = GoFunc(name=name, va=va, file_off=text_file_base + entry_off, size=size)
        funcs.append(fn)
        addr_to_name[va] = name

    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = cache_file.with_suffix(".tmp")
        tmp.write_text(json.dumps([[f.name, f.va, f.file_off, f.size] for f in funcs]))
        tmp.replace(cache_file)
    except Exception:
        pass

    return sections, funcs, addr_to_name


def extract_calls_and_strings(
    data: bytes,
    sections: list[Section],
    fn: GoFunc,
    addr_to_name: dict[int, str],
) -> tuple[list[str], list[tuple[int, str]]]:
    code = data[fn.file_off : fn.file_off + fn.size]
    calls: list[str] = []
    strings_out: list[tuple[int, str]] = []

    n_insns = len(code) // 4
    insns = struct.unpack_from(f"<{n_insns}I", code, 0)

    for idx, insn in enumerate(insns):
        pc = fn.va + idx * 4
        # Direct BL instruction
        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x03FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            callee = pc + (imm26 << 2)
            cname = addr_to_name.get(callee)
            if cname and not cname.startswith("runtime."):
                calls.append(cname)

        # ADRP + ADD pair (Go string or slice literal pointer load)
        if (insn & 0x9F000000) == 0x90000000 and idx + 1 < n_insns:
            insn2 = insns[idx + 1]
            rd1 = insn & 0x1F
            rd2 = insn2 & 0x1F
            rn2 = (insn2 >> 5) & 0x1F
            if (insn2 & 0xFF800000) == 0x91000000 and rd1 == rn2:
                immlo = (insn >> 29) & 0x3
                immhi = (insn >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = (pc & ~0xFFF) + (imm << 12)
                add_imm = (insn2 >> 10) & 0xFFF
                if (insn2 >> 22) & 1:
                    add_imm <<= 12
                target_va = page + add_imm
                foff = va_to_foff(sections, target_va)
                if foff is None:
                    continue

                # Look in neighboring instructions for `MOVZ reg, #len` (0xD2800000)
                explicit_len: int | None = None
                for k in list(range(idx + 2, min(idx + 6, n_insns))) + list(range(max(0, idx - 2), idx)):
                    ik = insns[k]
                    if (ik & 0xFF800000) == 0xD2800000 and ((ik >> 21) & 0x3) == 0:
                        cand = (ik >> 5) & 0xFFFF
                        if 1 <= cand <= 240:
                            explicit_len = cand
                            break

                length = explicit_len or 48
                if 0 <= foff <= len(data) - length:
                    raw = data[foff : foff + length]
                    if explicit_len is not None:
                        if all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                            strings_out.append((pc, raw.decode("ascii")))
                    else:
                        ascii_run = bytearray()
                        for b in raw:
                            if 32 <= b < 127:
                                ascii_run.append(b)
                            else:
                                break
                        if len(ascii_run) >= 4:
                            strings_out.append((pc, ascii_run.decode("ascii")))

    return list(dict.fromkeys(calls)), strings_out


KNOWN_PALETTE_ROLES: dict[int, str] = {
    0x000: "Background (terminal: nil)",
    0x010: "Primary Foreground (terminal: nil)",
    0x020: "Primary Accent: Spinner Shimmer & TUI Selector (orig: ANSI '12', patched: nil Primary Fg)",
    0x030: "Border / Muted Rule (ANSI '8')",
    0x040: "User Prompt (orig: ANSI '4', patched: nil Primary Fg)",
    0x050: "Success / Completed Tool Dot `●` / Diff Add (ANSI '2' Green)",
    0x060: "Secondary Success / Diff Add (ANSI '2' Green)",
    0x070: "Diff Add Bg (terminal: nil)",
    0x080: "Diff Delete Bg (terminal: nil)",
    0x090: "Danger / Diff Delete Fg (ANSI '1' Red)",
    0x0A0: "Diff Context Bg (terminal: nil)",
    0x0B0: "Diff Context Fg (terminal: nil)",
    0x0C0: "Secondary Muted (ANSI '8' Gray)",
    0x0D0: "Warning / In-Action Tool Dot `●` / Patched Inline `code` (ANSI '3' Amber)",
    0x0E0: "Mode / Special Badge (ANSI '5' Magenta)",
    0x0F0: "Error / Failed Tool Dot `●` (ANSI '1' Red)",
    0x100: "Tertiary Warning (ANSI '3' Amber)",
    0x110: "CCI / Markdown Link `Styles[+0xf30]` (ANSI '4' Blue + Underline)",
    0x120: "Secondary / CoT Base (ANSI '7' Silver)",
    0x130: "Dim / Canceled Tool Dot `●` / Shimmer Base (ANSI '8' Gray)",
}

KNOWN_OFFSET_ROLES: dict[int, str] = {
    0x0000: "UserPrompt (`> ...` in renderUserPrompt -> Patched Faint `> ` + Regular Primary Fg)",
    0x0288: "ToolName (`Bash`/`Edit`/`Read` in renderToolCallWithStatus -> Patched colorless Bold)",
    0x0510: "ToolArgs & CoT (`(xxx)` in renderToolCallWithStatus & `∴ Thought...` -> Patched Faint \\x1b[2m)",
    0x0798: "PrimaryText",
    0x0F30: "CCILink (`[text](file://...)` in restoreCCIPlaceholders -> ANSI '4' Blue + Underline)",
    0x1950: "RunningDot (Spinner shimmer shoulder -> Patched Primary Fg)",
    0x1BD8: "RunningLightPeak (Spinner shimmer peak -> Patched Primary Fg)",
    0x2370: "PromptChevron (`>` in live InputModel / PromptModel.promptChevron -> Patched Faint \\x1b[2m)",
    0x2B08: "HorizontalRule (`───` in renderUserPrompt -> ANSI '8' Gray)",
    0x3528: "SelectorActiveRow (`> /add-dir` & `/model` active item -> Patched Primary Fg + Bold)",
    0x37B0: "SelectorCursor (`>` in slash/picker menu -> Patched Primary Fg)",
    0x62E8: "Selection (mouse highlight in selectionState.highlight -> Patched Reverse \\x1b[7m)",
    0x74A0: "ToolDotCompleted (`●` completed in toolStatusIcon -> ANSI '2' Green)",
    0x7728: "ToolDotInAction (`●`/`○` pulsing in action in toolStatusIcon -> ANSI '3' Amber)",
    0x79B0: "ToolDotCanceled (`●` canceled in toolStatusIcon -> ANSI '8' Gray)",
    0x7C38: "ToolDotFailed (`●` failed/error in toolStatusIcon -> ANSI '1' Red)",
    0x88E0: "FooterKeyAccent (`↑/↓` / `enter` / `tab` -> Patched Primary Fg)",
    0x8B68: "FooterKeyBold (`↑/↓` / `enter` / `tab` bold badge -> Patched Primary Fg + Bold)",
}


def dump_tui_styles_and_palette(data: bytes, sections: list[Section], funcs: list[GoFunc]) -> None:
    fn_map = {f.name: f for f in funcs}
    ti = fn_map["google3/third_party/jetski/cli/types/types.init"]
    rs = fn_map["google3/third_party/jetski/cli/render/render.resolveStyles"]
    gs = fn_map["google3/third_party/jetski/cli/render/render.glamourStyleForScheme"]

    print(f"=== 1. types.ColorPalettes['terminal'] in {ti.name} @ {hex(ti.va)} ===")
    zero_loop = bytes.fromhex("a30080d25f7c81a85f7c81a85f7c81a85f7c81a8630400d163ffffb5")
    z_idx = data.find(zero_loop, ti.file_off, ti.file_off + ti.size)
    if z_idx != -1:
        # Decode stack color allocations preceding the zero loop
        sp_colors: dict[int, str] = {}
        scan_start = max(ti.file_off, z_idx - 0x180)
        for off in range(scan_start, z_idx - 16, 4):
            i1, i2, i3, i4, i5 = struct.unpack_from("<IIIII", data, off)
            if (i1 & 0x9F000000) == 0x90000000 and (i2 & 0xFF800000) == 0x91000000 and (i4 & 0xFC000000) == 0x94000000:
                pc = VM_BASE + off
                immlo = (i1 >> 29) & 3
                immhi = (i1 >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = (pc & ~0xFFF) + (imm << 12)
                add_imm = (i2 >> 10) & 0xFFF
                str_va = page + add_imm
                str_foff = va_to_foff(sections, str_va)
                slen = 2 if i3 == 0xB27F03E1 else 1
                sval = data[str_foff : str_foff + slen].decode("ascii", "replace") if str_foff else "?"
                if (i5 & 0xFFC003FF) == 0xF90003E0:
                    sp_off = ((i5 >> 10) & 0xFFF) * 8
                    sp_colors[sp_off] = sval
                else:
                    sp_colors[-1] = sval

        print(f"{'Slot':<10} {'Store VA':<14} {'Value':<12} {'Semantic Role'}")
        print("-" * 88)
        print(f"{'+0x000':<10} {'(zero_loop)':<14} {'nil':<12} {KNOWN_PALETTE_ROLES.get(0x000, '')}")
        print(f"{'+0x010':<10} {'(zero_loop)':<14} {'nil':<12} {KNOWN_PALETTE_ROLES.get(0x010, '')}")
        pos = z_idx + len(zero_loop)
        while pos < z_idx + len(zero_loop) + 0x110:
            i1, i2, i3, i4 = struct.unpack_from("<IIII", data, pos)
            if (i1 & 0xFFC003FF) == 0xF94003E2 and (i3 & 0xFFC003FF) == 0x910003FB:
                sp_src = ((i1 >> 10) & 0xFFF) * 8
                pal_dst = ((i3 >> 10) & 0xFFF) - 0x260
                val = "nil" if i4 == 0xA9007F7F else f"Color({sp_colors.get(sp_src, '?')!r})"
                print(f"+0x{pal_dst:03x}     {hex(VM_BASE + pos):<14} {val:<12} {KNOWN_PALETTE_ROLES.get(pal_dst, '')}")
                pos += 16
            elif (i1 & 0xFFC003FF) == 0x910003FB:
                pal_dst = ((i1 >> 10) & 0xFFF) - 0x260
                val = "nil" if i2 == 0xA9007F7F else f"Color({sp_colors.get(-1, '?')!r})"
                print(f"+0x{pal_dst:03x}     {hex(VM_BASE + pos):<14} {val:<12} {KNOWN_PALETTE_ROLES.get(pal_dst, '')}")
                pos += 8
            else:
                break

    print(f"\n=== 2. render.Styles (82 fields, 0x288B each) in {rs.name} @ {hex(rs.va)} ===")
    print(f"{'Idx':<5} {'Offset':<10} {'Resolve VA':<14} {'Palette Slot':<14} {'Role / Consumers'}")
    print("-" * 88)
    src_to_style: dict[int, tuple[int, int]] = {}
    pos = rs.file_off + 0x33E0
    field_idx = 0
    while pos < rs.file_off + 0x4600:
        if struct.unpack_from("<I", data, pos)[0] == 0xD2800158:
            d_val, s_val = 0, 0
            for back in range(pos - 16, pos, 4):
                bi = struct.unpack_from("<I", data, back)[0]
                rd, rn = bi & 0x1F, (bi >> 5) & 0x1F
                imm = ((bi >> 10) & 0xFFF) << (12 if ((bi >> 22) & 1) else 0)
                if (bi & 0xFF000000) == 0x91000000:
                    if rd == 4:
                        d_val = imm if rn == 31 else d_val + imm
                    if rd == 5:
                        s_val = imm if rn == 31 else s_val + imm
            if d_val >= 0xC868:
                src_to_style[s_val] = (field_idx, d_val - 0xC868)
                field_idx += 1
        pos += 4

    for off in range(rs.file_off + 0xF0, rs.file_off + 0x33E0, 4):
        insn = struct.unpack_from("<I", data, off)[0]
        if (insn & 0xFFC003FF) == 0x910003FB:
            imm = (insn >> 10) & 0xFFF
            if 0x580 <= imm <= 0x6B0 and (imm - 0x580) % 0x10 == 0:
                pal_off = imm - 0x580
                for k in range(off, min(off + 0x150, rs.file_off + 0x33E0), 4):
                    if struct.unpack_from("<I", data, k)[0] in (0xD2800158, 0xD2800298):
                        d_val = 0
                        for back in range(k - 28, k, 4):
                            bi = struct.unpack_from("<I", data, back)[0]
                            if (bi & 0xFF00001F) == 0x91000004:
                                rn = (bi >> 5) & 0x1F
                                imm2 = ((bi >> 10) & 0xFFF) << (12 if ((bi >> 22) & 1) else 0)
                                d_val = imm2 if rn == 31 else d_val + imm2
                        if d_val in src_to_style:
                            idx, st_off = src_to_style[d_val]
                            role = KNOWN_OFFSET_ROLES.get(st_off, "")
                            print(f"#{idx:<4} +0x{st_off:04x}   {hex(VM_BASE + off):<14} +0x{pal_off:03x}         {role}")
                            break

    print(f"\n=== 3. Glamour Inline Code (`Code.Color`) in {gs.name} @ {hex(gs.va)} ===")
    g_post = bytes.fromhex("a10200b4e0037cb2")
    g_idx = data.find(g_post, gs.file_off, gs.file_off + gs.size)
    if g_idx != -1:
        c_off = g_idx - 4
        (ldr_i,) = struct.unpack_from("<I", data, c_off)
        pal_slot = (((ldr_i >> 10) & 0xFFF) * 8) - 0x38
        print(f"  Check VA : {hex(VM_BASE + c_off)} -> reads palette[+0x{pal_slot:03x}]")
        print(f"  Load  VA : {hex(VM_BASE + c_off + 0x20)} -> reads palette[+0x{pal_slot:03x}]")



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default=DEFAULT_BINARY, help="Path to agy binary")
    parser.add_argument("-m", "--match", help="Substring to match against Go function symbol names")
    parser.add_argument("--calls", action="store_true", help="Print direct BL call targets inside matched functions")
    parser.add_argument("--strings", action="store_true", help="Print decoded ADRP+ADD string literals inside matched functions")
    parser.add_argument("--dedup-strings", action="store_true", help="Deduplicate repeated string literals within a function")
    parser.add_argument("--styles", action="store_true", help="Dump complete 20-slot ColorPalette, 82-field Styles, and Glamour Code.Color tables")
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of matched functions to display (default: 50)")
    args = parser.parse_args()

    data = args.binary.read_bytes()
    sections, funcs, addr_to_name = parse_gopclntab(data)

    if args.styles:
        dump_tui_styles_and_palette(data, sections, funcs)
        return 0
    if not args.match:
        parser.error("either --match (-m) or --styles is required")

    pattern = re.compile(args.match, re.IGNORECASE)
    matched = [f for f in funcs if pattern.search(f.name)]
    print(f"Matched {len(matched)} function(s) for {args.match!r} in {args.binary}:")

    for fn in matched[: args.limit]:
        print(f"\n=== {fn.name} @ {hex(fn.va)} (off {hex(fn.file_off)}, {fn.size}B) ===")
        if args.calls or args.strings:
            calls, strs = extract_calls_and_strings(data, sections, fn, addr_to_name)
            if args.calls and calls:
                print("  Calls:")
                for c in calls:
                    print(f"    -> {c}")
            if args.strings and strs:
                print("  Strings:")
                seen: set[str] = set()
                for pc, s in strs:
                    if not args.dedup_strings or s not in seen:
                        seen.add(s)
                        print(f"    [{hex(pc)}] {s!r}")

    if len(matched) > args.limit:
        print(f"\n... ({len(matched) - args.limit} more matched; pass --limit to increase)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
