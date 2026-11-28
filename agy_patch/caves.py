"""Shared `__TEXT` tail fill leaf slots and dead Halloween data-slot helpers."""

from __future__ import annotations

import struct

from .asm import VM_BASE, _slice_loads, _text_tail_cave

ELAPSED_CODE = 0x1E0         # executable leaf detours + effort matcher in __TEXT tail fill
LIGHT_LEAF_ROOM = 0x80       # bytes Site #49h's leaf may take before Site #50i's detours
GAP_LEAF_ROOM = 0x40         # bytes Site #49k's leaf may take before Site #49h's
CODE_THEME_LEAF_ROOM = 0xE0  # bytes Site #58b's adaptive light/dark code-theme leaves take before Site #49k's


def _elapsed_base(data: bytes | bytearray) -> int:
    """File offset of Site #50i's executable leaf detours at the end of the __TEXT fill."""
    fill, fill_end = _text_tail_cave(data)
    base = (fill_end - ELAPSED_CODE) & ~0xF
    if base < fill:
        raise RuntimeError(f"__TEXT fill ({fill_end - fill}B) has no room for elapsedSuffix's {ELAPSED_CODE}B detours")
    return base


def _light_detour_base(data: bytes | bytearray) -> int:
    """File offset of Site #49h's stage-color leaf, before Site #50i's detours."""
    fill, _ = _text_tail_cave(data)
    base = (_elapsed_base(data) - LIGHT_LEAF_ROOM) & ~0xF
    if base < fill:
        raise RuntimeError("the __TEXT fill has no room for the stage-color leaf")
    return base


def _gap_leaf_base(data: bytes | bytearray) -> int:
    """File offset of Site #49k's leaf, before Site #49h's stage-color leaf."""
    fill, _ = _text_tail_cave(data)
    base = (_light_detour_base(data) - GAP_LEAF_ROOM) & ~0xF
    if base < fill:
        raise RuntimeError("the __TEXT fill has no room for the pending gap's leaf")
    return base


def _code_theme_leaf_base(data: bytes | bytearray) -> int:
    """File offset of Site #58b's adaptive light/dark code-theme leaves, before Site #49k's."""
    fill, _ = _text_tail_cave(data)
    base = (_gap_leaf_base(data) - CODE_THEME_LEAF_ROOM) & ~0xF
    if base < fill:
        raise RuntimeError("the __TEXT fill has no room for the adaptive code-theme leaves")
    return base


def _halloween_logo_slices(data: bytes | bytearray, funcs: dict[str, tuple[int, int]]) -> list[tuple[int, int, int]]:
    """Return Halloween's two adjacent 14-row logo `[]string` slices as `[(ptr_va, len, hdr_va), ...]`."""
    rows: list[tuple[int, int, int]] = []
    seen_ptrs: set[int] = set()
    for _, va in _slice_loads(data, funcs["halloweenInit"]):
        ptr, n, cap = struct.unpack_from("<QQQ", data, va - VM_BASE)
        if n == cap == 14 and VM_BASE < ptr < VM_BASE + len(data) and ptr not in seen_ptrs:
            seen_ptrs.add(ptr)
            rows.append((ptr, n, va))
    rows.sort()
    if len(rows) != 2 or rows[0][0] + 16 * rows[0][1] != rows[1][0]:
        raise RuntimeError(f"halloween.init: expected two adjacent 14-row logo tables, found {rows}")
    return rows
