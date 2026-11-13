#!/usr/bin/env python3
"""Locate agy's embedded system prompt templates and reconcile them with `templates/`.

Each `embed.FS` file entry stores the name and contents as Go strings:
(name VA, name len, data VA, data len). The name string's VA plus its length is
a unique 16-byte key into the entry table, which yields the template's bytes.

`templates/v<version>/system_prompts/` holds only the templates we change in that agy
release: an empty file drops its section, and any other file is written into the
template's slot, padded with a Go comment. Every template not there keeps Google's text,
which this repo does not carry. The version comes from the binary itself, so a release
without its own directory is refused rather than patched with stale text.

`prompt_overrides.json` gives each changed template a `reason` and the `stock_sha256` of
Google's original. Patching from a clean backup stops unless the binary's template still
has that digest: upstream changed it, and the change needs a person's review. To read the
originals, dump them locally (`--dump`, or capture_prompt.py into `templates/v<ver>/stock/`,
which git ignores).

Run directly to print one template, or dump every embedded template:
    python3 prompt_templates.py identity.tmpl [--binary ~/.local/bin/agy.v1.5.3.orig]
    python3 prompt_templates.py --dump $TMPDIR/templates --binary ~/.local/bin/agy.v1.5.3.orig
    python3 prompt_templates.py skills.tmpl --digest --binary ~/.local/bin/agy.v1.5.8.orig
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
from typing import NamedTuple

VM_BASE = 0x100000000  # agy's Mach-O maps every section at VM_BASE + file offset
TEMPLATE_ROOT = b"google3/third_party/jetski/prompt/template_provider/templates/"
TEMPLATE_DIR = TEMPLATE_ROOT + b"system_prompts/"
TEMPLATES_ROOT = pathlib.Path(__file__).resolve().parent / "templates"  # one v<version>/ directory per agy release


class TemplateSlot(NamedTuple):
    name: str
    offset: int
    content: bytes


class Override(NamedTuple):
    name: str     # relative to system_prompts/, e.g. "helpers/async_termination_rule.tmpl"
    action: str   # "blank" or "replace"
    slot: TemplateSlot
    patched: bytes
    original: bytes | None  # Google's bytes; None when the slot holds neither them nor ours (only the backup reverts)


def find_template(data: bytes | bytearray, name: str) -> TemplateSlot:
    path = TEMPLATE_DIR + name.encode()
    entries = []
    pos = data.find(path)
    while pos != -1:
        entry = data.find(struct.pack("<QQ", VM_BASE + pos, len(path)))
        if entry != -1:
            entries.append(entry)
        pos = data.find(path, pos + 1)
    if len(entries) != 1:
        raise RuntimeError(f"Expected one embed.FS entry for {name}, found {len(entries)}")
    data_va, data_len = struct.unpack_from("<QQ", data, entries[0] + 16)
    offset = data_va - VM_BASE
    content = bytes(data[offset : offset + data_len])
    if b"\x00" in content:
        raise RuntimeError(f"embed.FS entry for {name} does not point at template text")
    return TemplateSlot(name, offset, content)


def iter_templates(data: bytes | bytearray) -> list[TemplateSlot]:
    """Every file in the template `embed.FS`, walked outward from identity.tmpl's 48-byte entry."""
    anchor = find_template(data, "identity.tmpl")
    anchor_name = TEMPLATE_DIR + b"identity.tmpl"
    first = data.find(struct.pack("<QQQ", VM_BASE + data.find(anchor_name), len(anchor_name), VM_BASE + anchor.offset))
    slots = []
    for step in (-48, 48):
        entry = first if step > 0 else first - 48
        while True:
            name_va, name_len, data_va, data_len = struct.unpack_from("<QQQQ", data, entry)
            if not 0 < name_len < 512 or not VM_BASE <= name_va < VM_BASE + len(data):
                break
            name = bytes(data[name_va - VM_BASE : name_va - VM_BASE + name_len])
            if not name.startswith(TEMPLATE_ROOT):
                break
            if data_len:
                content = bytes(data[data_va - VM_BASE : data_va - VM_BASE + data_len])
                slots.append(TemplateSlot(name[len(TEMPLATE_ROOT):].decode(), data_va - VM_BASE, content))
            entry += step
    return sorted(slots)


def comment_padding(length: int) -> bytes:
    """`length` bytes that render to nothing; spaces when too short for a Go comment."""
    if length < 12:
        return b" " * length
    return b"{{- /*" + b" " * (length - 12) + b"*/ -}}"


def fill_slot(name: str, text: bytes, slot_length: int) -> bytes:
    """`text` padded to exactly `slot_length` bytes; empty text blanks the slot."""
    if len(text) > slot_length:
        raise RuntimeError(f"{name}: replacement is {len(text)}B but the slot holds {slot_length}B")
    if not text and slot_length < 12:
        raise RuntimeError(f"{name}: slot too small to blank ({slot_length}B)")
    return text + comment_padding(slot_length - len(text))


def version_dir(version: str) -> pathlib.Path:
    path = TEMPLATES_ROOT / f"v{version}"
    if not path.is_dir():
        raise RuntimeError(
            f"No templates/v{version}/ for agy v{version}. Create it: `probe_agy.py rehearse` carries the previous "
            f"version's changes over when Google's originals are unchanged; otherwise dump them "
            f"(prompt_templates.py --dump templates/v{version}/stock --binary <new .orig>) and review each change."
        )
    return path


def stock_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def resolve_overrides(data: bytes | bytearray, version: str, strict: bool = False) -> list[Override]:
    """The slots that `templates/v<version>/system_prompts/` changes.

    `strict` (patching from a clean backup) demands every changed slot still hold Google's
    original, by its `stock_sha256`. Otherwise (inspecting a live binary) a slot that holds
    neither the original nor our text is reported with `original=None`, an unknown state.
    """
    root = version_dir(version)
    desired_dir, manifest = root / "system_prompts", root / "prompt_overrides.json"
    entries = json.loads(manifest.read_text()).get("templates", {}) if manifest.exists() else {}
    files = sorted(p.relative_to(desired_dir).as_posix() for p in desired_dir.rglob("*.tmpl")) if desired_dir.is_dir() else []
    if missing := sorted(n for n in files if not entries.get(n, {}).get("reason") or not entries.get(n, {}).get("stock_sha256")):
        raise RuntimeError(f"Changed templates need a `reason` and a `stock_sha256` in {manifest}: {missing}")
    if stale := sorted(set(entries) - set(files)):
        raise RuntimeError(f"{manifest} lists templates that system_prompts/ does not change: {stale}")

    overrides = []
    for name in files:
        desired, slot = (desired_dir / name).read_bytes(), find_template(data, name)
        is_stock = stock_digest(slot.content) == entries[name]["stock_sha256"]
        if strict and not is_stock:
            raise RuntimeError(
                f"{name}: Google's template in this binary is not the one system_prompts/{name} was written against "
                f"(stock_sha256 in {manifest}). Dump it, review the change, then update the file and its digest."
            )
        patched = fill_slot(name, desired.rstrip(b"\n"), len(slot.content))
        action = "blank" if not desired.strip() else "replace"
        overrides.append(Override(name, action, slot, patched, slot.content if is_stock else None))
    return overrides


def main() -> int:
    ap = argparse.ArgumentParser(description="Print or dump the templates embedded in an agy binary.")
    ap.add_argument("name", nargs="?", help="System prompt template to print, e.g. identity.tmpl")
    ap.add_argument("--dump", type=pathlib.Path, metavar="DIR", help="Write every embedded template under DIR")
    ap.add_argument("--digest", action="store_true", help="Print the template's stock_sha256 for prompt_overrides.json")
    ap.add_argument("--binary", type=pathlib.Path, default=pathlib.Path.home() / ".local/bin/agy")
    args = ap.parse_args()
    data = args.binary.read_bytes()
    if args.dump:
        for slot in iter_templates(data):
            dest = args.dump / slot.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(slot.content)
            print(f"{len(slot.content):6,}  {slot.name}")
    elif args.name and args.digest:
        print(stock_digest(find_template(data, args.name).content))
    elif args.name:
        print(find_template(data, args.name).content.decode())
    else:
        ap.error("give a template name or --dump DIR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
