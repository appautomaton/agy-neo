"""Stock-shape verification, binary inspection, apply/revert operations, config management, and CLI entrypoint."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess

from .asm import PatchSite, _text_section
from .paths import (
    AGY_NEO_CONF_SOURCE,
    AGY_NEO_CONF_TARGET,
    DEFAULT_BINARIES,
    GEMINI_WRAPPER_TARGET,
    HUB_WRAPPER_SOURCE,
    REPO,
    SETTINGS_PATH,
    SHAPES_PATH,
    STATUSLINE_SOURCE,
    STATUSLINE_TARGET,
    TITLE_SOURCE,
    TITLE_TARGET,
    _load_meta_cache,
    _save_meta_cache,
    rendered_wrapper,
)
from .registry import resolve_patch_sites


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
    if not path.exists():
        return "unknown"
    with path.open("rb") as f:
        is_wrapper = f.read(2) == b"#!"
    if not is_wrapper:
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
    if ver != "unknown" and not is_wrapper:
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


def _read_neo_conf(path: pathlib.Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.exists():
        return vals
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = (p.strip() for p in line.split("=", 1))
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        else:
            v = v.split(" #", 1)[0].split("\t#", 1)[0].rstrip()
        vals[k] = v
    return vals


def _ensure_neo_conf() -> pathlib.Path:
    """Install default agy-neo.conf on first run, or append AUTO_COMPACT_WINDOW if missing."""
    conf_path = pathlib.Path(os.environ.get("AGY_NEO_CONFIG") or AGY_NEO_CONF_TARGET)
    if not conf_path.exists():
        if AGY_NEO_CONF_SOURCE.exists():
            conf_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_cfg = conf_path.with_suffix(".conf.tmp")
            shutil.copy2(AGY_NEO_CONF_SOURCE, tmp_cfg)
            tmp_cfg.replace(conf_path)
            print(f"[cfg]  Installed default config {AGY_NEO_CONF_SOURCE} -> {conf_path}")
        return conf_path
    existing = _read_neo_conf(conf_path)
    if "AUTO_COMPACT_WINDOW" not in existing and AGY_NEO_CONF_SOURCE.exists():
        src_text = AGY_NEO_CONF_SOURCE.read_text()
        marker = "# Auto-compaction threshold"
        if marker in src_text:
            block = "\n" + src_text[src_text.index(marker) :].rstrip() + "\n"
        else:
            block = "\nAUTO_COMPACT_WINDOW=512K\n"
        cur = conf_path.read_text()
        tmp_cfg = conf_path.with_suffix(".conf.tmp")
        tmp_cfg.write_text(cur.rstrip() + "\n" + block)
        tmp_cfg.replace(conf_path)
        print(f"[cfg]  Added AUTO_COMPACT_WINDOW=512K to {conf_path}")
    return conf_path


def set_context_window(spec: str) -> None:
    """Set AUTO_COMPACT_WINDOW in agy-neo.conf (exported as AGY_CLI_AUTO_COMPACT_OVERRIDE)."""
    cleaned = spec.strip()
    low = cleaned.lower()
    if low in ("default", "off", "none", "0"):
        val = "off"
    else:
        if not re.fullmatch(r"\d+(?:\.\d+)?[kKmM%]|\d+", cleaned):
            raise SystemExit(
                f"Invalid --set-window value {spec!r}: expected token count (700000), K/M (512K, 0.5M), % (80%), or off/Default"
            )
        val = cleaned
    conf_path = _ensure_neo_conf()
    lines = conf_path.read_text().splitlines() if conf_path.exists() else []
    replaced = False
    out: list[str] = []
    for line in lines:
        if line.strip().startswith("AUTO_COMPACT_WINDOW="):
            out.append(f"AUTO_COMPACT_WINDOW={val}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"AUTO_COMPACT_WINDOW={val}")
    tmp_cfg = conf_path.with_suffix(".conf.tmp")
    tmp_cfg.write_text("\n".join(out) + "\n")
    tmp_cfg.replace(conf_path)
    print(f"[cfg]  Updated {conf_path}: AUTO_COMPACT_WINDOW={val}")


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
        print(f"Settings : {SETTINGS_PATH} -> model={settings.get('model')!r}")
    conf_path = pathlib.Path(os.environ.get("AGY_NEO_CONFIG") or AGY_NEO_CONF_TARGET)
    conf = _read_neo_conf(conf_path)
    pick = lambda env_k, cfg_k, dflt: os.environ.get(env_k) or conf.get(cfg_k) or dflt
    conf_label = str(conf_path) if conf_path.exists() else f"{conf_path} (defaults)"
    print(
        f"Cache    : {conf_label} -> engine=native(modelapiccpa), keepalive={pick('AGY_CACHE_KEEPALIVE', 'CACHE_KEEPALIVE', 'on')}, "
        f"ttl={pick('AGY_CACHE_TTL', 'CACHE_TTL', '5m')}, max_touches={pick('AGY_CACHE_MAX_TOUCHES', 'CACHE_MAX_TOUCHES', '4')}"
    )
    env_override = os.environ.get("AGY_CLI_AUTO_COMPACT_OVERRIDE")
    win_effective = env_override if env_override is not None else conf.get("AUTO_COMPACT_WINDOW", "512K")
    print(f"Window   : {conf_label} -> auto_compact={win_effective!r} (env AGY_CLI_AUTO_COMPACT_OVERRIDE={env_override!r})")


def main(description: str | None = None) -> int:
    parser = argparse.ArgumentParser(description=description or __doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="Show current binary and settings status")
    group.add_argument("--apply", action="store_true", help="Rebuild from the clean backup with every TUI site and prompt template applied")
    group.add_argument("--revert", action="store_true", help="Revert the binary patch to original bytes")
    group.add_argument(
        "--accept-shapes",
        action="store_true",
        help="Record the stock code shapes of a clean binary as reviewed (site_shapes.json), then show status",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Print resolved virtual addresses for each site")
    parser.add_argument(
        "--set-window",
        metavar="SPEC",
        help="Set AUTO_COMPACT_WINDOW in agy-neo.conf (e.g. 512K, 800K, 0.5M, 80%%, 700000, or off)",
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
        for src, dst in ((STATUSLINE_SOURCE, STATUSLINE_TARGET), (TITLE_SOURCE, TITLE_TARGET)):
            if src.exists() and (not dst.exists() or src.read_bytes() != dst.read_bytes()):
                dst.parent.mkdir(parents=True, exist_ok=True)
                tmp_sh = dst.with_suffix(".sh.tmp")
                shutil.copy2(src, tmp_sh)
                tmp_sh.replace(dst)
                print(f"[sync] Atomically synced {src} -> {dst}")
        _ensure_neo_conf()
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
