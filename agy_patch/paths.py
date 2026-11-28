"""Filesystem paths and metadata cache helpers for agy-neo."""

from __future__ import annotations

import json
import pathlib

HOME = pathlib.Path.home()
REPO = pathlib.Path(__file__).resolve().parent.parent
GEMINI_WRAPPER_TARGET = HOME / ".gemini/bin/agy"
DEFAULT_BINARIES: tuple[pathlib.Path, ...] = (HOME / ".local/bin/agy", GEMINI_WRAPPER_TARGET)
HUB_WRAPPER_SOURCE = REPO / "hub-wrapper.sh"


def rendered_wrapper() -> bytes:
    """hub-wrapper.sh bytes for installation at ~/.gemini/bin/agy."""
    return HUB_WRAPPER_SOURCE.read_bytes()


STATUSLINE_SOURCE = REPO / "statusline.sh"
STATUSLINE_TARGET = HOME / ".gemini/antigravity-cli/statusline.sh"
TITLE_SOURCE = REPO / "title.sh"
TITLE_TARGET = HOME / ".gemini/antigravity-cli/title.sh"
AGY_NEO_CONF_SOURCE = REPO / "agy-neo.conf"
AGY_NEO_CONF_TARGET = HOME / ".gemini/antigravity-cli/agy-neo.conf"

SETTINGS_PATH = HOME / ".gemini/antigravity-cli/settings.json"
CACHE_DIR = REPO / ".cache"
META_CACHE_PATH = CACHE_DIR / "binary_meta.json"
SHAPES_PATH = REPO / "site_shapes.json"


def _load_meta_cache() -> dict:
    try:
        if META_CACHE_PATH.exists():
            return json.loads(META_CACHE_PATH.read_text())
    except Exception:
        pass
    return {"files": {}, "pclntab": {}}


def _save_meta_cache(cache: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = META_CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, indent=2) + "\n")
        tmp.replace(META_CACHE_PATH)
    except Exception:
        pass
