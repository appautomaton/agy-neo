#!/usr/bin/env python3
"""Version-adaptive patcher for agy (darwin/arm64): TUI/Cortex sites and system prompt templates.

TUI & Cortex sites: parses the Mach-O __lrodata_gopcln symbol table with per-group symbol
resolution, anchors each site via invariant instruction patterns, and computes PC-relative
ARM64 displacements automatically across versions.

Prompt templates: writes every file in templates/v<version>/system_prompts/, the templates we
change, for the version the binary reports, once each original matches its recorded digest
(prompt_templates.py).

Every --apply rebuilds from the clean agy.v<version>.orig backup and re-signs the binary.
"""

from __future__ import annotations

import sys

from agy_patch import (
    AGY_NEO_CONF_SOURCE,
    AGY_NEO_CONF_TARGET,
    CACHE_DIR,
    DEFAULT_BINARIES,
    GEMINI_BAND_DARK,
    GEMINI_BAND_LIGHT,
    GEMINI_BLUE,
    GEMINI_PURPLE,
    GEMINI_ROSE,
    GEMINI_WRAPPER_TARGET,
    GOPCLN_MAGIC_120,
    GROUP_REQUIRED_SYMBOLS,
    GROUP_SPECS,
    HOME,
    HUB_WRAPPER_SOURCE,
    LC_SEGMENT_64,
    LDR_X_ANY_OFFSET,
    LIPGLOSS_COPY_LOOP_X5_X4_ORIG,
    META_CACHE_PATH,
    MH_MAGIC_64,
    NOP,
    OPTIONAL_SYMBOLS,
    PENDING_VERBS,
    REPO,
    SETTINGS_PATH,
    SHAPES_PATH,
    SPINNER_BREATH,
    SPINNER_STOCK,
    STATUSLINE_SOURCE,
    STATUSLINE_TARGET,
    SWARM_MARK,
    TARGET_SYMBOLS,
    TITLE_SOURCE,
    TITLE_TARGET,
    TOOL_MARKS,
    VM_BASE,
    PatchSite,
    _breath_frame,
    accept_shapes,
    apply_patch,
    assert_unreachable,
    backup_path_for,
    branch_target,
    codesign_adhoc,
    decode_adrp_add,
    decode_branch_target,
    detect_binary_version,
    encode_adr,
    encode_adrp,
    encode_adrp_add,
    encode_b,
    encode_b_cond,
    encode_b_eq,
    encode_b_ne,
    encode_bl,
    find_unique_anchor,
    find_unique_words,
    fold_lipgloss_copy_x5_x4,
    go_type_descriptor,
    inspect_binary,
    ldr_x,
    locate_symbols,
    locate_target_functions,
    print_status,
    rendered_wrapper,
    require_symbols,
    resolve_patch_sites,
    resolve_site_groups,
    revert_patch,
    set_context_window,
    sha256_file,
    site_state,
    stock_shape,
    stock_shapes,
    unreviewed_shapes,
)
from agy_patch.ops import main as _ops_main


def main() -> int:
    return _ops_main(description=__doc__)


if __name__ == "__main__":
    sys.exit(main())
