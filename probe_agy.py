#!/usr/bin/env python3
"""Probe an agy binary as it is used, on a loopback endpoint that spends no quota.

`rehearse` is the whole upgrade rehearsal in one command: it fetches a newer release (or takes
`--stock`), and on copies, never the installed binary, reports what upstream changed and whether
the patch still holds. It runs the three checks below, each against a loopback endpoint and an
isolated app data dir:

    wire    one print-mode turn per model ID; prints the request path and thinking config it sends
    tui     drives the TUI in a pty through a canned turn (two thoughts, an answer), `/model`, its
            context selector and `/context`; writes each screen as text plus its styled runs
    sites   compares every patch site of two clean binaries: patched bytes, and the stock code around
            them. A site whose bytes are derived from the binary always reads as clean, so this is
            what catches a struct field or frame slot that moved (references/context-window-patch.md §5.4)

`tui --against DIR` diffs the new snapshots against an earlier run, with versions, temp paths and
elapsed seconds masked. A pty cannot be opened inside the Claude Code sandbox; run `tui` outside it.

    python3 probe_agy.py rehearse
    python3 probe_agy.py wire  --binary /tmp/agy-new/agy
    python3 probe_agy.py tui   --binary ~/.local/bin/agy --out /tmp/tui-old
    python3 probe_agy.py tui   --binary /tmp/agy-new/agy --out /tmp/tui-new --against /tmp/tui-old
    python3 probe_agy.py sites ~/.local/bin/agy.v1.5.7.orig /tmp/agy-new/agy.v1.5.8.orig
"""

from __future__ import annotations

import argparse
import codecs
import difflib
import fcntl
import http.server
import json
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from pathlib import Path

import capture_prompt
import patch_agy
import prompt_templates

DEFAULT_BINARY = Path.home() / ".local/bin/agy"
STATE_DIR = Path.home() / ".gemini" / capture_prompt.STATE_SUBDIR
WIRE_MODELS = [
    *(f"gemini-4-hydrogen-{e}" for e in ("low", "medium", "high", "xhigh")),
    *(f"gemini-4-carbon-{e}" for e in ("low", "medium", "high")),
    *(f"gemini-4-argon-{e}" for e in ("low", "medium", "high")),
]
COLS, ROWS = 110, 60  # tall enough that no probed screen scrolls its first rows away
THOUGHTS = (
    "**Weighing the greeting**\n\nThe user said hello, so a short reply fits.",
    "\n\nSecond paragraph: mention one command so inline code shows.",
)
ANSWER = "Hello. Run `ls` to list files.\n\nSecond paragraph of the answer."
# A fresh app data dir opens with the color scheme, the terms (opt out of data use), and folder trust.
ONBOARDING = [("", "\r", 1.5), ("", "\r", 0.8), ("", "\x1b[B", 0.6), ("", "\x1b[C", 0.6), ("", "\r", 2.5), ("start", "\r", 4.0)]
SCENARIO = [
    ("typed", "hello", 0.8),
    ("thinking", "\r", 3.8),      # the second thought is live; the pending line counts
    ("done", "", 6.0),
    ("model", "/model\r", 2.5),
    ("model-context", "\t", 1.0),  # tab moves the context selector
    ("model-closed", "\x1b", 1.0),
    ("context", "/context\r", 2.5),
]


# --- wire -------------------------------------------------------------------------------------

def run_wire(binary: Path, models: list[str]) -> dict[str, str]:
    """Print, and return by model ID, the request each one sends; a model the binary rejects maps to `FAILED: ...`."""
    workspace = Path(tempfile.mkdtemp(prefix="agy-wire-"))
    sent: dict[str, str] = {}
    try:
        for model in models:
            shutil.rmtree(STATE_DIR, ignore_errors=True)
            try:
                capture_prompt.run_scenario(binary, workspace, ["--model", model], "say hi")
            except RuntimeError as exc:
                reason = next((line for line in str(exc).splitlines() if line.startswith("error:")), str(exc).splitlines()[-1])
                sent[model] = f"FAILED: {reason[:160]}"
                print(f"{model:26s} {sent[model]}")
                continue
            path, body = max(
                ((p, json.loads(b)) for p, b in capture_prompt._Recorder.captured if "GenerateContent" in p),
                key=lambda r: len(capture_prompt.system_text(r[1])),
            )
            config = body.get("generationConfig", {})
            sent[model] = f"{path.split('?')[0]:56s} thinkingConfig={json.dumps(config.get('thinkingConfig'))}"
            print(f"{model:26s} {sent[model]}")
    finally:
        shutil.rmtree(STATE_DIR, ignore_errors=True)
        shutil.rmtree(workspace, ignore_errors=True)
    return sent


# --- tui --------------------------------------------------------------------------------------

class _Gemini(http.server.BaseHTTPRequestHandler):
    """Answers the agent turn with a slow stream of two thoughts and an answer; anything else briefly."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *_: object) -> None:
        pass

    def _send(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send(b'{"models":[]}', "application/json")

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        stream = "streamGenerateContent" in self.path
        if not stream or len(body) < 20000:  # titles and other background calls carry short prompts
            reply = json.dumps({
                "candidates": [{"content": {"role": "model", "parts": [{"text": "Greeting"}]}, "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 1, "totalTokenCount": 11},
            }).encode()
            if stream:
                self._send(b"data: " + reply + b"\n\n", "text/event-stream")
            else:
                self._send(reply, "application/json")
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()

        def event(parts: list[dict], **candidate: object) -> None:
            data: dict = {"candidates": [{"content": {"role": "model", "parts": parts}, **candidate}]}
            if candidate:
                data["usageMetadata"] = {"promptTokenCount": 41000, "candidatesTokenCount": 30, "thoughtsTokenCount": 25, "totalTokenCount": 41055}
            self.wfile.write(b"data: " + json.dumps(data).encode() + b"\n\n")
            self.wfile.flush()

        for thought in THOUGHTS:
            event([{"text": thought, "thought": True}])
            time.sleep(2.5)
        event([{"text": ANSWER}])
        time.sleep(0.3)
        event([{"text": ""}], finishReason="STOP")
        self.close_connection = True


_CSI = re.compile(r"\x1b\[([?>=<]?)([0-9;:]*)[ -/]*([@-~])")
_STRING = re.compile(r"\x1b[\]P_^][^\x07\x1b]*(?:\x07|\x1b\\)")
_SGR_FLAGS = {1: "bold", 2: "faint", 3: "italic", 4: "underline", 7: "reverse"}
_SGR_RESETS = {22: ("bold", "faint"), 23: ("italic",), 24: ("underline",), 27: ("reverse",), 39: ("fg",), 49: ("bg",)}
_BLANK = (" ", "")


class Screen:
    """The subset of a VT100 that bubbletea's renderer uses: cursor moves, erases, scrolls, and SGR."""

    def __init__(self) -> None:
        self.grid = [[_BLANK] * COLS for _ in range(ROWS)]
        self.row = self.col = 0  # col == COLS is a pending wrap
        self.attrs: dict[str, object] = {}
        self.pending = ""

    def _style(self) -> str:
        return ",".join(k if v is True else f"{k}={v}" for k, v in sorted(self.attrs.items()))

    def _erased(self) -> tuple[str, str]:
        return (" ", self._style()) if "bg" in self.attrs else _BLANK

    def _line_feed(self) -> None:
        if self.row == ROWS - 1:
            self.grid.pop(0)
            self.grid.append([_BLANK] * COLS)
        else:
            self.row += 1

    def _sgr(self, params: list[int]) -> None:
        i = 0
        while i < len(params):
            p = params[i]
            if p == 0:
                self.attrs = {}
            elif p in _SGR_FLAGS:
                self.attrs[_SGR_FLAGS[p]] = True
            elif p in _SGR_RESETS:
                for key in _SGR_RESETS[p]:
                    self.attrs.pop(key, None)
            elif p in (38, 48) and i + 2 < len(params):
                key = "fg" if p == 38 else "bg"
                if params[i + 1] == 5:
                    self.attrs[key] = str(params[i + 2])
                    i += 2
                else:
                    self.attrs[key] = "#%02x%02x%02x" % tuple(params[i + 2 : i + 5])
                    i += 4
            elif 30 <= p <= 37 or 90 <= p <= 97:
                self.attrs["fg"] = str(p - 30 if p < 90 else p - 82)
            elif 40 <= p <= 47 or 100 <= p <= 107:
                self.attrs["bg"] = str(p - 40 if p < 100 else p - 92)
            i += 1

    def _csi(self, params: list[str], final: str) -> None:
        def n(k: int = 0, default: int = 1) -> int:
            return int(params[k]) if len(params) > k and params[k] else default

        if final == "m":
            self._sgr([int(p) if p else 0 for p in params] or [0])
            return
        self.col = min(self.col, COLS - 1)  # any cursor command drops a pending wrap
        if final in "Hf":
            self.row, self.col = min(ROWS, n(0)) - 1, min(COLS, n(1)) - 1
        elif final == "A":
            self.row = max(0, self.row - n())
        elif final == "B":
            self.row = min(ROWS - 1, self.row + n())
        elif final == "C":
            self.col = min(COLS - 1, self.col + n())
        elif final == "D":
            self.col = max(0, self.col - n())
        elif final == "G":
            self.col = min(COLS, n()) - 1
        elif final == "d":
            self.row = min(ROWS, n()) - 1
        elif final == "K":
            mode = n(0, 0)
            span = (self.col, COLS) if mode == 0 else (0, self.col + 1) if mode == 1 else (0, COLS)
            self.grid[self.row][span[0] : span[1]] = [self._erased()] * (span[1] - span[0])
        elif final == "X":
            end = min(COLS, self.col + n())
            self.grid[self.row][self.col : end] = [self._erased()] * (end - self.col)
        elif final == "J":
            mode = n(0, 0)
            if mode == 0:
                self.grid[self.row][self.col :] = [_BLANK] * (COLS - self.col)
                for r in range(self.row + 1, ROWS):
                    self.grid[r] = [_BLANK] * COLS
            elif mode in (2, 3):
                self.grid = [[_BLANK] * COLS for _ in range(ROWS)]
        elif final == "L":
            for _ in range(n()):
                self.grid.insert(self.row, [_BLANK] * COLS)
                self.grid.pop()
        elif final == "M":
            for _ in range(n()):
                self.grid.pop(self.row)
                self.grid.append([_BLANK] * COLS)
        elif final == "S":
            for _ in range(n()):
                self.grid.pop(0)
                self.grid.append([_BLANK] * COLS)

    def feed(self, text: str) -> None:
        text, i = self.pending + text, 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b":
                if m := _CSI.match(text, i):
                    if not m.group(1):  # private modes and queries change nothing on screen
                        self._csi(m.group(2).replace(":", ";").split(";") if m.group(2) else [], m.group(3))
                    i = m.end()
                elif m := _STRING.match(text, i):
                    i = m.end()
                elif i + 1 < len(text) and text[i + 1] not in "[]P_^":
                    i += 3 if text[i + 1] in "()" else 2
                else:
                    break  # an unfinished sequence: wait for the rest
                continue
            if ch == "\r":
                self.col = 0
            elif ch == "\n":
                self._line_feed()
            elif ch == "\b":
                self.col = max(0, min(self.col, COLS - 1) - 1)
            elif ch == "\t":  # the renderer moves the cursor with hard tabs
                self.col = min(COLS - 1, (min(self.col, COLS - 1) // 8 + 1) * 8)
            elif ch >= " ":
                if self.col >= COLS:
                    self.col = 0
                    self._line_feed()
                self.grid[self.row][self.col] = (ch, self._style())
                self.col += 1
            i += 1
        self.pending = text[i:]

    def dump(self) -> str:
        """Each non-empty row as text, followed by its styled runs (`~ [style]'text'`) when it has any."""
        out: list[str] = []
        for cells in self.grid:
            text = "".join(c for c, _ in cells).rstrip()
            if not text and not any(style for _, style in cells):
                continue
            out.append(text)
            runs, start = [], 0
            for end in range(1, COLS + 1):
                if end == COLS or cells[end][1] != cells[start][1]:
                    if cells[start][1]:
                        runs.append(f"[{cells[start][1]}]{''.join(c for c, _ in cells[start:end])!r}")
                    start = end
            if runs:
                out.append("      ~ " + " ".join(runs))
        return "\n".join(out) + "\n"


def run_tui(binary: Path, out: Path, settings: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Gemini)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    shutil.rmtree(STATE_DIR, ignore_errors=True)
    workspace = tempfile.mkdtemp(prefix="agy-tui-")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AGY_", "GEMINI_", "GOOGLE_"))}
    env.update(
        GEMINI_API_KEY="probe", GOOGLE_GEMINI_BASE_URL=f"http://127.0.0.1:{server.server_port}",
        AGY_CLI_DISABLE_AUTO_UPDATE="true", TERM="xterm-256color", COLORTERM="truecolor",
    )
    argv = [str(binary), f"--app_data_dir={capture_prompt.STATE_SUBDIR}", "--settings", json.dumps(settings)]
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(workspace)
        os.execve(argv[0], argv, env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    screen, raw, decoder = Screen(), bytearray(), codecs.getincrementaldecoder("utf-8")("replace")

    def pump(seconds: float) -> None:
        deadline = time.time() + seconds
        while time.time() < deadline:
            if not select.select([fd], [], [], 0.05)[0]:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            raw.extend(chunk)
            # Answer what bubbletea asks at startup: background color (dark), device attributes, cursor.
            if b"\x1b]11;?" in chunk:
                os.write(fd, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
            if b"\x1b[c" in chunk or b"\x1b[0c" in chunk:
                os.write(fd, b"\x1b[?62;22c")
            if b"\x1b[6n" in chunk:
                os.write(fd, f"\x1b[{screen.row + 1};{min(screen.col, COLS - 1) + 1}R".encode())
            screen.feed(decoder.decode(chunk))

    try:
        pump(6)
        for name, keys, wait in ONBOARDING + SCENARIO:
            os.write(fd, keys.encode())
            pump(wait)
            if name:
                (out / f"{name}.txt").write_text(screen.dump())
    finally:
        for _ in range(2):
            os.write(fd, b"\x03")
            pump(0.8)
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        os.waitpid(pid, 0)
        (out / "raw.bin").write_bytes(raw)
        shutil.rmtree(STATE_DIR, ignore_errors=True)
        shutil.rmtree(workspace, ignore_errors=True)


_MASKS = [(re.compile(r"agy-tui-\w+"), "agy-tui-X"), (re.compile(r"\b1\.\d+\.\d+\b"), "N.N.N"), (re.compile(r"\b\d+s\b"), "Ns")]


def diff_snapshots(old: Path, new: Path) -> int:
    """Diff two snapshot dirs; return how many screens differ.

    `thinking` is a moving frame, so it is compared as text with the spinner masked: the running
    light's position and the spinner's phase depend on when the frame was taken.
    """
    def lines(path: Path) -> list[str]:
        text = path.read_text()
        for pattern, mask in _MASKS:
            text = pattern.sub(mask, text)
        if path.stem == "thinking":
            return [re.sub("[◐◓◑◒]", "◐", line) for line in text.splitlines() if not line.startswith("      ~ ")]
        return text.splitlines()

    changed = 0
    for name in [name for name, _, _ in ONBOARDING + SCENARIO if name]:
        a, b = old / f"{name}.txt", new / f"{name}.txt"
        delta = list(difflib.unified_diff(lines(a), lines(b), str(a), str(b), lineterm="", n=0))
        print(f"{name:14s} {'identical' if not delta else f'{len(delta) - 2} diff lines'}")
        if delta:
            changed += 1
            print("\n".join("    " + line[:220] for line in delta[2:42]))
    return changed


# --- sites ------------------------------------------------------------------------------------

def _pc_relative(word: int) -> bool:
    return (
        (word & 0x7C000000) == 0x14000000                        # b, bl
        or (word & 0x9F000000) in (0x90000000, 0x10000000)       # adrp, adr
        or (word & 0xFF000010) == 0x54000000                     # b.cond
        or (word & 0x7E000000) in (0x34000000, 0x36000000)       # cbz/cbnz, tbz/tbnz
    )


def _word_diff(a: bytes, b: bytes) -> list[str]:
    """Words that differ and are not addresses: branches, and the `add`/`ldr` that completes an `adrp`."""
    count = min(len(a), len(b)) // 4
    out, prev = [], 0
    for i, (x, y) in enumerate(zip(struct.unpack(f"<{count}I", a[: count * 4]), struct.unpack(f"<{count}I", b[: count * 4]))):
        completes_adrp = (prev & 0x9F000000) == 0x90000000 and (prev & 31) == ((x >> 5) & 31)
        if x != y and not _pc_relative(x) and not completes_adrp:
            out.append(f"+{i * 4:#x} {x:08x}->{y:08x}")
        prev = x
    return out


def compare_sites(old_bin: Path, new_bin: Path, context: int = 0x40) -> int:
    old, new = old_bin.read_bytes(), new_bin.read_bytes()
    resolve = lambda path, data: {s.name: s for s in patch_agy.resolve_patch_sites(data, patch_agy.detect_binary_version(path), strict=True)}
    old_sites, new_sites = resolve(old_bin, old), resolve(new_bin, new)
    for label, here, there in (("only in old", old_sites, new_sites), ("only in new", new_sites, old_sites)):
        gone: dict[str, int] = {}
        for name in here.keys() - there.keys():
            gone[here[name].domain] = gone.get(here[name].domain, 0) + 1
        for domain, count in sorted(gone.items()):
            print(f"{label}: {count} {domain} site(s)")
    flagged = 0
    for name, b in new_sites.items():
        a = old_sites.get(name)
        if a is None or a.domain in ("prompt", "tool-monitors"):  # text, not code
            continue
        notes = []
        if len(a.patched) != len(b.patched):
            notes.append(f"patched length {len(a.patched)} -> {len(b.patched)}")
        elif delta := _word_diff(a.patched, b.patched):
            notes.append("patched: " + " ".join(delta))
        around = lambda data, s: data[s.offset - context : s.offset + len(s.patched) + context]
        if delta := _word_diff(around(old, a), around(new, b)):
            notes.append(f"stock code around it ({len(delta)} words): " + " ".join(delta[:8]))
        if notes:
            flagged += 1
            print(f"- {name}\n    " + "\n    ".join(notes))
    print(f"{len(new_sites)} sites, {flagged} to read: every flagged word should be a frame slot or a field that moved, never a different instruction")
    return flagged


# --- rehearse ---------------------------------------------------------------------------------

def _stage(clean: Path, dest: Path) -> tuple[Path, Path, str]:
    """Copy a clean binary to `dest/agy` and link it as the backup --apply patches from; return both and the version."""
    dest.mkdir(parents=True, exist_ok=True)
    binary = dest / "agy"
    binary.unlink(missing_ok=True)  # on a second rehearsal `clean` may be this directory's own backup, a link to it
    shutil.copy2(clean, binary)
    binary.chmod(0o755)
    version = patch_agy.detect_binary_version(binary)
    backup = patch_agy.backup_path_for(binary)
    backup.unlink(missing_ok=True)
    os.link(binary, backup)  # --apply replaces `agy` with a new file, so the link stays clean
    return binary, backup, version


def _scaffold_templates(stock: Path, version: str, old_version: str) -> tuple[str, str]:
    """Make `templates/v<version>/` when the release has none: carry the previous release's changes over
    when Google's originals under them are unchanged, by digest. The originals go to `stock/`, which git
    ignores, for a person to read."""
    templates = prompt_templates.TEMPLATES_ROOT
    new_dir, old_dir = templates / f"v{version}", templates / f"v{old_version}"
    if (new_dir / "system_prompts").is_dir():
        return "ok", "present"
    slots = {s.name: s for s in prompt_templates.iter_templates(stock.read_bytes())}
    for slot in slots.values():
        (new_dir / "stock" / slot.name).parent.mkdir(parents=True, exist_ok=True)
        (new_dir / "stock" / slot.name).write_bytes(slot.content)
    manifest = json.loads((old_dir / "prompt_overrides.json").read_text())
    moved = [name for name, entry in manifest["templates"].items()
             if (slot := slots.get(f"system_prompts/{name}")) is None
             or prompt_templates.stock_digest(slot.content) != entry["stock_sha256"]]
    if moved:
        return "FAIL", (f"Google changed templates we change: {', '.join(moved)}. Originals dumped to {new_dir}/stock; "
                        f"review each, then write templates/v{version}/ (templates/v{old_version}/README.md, Editing)")
    shutil.copytree(old_dir / "system_prompts", new_dir / "system_prompts")
    manifest["$comment"] = manifest["$comment"].replace(f"agy v{old_version}", f"agy v{version}")
    (new_dir / "prompt_overrides.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return "ok", f"scaffolded from v{old_version} ({len(manifest['templates'])} changed templates, originals unchanged); README.md is left to write"


def _stock_prompt(backup: Path, version: str, old_backup: Path, old_version: str) -> tuple[str, str]:
    """Capture the stock prompt and tools; an experiment's default can change what the same templates render.
    The captures stay local (git ignores stock/); the previous release's is taken first when it is missing."""
    new, old = (prompt_templates.TEMPLATES_ROOT / f"v{v}" / "stock" for v in (version, old_version))
    for binary, dest in ((old_backup, old), (backup, new)):
        if binary is backup or not (dest / "PROMPT.md").is_file():
            run = subprocess.run([sys.executable, str(capture_prompt.REPO / "capture_prompt.py"), "--binary", str(binary)],
                                 capture_output=True, text=True)
            if run.returncode:
                return "FAIL", f"capture_prompt.py: {run.stderr.strip().splitlines()[-1] if run.stderr.strip() else run.returncode}"
    same_prompt = (new / "PROMPT.md").read_text().split("\n", 1)[1] == (old / "PROMPT.md").read_text().split("\n", 1)[1]
    same_tools = (new / "tools.json").read_bytes() == (old / "tools.json").read_bytes()
    if same_prompt and same_tools:
        return "ok", f"rendered prompt and tool schemas identical to v{old_version}"
    what = " and ".join(n for n, same in (("PROMPT.md", same_prompt), ("tools.json", same_tools)) if not same)
    return "READ", f"{what} differ from v{old_version}: diff templates/v{old_version}/stock templates/v{version}/stock"


def rehearse(stock: Path | None, old: Path | None, workdir: Path | None, no_tui: bool) -> int:
    """Rehearse an upgrade on copies and report, step by step, whether the patch still holds."""
    report: list[tuple[str, str, str]] = []

    def step(name: str, verdict: str, detail: str) -> None:
        report.append((name, verdict, detail))
        print(f"\n== {name}: {verdict}  {detail}", flush=True)

    def finish() -> int:
        print("\n" + "=" * 100)
        for name, verdict, detail in report:
            print(f"{verdict:6s} {name:18s} {detail[:160]}")
        bad = [v for _, v, _ in report if v in ("FAIL", "REVIEW")]
        to_read = sum(v == "READ" for _, v, _ in report)
        print("=" * 100 + f"\ncopies kept in {workdir}")
        if not bad:
            print("The patch holds" + (f"; {to_read} step(s) marked READ show what upstream changed." if to_read else ".") + " To upgrade: README.md §3.")
        return 1 if bad else 0

    old = old or patch_agy.backup_path_for(DEFAULT_BINARY)
    if not old.exists():
        raise SystemExit(f"{old} is missing: give the previous release's clean binary with --old")
    workdir = workdir or Path(tempfile.mkdtemp(prefix="agy-rehearsal-"))
    if stock is None:
        fetch = subprocess.run([sys.executable, "-I", str(capture_prompt.REPO / "check_agy_update.py"), "--fetch", str(workdir / "release")],
                               capture_output=True, text=True)
        print(fetch.stdout.strip())
        if fetch.returncode == 0:  # up to date: nothing to rehearse
            shutil.rmtree(workdir, ignore_errors=True)
            return 0
        unpacked = re.search(r"^Verified and unpacked: (.+)$", fetch.stdout, re.M)
        if fetch.returncode != 1 or not unpacked:
            raise SystemExit(f"check_agy_update.py failed: {fetch.stderr.strip()}")
        stock = Path(unpacked.group(1))
    new_bin, new_orig, version = _stage(stock, workdir / "new")
    old_bin, old_orig, old_version = _stage(old, workdir / "old")
    print(f"rehearsing v{old_version} -> v{version} in {workdir}")

    # 1. What upstream ships. A site whose behavior the release now has should retire, even if it still resolves.
    print(f"\n-- wire, stock v{version}")
    stock_wire = run_wire(new_orig, WIRE_MODELS)
    rejected = [m for m, v in stock_wire.items() if v.startswith("FAILED")]
    step("stock wire", "ok" if not rejected else "READ", f"{len(stock_wire) - len(rejected)} of {len(stock_wire)} picker IDs are built in" + (f"; not: {', '.join(rejected)}" if rejected else ""))

    # 2. Templates and the rendered prompt.
    verdict, detail = _scaffold_templates(new_orig, version, old_version)
    step("templates", verdict, detail)
    if verdict == "ok":
        step("stock prompt", *_stock_prompt(new_orig, version, old_orig, old_version))

    # 3. Every resolver, so that one moved anchor does not hide the rest.
    new_data, old_data = new_orig.read_bytes(), old_orig.read_bytes()
    new_groups = patch_agy.resolve_site_groups(new_data, version, strict=True)
    old_groups = patch_agy.resolve_site_groups(old_data, old_version, strict=True)
    broken = 0
    print(f"\n-- sites by group, v{old_version} -> v{version}")
    for name, result in new_groups.items():
        before = old_groups.get(name)
        was = "failed" if isinstance(before, Exception) else str(len(before or ()))
        if isinstance(result, Exception):
            broken += 1
            print(f"  RE-AUTHOR  {name:20s} {was:>3} -> ?   {type(result).__name__}: {result}")
        else:
            dirty = [s.name for s in result if patch_agy.site_state(new_data, s) != "unpatched"]
            broken += bool(dirty)
            verdict = "RE-AUTHOR" if dirty else "retired" if was not in ("0", "failed") and not result else "keep"
            print(f"  {verdict:10s} {name:20s} {was:>3} -> {len(result):<3}" + (f" stock bytes unknown at: {dirty[0]}" if dirty else ""))
    if broken:
        step("resolve", "FAIL", f"{broken} group(s) to re-author; read references/context-window-patch.md §5 first")
        return finish()
    sites = patch_agy.resolve_patch_sites(new_data, version, strict=True)
    step("resolve", "ok", f"{len(sites)} sites resolve on the clean v{version}")

    # 4. Stock code that moved: the review that --status cannot do.
    print(f"\n-- sites, v{old_version} -> v{version}")
    flagged = compare_sites(old_orig, new_orig)
    unreviewed = patch_agy.unreviewed_shapes(new_data, sites)
    if unreviewed:
        step("stock shapes", "REVIEW", f"{len(unreviewed)} site(s) show stock code of a new shape: {'; '.join(unreviewed)}. "
             f"Read them above and in a disassembly, then: patch_agy.py --accept-shapes --binary {new_bin}, and rehearse again with --stock {new_orig} --dir {workdir}")
        return finish()
    step("stock shapes", "ok", f"every code site has a reviewed shape; {flagged} differ from v{old_version} only in a frame slot, field or address (listed above)")

    # 5. Patch the copy.
    patch_agy.apply_patch(new_bin)
    state = patch_agy.inspect_binary(new_bin)[0]
    signed = subprocess.run(["codesign", "-v", str(new_bin)], capture_output=True).returncode == 0
    runs = subprocess.run([str(new_bin), "--version"], capture_output=True, text=True).stdout.strip() == version
    step("apply", "ok" if state == "patched" and signed and runs else "FAIL", f"state {state}, signature {'valid' if signed else 'INVALID'}, {'runs' if runs else 'DOES NOT RUN'}")
    if report[-1][1] != "ok":
        return finish()

    # 6. The patched copy, as it is used.
    print(f"\n-- wire, patched v{version}")
    patched_wire = run_wire(new_bin, WIRE_MODELS)
    rejected = [m for m, v in patched_wire.items() if v.startswith("FAILED")]
    differs = [m for m in WIRE_MODELS if patched_wire[m] != stock_wire[m]]
    step("patched wire", "FAIL" if rejected else "ok",
         f"rejected: {', '.join(rejected)}" if rejected else
         "every picker ID sends a request" + (f"; the patch changes: {', '.join(differs)}" if differs else ", the same as stock"))

    if no_tui:
        step("screens", "skip", "--no-tui")
        return finish()
    try:
        patch_agy.apply_patch(old_bin)
        settings = {"modelProvider": "gemini", "model": "Gemini 4 Hydrogen (High)", "contextWindow": "512K", "showTips": False}
        run_tui(old_bin, workdir / "screens-old", settings)
        run_tui(new_bin, workdir / "screens-new", settings)
    except OSError as exc:
        step("screens", "skip", f"no pty ({exc}); run outside the sandbox")
        return finish()
    print(f"\n-- screens, patched v{old_version} -> patched v{version}")
    changed = diff_snapshots(workdir / "screens-old", workdir / "screens-new")
    step("screens", "READ" if changed else "ok",
         f"{changed} screen(s) differ from patched v{old_version} (above): tell upstream's changes from ours" if changed else f"identical to patched v{old_version}")
    return finish()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    wire = sub.add_parser("wire", help="the request each model ID sends")
    wire.add_argument("models", nargs="*", default=WIRE_MODELS)
    wire.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    tui = sub.add_parser("tui", help="screen snapshots of a canned session")
    tui.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    tui.add_argument("--out", type=Path, help="snapshot directory (default: .cache/probe/v<version>)")
    tui.add_argument("--against", type=Path, help="diff the snapshots against this earlier run")
    tui.add_argument("--settings", type=json.loads, default={}, help="extra settings.json keys, as JSON")
    reh = sub.add_parser("rehearse", help="rehearse an upgrade on copies: fetch, resolve, patch, probe")
    reh.add_argument("--stock", type=Path, help="a clean binary of the new release (default: fetch it if one is newer)")
    reh.add_argument("--old", type=Path, help="the clean binary to compare with (default: the installed version's .orig)")
    reh.add_argument("--dir", type=Path, help="working directory for the copies (default: a new temp dir)")
    reh.add_argument("--no-tui", action="store_true", help="skip the screen probe (it needs a pty)")
    sites = sub.add_parser("sites", help="compare every patch site of two clean binaries")
    sites.add_argument("old", type=Path)
    sites.add_argument("new", type=Path)
    args = ap.parse_args()

    if args.command == "wire":
        return 1 if any(v.startswith("FAILED") for v in run_wire(args.binary, args.models).values()) else 0
    if args.command == "rehearse":
        return rehearse(args.stock, args.old, args.dir, args.no_tui)
    if args.command == "sites":
        compare_sites(args.old, args.new)
        return 0
    version = subprocess.run([str(args.binary), "--version"], capture_output=True, text=True).stdout.strip()
    out = args.out or capture_prompt.REPO / ".cache/probe" / f"v{version}"
    settings = {"modelProvider": "gemini", "model": "Gemini 4 Hydrogen (High)", "contextWindow": "512K", "showTips": False, **args.settings}
    run_tui(args.binary, out, settings)
    print(f"wrote {out}")
    return 1 if args.against and diff_snapshots(args.against, out) else 0


if __name__ == "__main__":
    sys.exit(main())
