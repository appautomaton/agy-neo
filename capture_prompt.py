#!/usr/bin/env python3
"""Capture the exact prompt that `agy` sends to the model, as one readable document.

`agy` is pointed at a loopback endpoint that records the first generation request
and answers 500, so the turn ends without network access or quota use. Output:

    PROMPT.md     system instruction section by section (with each section's source),
                  tool descriptions, and the user turn of every scenario
    tools.json    full tool schemas


An `.orig` binary is stock and goes to `templates/v<version>/stock/`, which git ignores: Google's
text stays local. Any other binary is patched and goes to `.cache/system-prompt/v<version>/`:
it is derived from `templates/` and goes stale.

State goes to an isolated app data dir (`.capture-state` in this repo) that
is deleted afterwards, so captures never appear in the CLI's conversation history.
The isolation also keeps the MCP schema cache writable; when that write fails,
`agy` falls back to eager-loading every MCP tool, which misrepresents normal runs.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import NamedTuple

import prompt_templates

HOME = Path.home()
DEFAULT_BINARY = HOME / ".local/bin/agy"
REPO = Path(__file__).resolve().parent
STOCK_OUT = REPO / "templates"                  # templates/v<version>/stock/: what Google ships
PATCHED_OUT = REPO / ".cache/system-prompt"     # regenerated on demand; never a source of truth
# `--app_data_dir` is relative to ~/.gemini; the state lives in this repo, wherever it is.
STATE_SUBDIR = os.path.relpath(REPO / ".capture-state", Path.home() / ".gemini")
SECTION_RE = re.compile(r"^<([A-Za-z][\w ]*)>\n", re.M)
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
RULES_RE = re.compile(r"<RULE\[[^\]]*\]>.*</RULE\[[^\]]*\]>", re.S)
RULES_MARK = "[dynamic: your AGENTS.md / rules]"


class _Recorder(http.server.BaseHTTPRequestHandler):
    captured: list[tuple[str, bytes]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        self.captured.append((self.path, body))
        self.send_response(500)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":{"code":500,"message":"captured","status":"INTERNAL"}}')

    do_GET = do_POST

    def log_message(self, *_: object) -> None:
        pass


def run_scenario(binary: Path, workspace: Path, extra_args: list[str], prompt: str) -> dict:
    """Run one `agy --print` turn against the recorder and return the main request."""
    _Recorder.captured = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    env = {k: v for k, v in os.environ.items() if not k.startswith("AGY_LLM_GATEWAY_")}
    env.update(
        GEMINI_API_KEY="capture",
        GOOGLE_GEMINI_BASE_URL=f"http://127.0.0.1:{server.server_port}",
        AGY_CLI_DISABLE_AUTO_UPDATE="true",
    )
    cmd = [
        str(binary),
        f"--app_data_dir={STATE_SUBDIR}",
        "--settings", json.dumps({"modelProvider": "gemini"}),
        *extra_args,
        "--print", prompt,
    ]
    try:
        proc = subprocess.run(cmd, cwd=workspace, env=env, capture_output=True, text=True, timeout=120)
    finally:
        server.shutdown()

    requests = [json.loads(body) for path, body in _Recorder.captured if "GenerateContent" in path]
    if not requests:
        raise RuntimeError(f"no generation request captured; agy stderr tail:\n{proc.stderr[-1500:]}")
    # Background calls (titles, safety checks) carry short prompts; the agent turn has the largest.
    return max(requests, key=lambda r: len(system_text(r)))


def system_text(request: dict) -> str:
    return "".join(p.get("text", "") for p in request.get("systemInstruction", {}).get("parts", []))


def normalize(text: str, workspace: Path) -> str:
    """Replace per-run values so captures diff cleanly across runs and versions."""
    # Longest first: macOS resolves /tmp to /private/tmp, which contains the shorter form.
    for path in sorted({str(workspace), str(workspace.resolve())}, key=len, reverse=True):
        text = text.replace(path, "<workspace>")
    text = text.replace(str(HOME / ".gemini" / STATE_SUBDIR), "<appDataDir>")
    text = UUID_RE.sub("<uuid>", text)
    return re.sub(r"(The current local time is: )\S+", r"\1<local-time>", text)


def split_sections(text: str) -> list[tuple[str, str]]:
    """Split on top-level `<name>` blocks, skipping tags nested inside a section."""
    sections, pos = [], 0
    while (m := SECTION_RE.search(text, pos)) :
        end = text.find(f"\n</{m.group(1)}>", m.end())
        if end < 0:
            pos = m.end()
            continue
        if loose := text[pos : m.start()].strip():
            sections.append(("_loose", loose))
        sections.append((m.group(1), text[m.end() : end]))
        pos = end + len(m.group(1)) + 4
    if loose := text[pos:].strip():
        sections.append(("_loose", loose))
    return sections


def approx_tokens(chars: int) -> int:
    return round(chars / 4)  # English-heavy prompt text averages ~4 chars per token


class Capture(NamedTuple):
    system: str
    sections: list[tuple[str, str]]
    user_turn: str
    tools: list[dict]
    generation_config: dict


def capture(request: dict, workspace: Path) -> Capture:
    system = normalize(system_text(request), workspace)
    turns = [p["text"] for c in request.get("contents", []) if c.get("role") == "user" for p in c["parts"] if "text" in p]
    tools = [d for t in request.get("tools", []) for d in t.get("functionDeclarations", [])]
    return Capture(system, split_sections(system), normalize("\n\n".join(turns), workspace), tools,
                   request.get("generationConfig", {}))


def template_lines(data: bytes) -> list[str]:
    """Literal text of every system prompt template, split into lines long enough to be distinctive."""
    lines = []
    for slot in prompt_templates.iter_templates(data):
        if slot.name.startswith("system_prompts/"):
            text = re.sub(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", "", slot.content.decode(), flags=re.S)
            for fragment in re.split(r"\{\{.*?\}\}", text, flags=re.S):
                lines += [l.strip() for l in fragment.splitlines() if len(l.strip()) >= 12]
    return lines


def section_source(body: str, data: bytes, tmpl_lines: list[str]) -> str:
    """Where a section's text comes from: a template, Go string literals, or run-time data."""
    def tag(line: str) -> str:
        if re.fullmatch(r"#? ?[\w./-]+", line):
            return "dynamic"  # bare identifiers: MCP server and tool names
        if any(t in line or line in t for t in tmpl_lines):
            return "template"
        # Go code splices names into literals with %s, so probe several 24-char windows.
        starts = {0, len(line) // 3, 2 * len(line) // 3, max(len(line) - 24, 0)}
        return "Go" if any(line[i : i + 24].encode() in data for i in starts) else "dynamic"

    sizes: dict[str, int] = {}
    for line in body.splitlines():
        if len(line.strip()) >= 12 or re.fullmatch(r"#? ?[\w./-]+", line.strip() or "-"):
            kind = tag(line.strip())
            sizes[kind] = sizes.get(kind, 0) + len(line)
    total = sum(sizes.values()) or 1
    return " + ".join(k for k in ("template", "Go", "dynamic") if sizes.get(k, 0) / total >= 0.05) or "template"


def approx_tokens(chars: int) -> int:
    return round(chars / 4)  # English-heavy prompt text averages ~4 chars per token


def withhold_rules(text: str) -> str:
    """Hide the user's own rules: PROMPT.md gets committed and shared. Reported sizes still count them."""
    return RULES_RE.sub(RULES_MARK, text)


def fence(text: str) -> list[str]:
    ticks = "````" if "```" in text else "```"
    return [ticks + "text", text.strip("\n"), ticks]


def write_prompt_doc(dest: Path, title: str, captures: dict[str, Capture], data: bytes) -> None:
    tmpl_lines = template_lines(data)
    first_name, first = next(iter(captures.items()))
    tool_chars = sum(len(json.dumps(t, ensure_ascii=False)) for t in first.tools)
    out = [f"# {title}", "",
           "What the model receives on a fresh `agy --print` turn, captured from the binary's real request. "
           "Paths, IDs and times are normalized (`<workspace>`, `<appDataDir>`, `<uuid>`). "
           "User rule text is withheld; sizes still count it. Tokens ≈ chars / 4.", "",
           "| Part | Chars | ≈Tokens |", "| :--- | ---: | ---: |",
           f"| System instruction ({len(first.sections)} sections) | {len(first.system):,} | {approx_tokens(len(first.system)):,} |",
           f"| Tool schemas ({len(first.tools)} tools; full schemas in `tools.json`) | {tool_chars:,} | {approx_tokens(tool_chars):,} |",
           f"| User turn wrapper (`{first_name}`) | {len(first.user_turn):,} | {approx_tokens(len(first.user_turn)):,} |", ""]

    sources = [section_source(body, data, tmpl_lines) for _, body in first.sections]
    out += ["## 1. System Instruction", "", "| # | Section | Source | Chars |", "| ---: | :--- | :--- | ---: |"]
    out += [f"| {i} | `{n}` | {src} | {len(b):,} |" for i, ((n, b), src) in enumerate(zip(first.sections, sources), 1)]
    for i, ((name, body), src) in enumerate(zip(first.sections, sources), 1):
        out += ["", f"### 1.{i} `<{name}>` · {src} · {len(body):,} chars", "", *fence(withhold_rules(body))]

    out += ["", "## 2. Tools", "", "| Tool | Schema chars | Description |", "| :--- | ---: | :--- |"]
    for t in first.tools:
        desc = " ".join(t.get("description", "").split()).replace("|", "\\|")
        out.append(f"| `{t['name']}` | {len(json.dumps(t, ensure_ascii=False)):,} | {desc} |")

    out += ["", "## 3. User Turn", ""]
    for name, cap in captures.items():
        same = "" if cap.system == first.system else " (system instruction differs; see note)"
        out += [f"### `{name}`{same} · {len(cap.user_turn):,} chars", "", *fence(cap.user_turn), ""]
        if cap.system != first.system:
            out += [f"> `{name}` sends a {len(cap.system):,}-char system instruction instead:", "", *fence(withhold_rules(cap.system)), ""]
    out += [f"`generationConfig`: `{json.dumps(first.generation_config)}`"]
    (dest / "PROMPT.md").write_text("\n".join(out) + "\n")
    (dest / "tools.json").write_text(json.dumps(first.tools, indent=2, ensure_ascii=False) + "\n")


def parse_scenario(spec: str) -> tuple[str, list[str]]:
    if spec == "default":
        return "default", []
    if spec == "plan":
        return "plan", ["--mode", "plan"]
    if spec.startswith("agent:"):
        name = spec.split(":", 1)[1]
        return f"agent-{name}", ["--agent", name]
    raise argparse.ArgumentTypeError(f"unknown scenario {spec!r}; use default, plan, or agent:<name>")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="*", default=["default", "plan"], help="default | plan | agent:<name>")
    ap.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    ap.add_argument("--out", type=Path, help="Output directory (default: templates/v<ver>/stock for stock, .cache/system-prompt/v<ver> otherwise)")
    ap.add_argument("--workspace", type=Path, help="Run inside this directory (default: a fresh empty one)")
    ap.add_argument("--prompt", default="say hi")
    args = ap.parse_args()
    scenarios = [parse_scenario(s) for s in args.scenarios]

    version = subprocess.run([str(args.binary), "--version"], capture_output=True, text=True).stdout.strip()
    stock = args.binary.name.endswith(".orig")
    dest = args.out or (STOCK_OUT / f"v{version}" / "stock" if stock else PATCHED_OUT / f"v{version}")
    state_dir = HOME / ".gemini" / STATE_SUBDIR
    workspace = args.workspace or Path(tempfile.mkdtemp(prefix="agy-capture-"))

    captures = {}
    try:
        for name, extra in scenarios:
            shutil.rmtree(state_dir, ignore_errors=True)
            captures[name] = capture(run_scenario(args.binary, workspace, extra, args.prompt), workspace)
            print(f"{name:20s} system {len(captures[name].system):>7,}  tools {len(captures[name].tools):>3}")
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)
        if not args.workspace:
            shutil.rmtree(workspace, ignore_errors=True)

    if not stock:
        shutil.rmtree(dest, ignore_errors=True)  # stock/ also holds the template sources; only overwrite our files there
    dest.mkdir(parents=True, exist_ok=True)
    data = args.binary.read_bytes()
    title = f"`agy` v{version} CLI Prompt ({'stock' if stock else 'patched: ' + str(args.binary)})"
    write_prompt_doc(dest, title, captures, data)
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
