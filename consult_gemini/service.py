"""Session lifecycle, model/effort selection, LRU/TTL session eviction, and consultation orchestration."""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

from .acp_client import AcpClient, AcpError, TurnCollector, detect_soft_error
from .usage_db import TurnUsage, get_max_gen_idx, read_turn_usage_since

DEFAULT_AGY_BIN = os.environ.get("AGY_BIN", str(pathlib.Path.home() / ".gemini/bin/agy"))
DEFAULT_GEMINI_DIR = pathlib.Path(os.environ.get("AGY_GEMINI_DIR", pathlib.Path.home() / ".gemini"))
ACP_APP_DATA_SUBDIR = "antigravity-acp"
# A consult asks Gemini 4 Carbon unless the caller asks for Flash, at high effort unless it
# asks for medium. No other model or effort can be named through the tool.
DEFAULT_MODEL = os.environ.get("AGY_CONSULT_DEFAULT_MODEL", "gemini-4-carbon")
FLASH_MODEL = os.environ.get("AGY_CONSULT_FLASH_MODEL", "gemini-3.8-flash")
DEFAULT_EFFORT = "high"
EFFORTS = ("medium", "high")
EFFORT_SUFFIXES = ("low", "medium", "high")
CONTEXT_WINDOW = "512K"  # the preset agy is given: 1.3x quota, against 1.8x for 900K
MAX_LIVE_SESSIONS = int(os.environ.get("AGY_CONSULT_MAX_SESSIONS", "16"))
# A session lives as long as its prompt cache: five minutes after its last reply.
IDLE_SESSION_TTL_SEC = float(os.environ.get("AGY_CONSULT_IDLE_TTL_SEC", "300"))
# A turn is cancelled once Gemini has sent nothing for ten minutes, or once it has run an hour in all.
# Silence marks a hung turn; a turn still thinking or reading may run until the hour is up.
CONSULT_STALL_SEC = float(os.environ.get("AGY_CONSULT_STALL_SEC", "600"))
CONSULT_MAX_SEC = float(os.environ.get("AGY_CONSULT_MAX_SEC", "3600"))

CONSULT_SYSTEM_APPEND = (
    "You are being consulted as a senior staff engineering peer, software architect, code reviewer, "
    "and verification agent by another coding agent.\n"
    "- Use your codebase tools (`read_file`, `grep_search`, `find_by_name`, `list_dir`) to inspect files "
    "and trace execution flows yourself.\n"
    "- By default you operate in strictly read-only mode (write and command permissions are denied unless the "
    "caller explicitly enabled `allow_writes=true`). Do not attempt file edits or shell commands unless asked.\n"
    "- Lead with root causes, architectural trade-offs, verification findings, or exact drop-in code blocks, "
    "citing file paths and line numbers."
)


@dataclass
class SessionInfo:
    session_id: str
    client_id: str
    cwd: str
    model: str
    effort: str
    mode: str
    gen_cursor: int = -1
    inflight: int = 0
    last_used: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)


@dataclass
class ConsultResult:
    session_id: str
    model: str
    effort: str
    text: str
    thoughts: str
    tool_calls: list[str]
    stop_reason: str
    usage: TurnUsage | None

    def format_markdown(self, include_thoughts: bool = False) -> str:
        usage_str = self.usage.format_summary() if self.usage else "n/a"
        header = (
            f"[session_id: {self.session_id} | model: {self.model} ({self.effort}) | "
            f"tools_run: {len(self.tool_calls)} | usage: {usage_str} | "
            f"follow up with this session_id within {IDLE_SESSION_TTL_SEC / 60:.0f} min, then start fresh]"
        )
        parts = [header]
        if include_thoughts and self.thoughts.strip():
            parts.append(f"<thinking>\n{self.thoughts.strip()}\n</thinking>")
        parts.append(self.text.strip() if self.text.strip() else "(empty response)")
        return "\n\n".join(parts)


def _naming_session(exc: AcpError, session_id: str, partial_text: str = "") -> AcpError:
    """Name the session a consult failed in, so the caller can still follow up on its work.

    A timed-out or rejected turn leaves its session open, with everything read so far in its
    context and its prompt cache warm. Only a dead `agy acp` process takes its sessions with it.
    Whatever Gemini had already written comes back too, so the caller need not ask for it again.
    """
    if exc.kind == "TRANSPORT":
        return exc
    parts = [
        str(exc),
        f"[session_id: {session_id} | the session is still open: follow up with this session_id "
        f"within {IDLE_SESSION_TTL_SEC / 60:.0f} min to continue from where it stopped, then start fresh]",
    ]
    if partial_text.strip():
        parts.append(f"What Gemini had written before it stopped:\n\n{partial_text.strip()}")
    return AcpError("\n\n".join(parts), exc.kind)


async def _await_turn(prompt: asyncio.Task[dict], collector: TurnCollector) -> dict:
    """Await a `session/prompt` request, abandoning it once the turn has gone quiet for too long."""
    try:
        while True:
            quiet_for = time.monotonic() - collector.last_update
            if quiet_for >= CONSULT_STALL_SEC:
                raise AcpError(
                    f"consult stalled: Gemini sent nothing for {CONSULT_STALL_SEC / 60:.0f} min",
                    "STALLED",
                )
            done, _ = await asyncio.wait({prompt}, timeout=CONSULT_STALL_SEC - quiet_for)
            if done:
                return prompt.result()
    finally:
        prompt.cancel()


def prepare_acp_app_data_dir(gemini_dir: pathlib.Path = DEFAULT_GEMINI_DIR) -> pathlib.Path:
    """Ensure `~/.gemini/antigravity-acp` has `toolPermission: request-review` so ACP gates writes."""
    acp_dir = gemini_dir / ACP_APP_DATA_SUBDIR
    (acp_dir / "conversations").mkdir(parents=True, exist_ok=True)
    cli_dir = gemini_dir / "antigravity-cli"

    src_token = cli_dir / "antigravity-oauth-token"
    dst_token = acp_dir / "antigravity-oauth-token"
    if src_token.exists() and not dst_token.exists():
        try:
            dst_token.symlink_to(src_token)
        except OSError:
            pass

    settings_path = acp_dir / "settings.json"
    desired = {
        "agentMode": "default",
        "allowNonWorkspaceAccess": True,
        "contextWindow": CONTEXT_WINDOW,
        "model": "Gemini 4 Carbon (High)",
        "toolPermission": "request-review",
    }
    current = {}
    if settings_path.exists():
        try:
            current = json.loads(settings_path.read_text())
        except Exception:
            current = {}
    merged = {**current, **desired}
    if merged != current:
        settings_path.write_text(json.dumps(merged, indent=2) + "\n")
    return acp_dir


def normalize_model(model: str | None) -> str:
    raw_model = (model or DEFAULT_MODEL).strip()
    for suffix in EFFORT_SUFFIXES:
        if raw_model.lower().endswith(f"-{suffix}"):
            raw_model = raw_model[: -(len(suffix) + 1)]
            break
    return raw_model


def normalize_cwd(raw_cwd: str | None, fallback_cwd: str | None = None) -> str:
    """Normalize `cwd` into a clean absolute directory path (stripping quotes, `file://`, or shell escapes)."""
    base = pathlib.Path(fallback_cwd).expanduser() if fallback_cwd else pathlib.Path.cwd()
    s = (raw_cwd or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1].strip()
    if s.startswith("file://"):
        parsed = urllib.parse.urlparse(s)
        s = urllib.parse.unquote(parsed.path)
    if not s:
        target = base.resolve()
    else:
        candidate = pathlib.Path(s).expanduser()
        if not candidate.is_absolute():
            candidate = base / candidate
        if not candidate.exists() and "\\ " in s:
            unescaped = pathlib.Path(s.replace("\\ ", " ")).expanduser()
            if not unescaped.is_absolute():
                unescaped = base / unescaped
            if unescaped.exists():
                candidate = unescaped
        target = candidate.resolve()
    if not target.exists():
        raise ValueError(f"cwd does not exist: {target}")
    if not target.is_dir():
        target = target.parent
    return str(target)


class ConsultService:
    """High-level coordinator for `consult_gemini` calls over a single shared `AcpClient`."""

    def __init__(
        self,
        agy_bin: str = DEFAULT_AGY_BIN,
        gemini_dir: pathlib.Path = DEFAULT_GEMINI_DIR,
    ):
        self.agy_bin = agy_bin
        self.gemini_dir = gemini_dir
        self.acp_app_dir = prepare_acp_app_data_dir(gemini_dir)
        self.client = AcpClient(
            agy_bin=self.agy_bin,
            app_data_dir=ACP_APP_DATA_SUBDIR,
            workspace_cwd=str(pathlib.Path.cwd()),
        )
        self.sessions: dict[str, SessionInfo] = {}
        self._acp_pid: int | None = None

    @property
    def inflight_count(self) -> int:
        return sum(s.inflight for s in self.sessions.values())

    def _session_db_path(self, session_id: str) -> pathlib.Path:
        return self.acp_app_dir / "conversations" / f"{session_id}.db"

    async def close_client_idle_sessions(
        self,
        client_id: str,
        keep_session_id: str | None = None,
        cancel_inflight: bool = False,
    ) -> None:
        """Close sessions belonging to `client_id` without touching other Claude windows."""
        if not client_id:
            return
        targets = [
            s
            for s in list(self.sessions.values())
            if s.client_id == client_id
            and s.session_id != keep_session_id
            and (cancel_inflight or s.inflight == 0)
        ]
        for s in targets:
            self.sessions.pop(s.session_id, None)
            if s.inflight > 0:
                try:
                    await self.client.notify("session/cancel", {"sessionId": s.session_id})
                except Exception:
                    pass
            try:
                await self.client.request("session/close", {"sessionId": s.session_id}, timeout=10.0)
            except Exception:
                pass

    async def sweep_dead_clients_and_ttl(self) -> None:
        """Close idle sessions whose owning MCP client process exited, or that exceeded TTL / LRU cap."""
        now = time.monotonic()
        idle = [s for s in self.sessions.values() if s.inflight == 0]
        to_close: list[str] = []
        for s in idle:
            dead_owner = False
            if s.client_id.isdigit():
                try:
                    os.kill(int(s.client_id), 0)
                except ProcessLookupError:
                    dead_owner = True
                except PermissionError:
                    pass
            if dead_owner or (now - s.last_used) >= IDLE_SESSION_TTL_SEC:
                to_close.append(s.session_id)

        remaining_idle = [s for s in idle if s.session_id not in to_close]
        overflow = len(self.sessions) - len(to_close) - MAX_LIVE_SESSIONS
        if overflow > 0 and remaining_idle:
            remaining_idle.sort(key=lambda s: s.last_used)
            to_close.extend(s.session_id for s in remaining_idle[:overflow])

        for sid in to_close:
            self.sessions.pop(sid, None)
            try:
                await self.client.request("session/close", {"sessionId": sid}, timeout=10.0)
            except Exception:
                pass

    async def _open_or_resume_session(
        self,
        client_id: str,
        session_id: str | None,
        cwd: str,
        model: str,
        effort: str,
        allow_writes: bool,
    ) -> SessionInfo:
        await self.client.ensure_started()
        cur_pid = self.client.proc.pid if self.client.proc else None
        if cur_pid != self._acp_pid:
            self.sessions.clear()
            self._acp_pid = cur_pid

        # Close what has lapsed: sessions past their five minutes, and those whose window has gone.
        # A window's other sessions stay, so consults run side by side can each be followed up.
        await self.sweep_dead_clients_and_ttl()
        target_mode = "accept-edits" if allow_writes else "default"

        info: SessionInfo | None = None
        if session_id:
            # A lapsed session is never loaded again from disk: its cache is gone, and its whole
            # history would be sent again at full price. The caller is told to start fresh.
            info = self.sessions.get(session_id)
            if info is None:
                raise AcpError(
                    f"session {session_id} has expired: a session lasts {IDLE_SESSION_TTL_SEC / 60:.0f} minutes "
                    "after its last reply, the life of its prompt cache. Start a fresh consult without "
                    "`session_id` and restate what it needs.",
                    "EXPIRED",
                )
            info.client_id = client_id or info.client_id
            info.cwd = cwd

        if info is None:
            res = await self.client.request(
                "session/new",
                {
                    "cwd": cwd,
                    "mcpServers": [],
                    "_meta": {"antigravity": {"systemPrompt": {"append": CONSULT_SYSTEM_APPEND}}},
                },
                timeout=60.0,
            )
            new_sid = str(res.get("sessionId") or "")
            if not new_sid:
                raise AcpError("session/new returned no sessionId")
            opts = res.get("configOptions") or []
            cur_model = next((o.get("currentValue") for o in opts if o.get("id") == "model"), "")
            cur_effort = next((o.get("currentValue") for o in opts if o.get("id") == "thought_level"), "")
            cur_mode = next((o.get("currentValue") for o in opts if o.get("id") == "mode"), "default")
            info = SessionInfo(
                session_id=new_sid,
                client_id=client_id,
                cwd=cwd,
                model=str(cur_model or ""),
                effort=str(cur_effort or ""),
                mode=str(cur_mode or "default"),
                gen_cursor=get_max_gen_idx(self._session_db_path(new_sid)),
            )
            self.sessions[new_sid] = info

        if info.model != model:
            await self.client.request(
                "session/set_config_option",
                {"sessionId": info.session_id, "configId": "model", "value": model},
                timeout=30.0,
            )
            info.model = model

        if info.effort != effort:
            await self.client.request(
                "session/set_config_option",
                {"sessionId": info.session_id, "configId": "thought_level", "value": effort},
                timeout=30.0,
            )
            info.effort = effort

        if info.mode != target_mode:
            await self.client.request(
                "session/set_config_option",
                {"sessionId": info.session_id, "configId": "mode", "value": target_mode},
                timeout=30.0,
            )
            info.mode = target_mode

        info.last_used = time.monotonic()
        return info

    async def consult(
        self,
        prompt: str,
        client_id: str = "",
        cwd: str | None = None,
        session_id: str | None = None,
        flash: bool = False,
        effort: str | None = None,
        allow_writes: bool = False,
        on_progress: Callable[[str], None] | None = None,
    ) -> ConsultResult:
        resolved_cwd = normalize_cwd(cwd)
        resolved_model = normalize_model(FLASH_MODEL if flash else DEFAULT_MODEL)
        resolved_effort = (effort or DEFAULT_EFFORT).strip().lower()
        if resolved_effort not in EFFORTS:
            raise ValueError(f"effort must be one of {', '.join(EFFORTS)}; got {effort!r}")

        info = await self._open_or_resume_session(
            client_id=client_id,
            session_id=session_id,
            cwd=resolved_cwd,
            model=resolved_model,
            effort=resolved_effort,
            allow_writes=allow_writes,
        )

        info.inflight += 1
        try:
            async with info.lock:
                db_path = self._session_db_path(info.session_id)
                before_idx = max(info.gen_cursor, get_max_gen_idx(db_path))
                collector = TurnCollector(allow_writes=allow_writes, on_progress=on_progress)
                self.client.attach_turn(info.session_id, collector)
                try:
                    request = self.client.request(
                        "session/prompt",
                        {
                            "sessionId": info.session_id,
                            "prompt": [{"type": "text", "text": prompt}],
                        },
                        timeout=CONSULT_MAX_SEC,
                    )
                    res = await _await_turn(asyncio.create_task(request), collector)
                except (asyncio.CancelledError, AcpError) as exc:
                    if isinstance(exc, asyncio.CancelledError) or exc.kind in ("TIMEOUT", "STALLED"):
                        try:
                            await self.client.notify("session/cancel", {"sessionId": info.session_id})
                        except Exception:
                            pass
                    if isinstance(exc, AcpError):
                        raise _naming_session(exc, info.session_id, collector.answer_text()) from exc
                    raise
                finally:
                    self.client.detach_turn(info.session_id)
        finally:
            info.inflight = max(0, info.inflight - 1)
            info.last_used = time.monotonic()

        full_text = collector.answer_text()
        full_thoughts = "".join(collector.thoughts)

        soft_error = detect_soft_error("".join(collector.texts))
        if soft_error is not None:
            # The label may be wrong; the text never is, so it goes back with the error.
            raise _naming_session(soft_error, info.session_id, full_text)

        usage, new_cursor = read_turn_usage_since(db_path, before_idx)
        info.gen_cursor = new_cursor
        if usage is None and isinstance(res.get("usage"), dict):
            u = res["usage"]
            usage = TurnUsage(
                input_tokens=int(u.get("inputTokens") or 0),
                cached_read_tokens=int(u.get("cachedReadTokens") or 0),
                cached_write_tokens=int(u.get("cachedWriteTokens") or 0),
                output_tokens=int(u.get("outputTokens") or 0),
                thought_tokens=int(u.get("thoughtTokens") or 0),
            )

        return ConsultResult(
            session_id=info.session_id,
            model=info.model,
            effort=info.effort,
            text=full_text,
            thoughts=full_thoughts,
            tool_calls=collector.tool_calls,
            stop_reason=str(res.get("stopReason") or "end_turn"),
            usage=usage,
        )

    async def shutdown(self) -> None:
        for sid in list(self.sessions.keys()):
            try:
                await self.client.request("session/close", {"sessionId": sid}, timeout=5.0)
            except Exception:
                pass
        self.sessions.clear()
        await self.client.stop()
