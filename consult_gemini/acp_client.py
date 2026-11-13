"""Async JSON-RPC 2.0 client managing a persistent `agy acp` subprocess."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable


_VERIFY_RE = re.compile(r"^\s*⚠?\s*Verification Required\s*$|Verify your account to continue", re.I)
_BLOCK_RE = re.compile(
    r"^\s*The prompt could not be submitted|Generative AI Prohibited Use policy|prompt contains sensitive words",
    re.I,
)
# agy reports each failed attempt at a model request on a line of its own, then retries by itself.
# Only "Agent execution terminated due to error" means it has given up.
_RETRY_NOTICE_RE = re.compile(r"^\s*⚠\s*API error \(attempt (\d+)\):[ \t]*([^\n]*)(?:\n|$)", re.M)
_TERMINATED_RE = re.compile(r"\s*⚠\s*Agent execution terminated due to error")


class AcpError(RuntimeError):
    def __init__(self, message: str, kind: str = "SERVER"):
        super().__init__(message)
        self.kind = kind


def split_retry_notices(text: str) -> tuple[str, list[str]]:
    """Separate agy's retry notices from the answer, returning the answer and each notice's detail."""
    notices = [m.group(2).strip() for m in _RETRY_NOTICE_RE.finditer(text)]
    return _RETRY_NOTICE_RE.sub("", text), notices


def detect_soft_error(text: str) -> AcpError | None:
    """Read a finished turn's text for the canned errors Antigravity sends as ordinary text.

    Only agy decides when a turn is over; this is read once it is, and only labels the outcome.
    Retry notices followed by no answer mean agy's retries ran out.
    """
    answer, notices = split_retry_notices(text)
    head = answer[:600]
    if _BLOCK_RE.search(head):
        return AcpError(f"Blocked by Antigravity prompt filter: {head[:200].strip()}", "BLOCKED")
    if _VERIFY_RE.search(head):
        return AcpError(f"Account verification required: {head[:160].strip()}", "VERIFY")
    if _TERMINATED_RE.match(answer) or (notices and not answer.strip()):
        detail = notices[-1] if notices else "agent execution terminated"
        tries = f" after {len(notices)} failed attempt{'s' if len(notices) != 1 else ''}" if notices else ""
        return AcpError(f"Antigravity upstream API error{tries}: {detail[:240]}", "UPSTREAM_ERROR")
    return None


@dataclass
class TurnCollector:
    allow_writes: bool = False
    on_progress: Callable[[str], None] | None = None
    thoughts: list[str] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)
    # When the turn last showed signs of life: its start, then every update of any kind.
    last_update: float = field(default_factory=time.monotonic)

    def answer_text(self) -> str:
        """The reply as written so far, without agy's retry notices."""
        return split_retry_notices("".join(self.texts))[0]

    def on_update(self, update: dict[str, Any]) -> None:
        self.last_update = time.monotonic()
        kind = update.get("sessionUpdate")
        if kind == "agent_thought_chunk":
            content = update.get("content") or {}
            text = content.get("text") if isinstance(content, dict) else ""
            if text:
                self.thoughts.append(text)
                if self.on_progress:
                    self.on_progress("thinking")
        elif kind == "agent_message_chunk":
            content = update.get("content") or {}
            text = content.get("text") if isinstance(content, dict) else ""
            if text:
                self.texts.append(text)
                if self.on_progress:
                    retry = _RETRY_NOTICE_RE.search(text)
                    self.on_progress(f"retrying after: {retry.group(2).strip()[:120]}" if retry else "writing")
        elif kind == "tool_call":
            title = update.get("title") or update.get("kind") or "tool"
            self.tool_calls.append(str(title))
            if self.on_progress:
                self.on_progress(f"tool:{title}")


class AcpClient:
    """Manages one persistent `agy acp` front process and multiplexes sessions over stdio."""

    def __init__(self, agy_bin: str, app_data_dir: str, workspace_cwd: str):
        self.agy_bin = agy_bin
        self.app_data_dir = app_data_dir
        self.workspace_cwd = workspace_cwd
        self.proc: asyncio.subprocess.Process | None = None
        self.init_result: dict[str, Any] | None = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._turns: dict[str, TurnCollector] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None and self.init_result is not None

    async def ensure_started(self) -> dict[str, Any]:
        async with self._lock:
            if self.alive and self.init_result is not None:
                return self.init_result
            await self._start_locked()
            assert self.init_result is not None
            return self.init_result

    async def _start_locked(self) -> None:
        await self.stop()
        env = dict(os.environ)
        # Disable background cache_relay.py touches for MCP; native 5m implicit cache covers immediate follow-ups.
        env["AGY_CACHE_RELAY"] = "off"
        # Route through the local CLIProxyAPI gateway (hub-wrapper.sh), not Cloud Code. The picker then
        # offers AGY_LLM_GATEWAY_MODELS base IDs (gemini-4-carbon, gemini-4-argon, gemini-3.8-flash);
        # AGY_ACP_GATEWAY=0 in the caller's environment restores Cloud Code.
        env.setdefault("AGY_ACP_GATEWAY", "1")
        argv = [
            self.agy_bin,
            "acp",
            "--app-data-dir",
            self.app_data_dir,
            "--disable-telemetry",
        ]
        self.proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=self.workspace_cwd,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=64 * 1024 * 1024,
        )
        self._reader_task = asyncio.create_task(self._reader_loop())
        self.init_result = await self.request(
            "initialize",
            {
                "protocolVersion": 1,
                "clientCapabilities": {
                    "fs": {"readTextFile": False, "writeTextFile": False},
                    "terminal": False,
                },
                "clientInfo": {"name": "zed", "version": "1.0.0"},
            },
            timeout=60.0,
        )

    async def _reader_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue

                if "id" in msg and ("result" in msg or "error" in msg) and "method" not in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            err = msg["error"] or {}
                            text = str(err.get("message") or err)
                            if err.get("data"):
                                text += f" | {json.dumps(err['data'], ensure_ascii=False)[:400]}"
                            fut.set_exception(AcpError(text))
                        else:
                            fut.set_result(msg.get("result") or {})
                elif msg.get("method") == "session/update":
                    params = msg.get("params") or {}
                    sid = params.get("sessionId")
                    collector = self._turns.get(sid) if isinstance(sid, str) else None
                    if collector is not None:
                        collector.on_update(params.get("update") or {})
                elif "method" in msg and "id" in msg:
                    await self._handle_agent_request(msg)
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(AcpError("agy acp process exited unexpectedly", "TRANSPORT"))
            self._pending.clear()
            self.init_result = None

    async def _handle_agent_request(self, msg: dict[str, Any]) -> None:
        req_id = msg["id"]
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "session/request_permission":
            sid = params.get("sessionId")
            collector = self._turns.get(sid) if isinstance(sid, str) else None
            options = params.get("options") or []
            if collector is not None and collector.allow_writes and options:
                allow_opt = next(
                    (
                        o
                        for o in options
                        if "allow" in str(o.get("kind", "")).lower() or "allow" in str(o.get("optionId", "")).lower()
                    ),
                    options[0],
                )
                outcome = {"outcome": "selected", "optionId": allow_opt["optionId"]}
            else:
                outcome = {"outcome": "cancelled"}
            await self._send({"jsonrpc": "2.0", "id": req_id, "result": {"outcome": outcome}})
        else:
            await self._send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not supported: {method}"},
                }
            )

    async def _send(self, payload: dict[str, Any]) -> None:
        async with self._write_lock:
            if not self.proc or not self.proc.stdin or self.proc.stdin.is_closing():
                raise AcpError("agy acp stdin is not open", "TRANSPORT")
            self.proc.stdin.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            await self.proc.stdin.drain()

    async def request(self, method: str, params: dict[str, Any], timeout: float = 300.0) -> dict[str, Any]:
        self._next_id += 1
        rid = self._next_id
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            raise AcpError(f"ACP request {method} timed out after {timeout:.0f}s", "TIMEOUT")
        finally:
            self._pending.pop(rid, None)

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def attach_turn(self, session_id: str, collector: TurnCollector) -> None:
        self._turns[session_id] = collector

    def detach_turn(self, session_id: str) -> None:
        self._turns.pop(session_id, None)

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.proc.kill()
        self.proc = None
        self.init_result = None
