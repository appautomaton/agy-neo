"""Zero-dependency Model Context Protocol (MCP) thin stdio client forwarding to the shared `consult_gemini` Hub."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Any

from .hub import call_hub_consult, notify_hub_client_exit

DEFAULT_MCP_PROTOCOL_VERSION = "2024-11-05"

# What every client reads at connection, whether or not it has loaded the tool.
SERVER_INSTRUCTIONS = (
    "Gemini as a second opinion that reads the workspace itself. Use it for an independent review, a diagnosis, "
    "or to attack a plan. Its answer is a lead to verify, never a source. A consult that reads code takes "
    "minutes: ask once, with everything it needs. Follow up within 5 minutes of a reply, while its cache is warm; "
    "later, start fresh."
)

TOOL_DEFINITION: dict[str, Any] = {
    "name": "consult_gemini",
    "description": (
        "Consult Gemini 4 Carbon (high effort, 512K context) through the shared local Antigravity hub. It reads "
        "the workspace itself (`read_file`, `grep_search`, `find_by_name`, `list_dir`), read-only unless "
        "`allow_writes`.\n\n"
        "Brief it as a peer who knows nothing of this session: the goal, the paths to read, the data you have, "
        "what is ruled out, the question, a word limit. For an independent view, give facts and withhold your "
        "conclusion; to test a plan, state it and ask what is wrong with it. One topic to a consult; separate "
        "topics run as parallel fresh consults.\n\n"
        "A consult that reads code runs for minutes and may move to the background. Check what it cites before "
        "acting on it.\n\n"
        "Follow-ups: pass the `session_id` from the reply's header within 5 minutes of that reply. Its prompt "
        "cache lasts that long; after it, continuing would send the whole conversation again at full price, so "
        "the session is closed and the call refused: start a fresh consult and restate what it needs."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": (
                    "The question, review, diagnosis or verification for Gemini. It reads and searches the "
                    "workspace itself: name paths and symbols instead of pasting files."
                ),
            },
            "cwd": {
                "type": "string",
                "description": "Absolute path to the workspace directory Gemini should inspect. Defaults to current working directory.",
            },
            "session_id": {
                "type": "string",
                "description": (
                    "The `session_id` from the previous reply's header, to follow up on it within 5 minutes. "
                    "Omit for a new topic."
                ),
            },
            "flash": {
                "type": "boolean",
                "description": "Ask Gemini 3.8 Flash instead of Gemini 4 Carbon, for a quick, cheap question (default: false).",
            },
            "effort": {
                "type": "string",
                "enum": ["high", "medium"],
                "description": "Thinking effort (default: 'high').",
            },
            "allow_writes": {
                "type": "boolean",
                "description": (
                    "Allow Gemini to edit files or run commands in the workspace (default: false, strictly read-only). "
                    "Keep false for reviews/consultations; if set to true, re-read any modified files afterward."
                ),
            },
            "include_thoughts": {
                "type": "boolean",
                "description": "Include Gemini's internal <thinking> chain-of-thought in the returned text (default: false).",
            },
        },
        "required": ["prompt"],
        "additionalProperties": False,
    },
}


class McpStdioServer:
    def __init__(self) -> None:
        self._write_lock = asyncio.Lock()
        self._inflight: dict[Any, asyncio.Task[None]] = {}

    def _write_line(self, message: dict[str, Any]) -> None:
        raw = json.dumps(message, ensure_ascii=False) + "\n"
        sys.stdout.buffer.write(raw.encode("utf-8"))
        sys.stdout.buffer.flush()

    async def send(self, message: dict[str, Any]) -> None:
        async with self._write_lock:
            self._write_line(message)

    async def handle_message(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        if req_id is None:
            if method == "notifications/cancelled":
                cancel_id = params.get("requestId")
                target = self._inflight.get(cancel_id)
                if target is not None and not target.done():
                    target.cancel()
            return

        if method == "initialize":
            client_proto = params.get("protocolVersion")
            proto = client_proto if isinstance(client_proto, str) and client_proto else DEFAULT_MCP_PROTOCOL_VERSION
            await self.send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": proto,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "consult-gemini", "version": "1.1.0"},
                        "instructions": SERVER_INSTRUCTIONS,
                    },
                }
            )
            return

        if method == "ping":
            await self.send({"jsonrpc": "2.0", "id": req_id, "result": {}})
            return

        if method == "tools/list":
            await self.send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": [TOOL_DEFINITION]}})
            return

        if method in ("resources/list", "prompts/list"):
            key = "resources" if method.startswith("resources") else "prompts"
            await self.send({"jsonrpc": "2.0", "id": req_id, "result": {key: []}})
            return

        if method == "tools/call":
            await self._handle_tool_call(req_id, params)
            return

        await self.send(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )

    async def _handle_tool_call(self, req_id: Any, params: dict[str, Any]) -> None:
        name = params.get("name")
        if name != "consult_gemini":
            await self.send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown tool: {name}"},
                }
            )
            return

        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        prompt = str(args.get("prompt") or "").strip()
        if not prompt:
            await self.send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "Error: `prompt` must be a non-empty string."}],
                        "isError": True,
                    },
                }
            )
            return

        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        progress_token = meta.get("progressToken")
        loop = asyncio.get_running_loop()
        step_counter = 0
        last_progress_at = 0.0
        progress_sends: set[asyncio.Task[None]] = set()

        def on_progress(stage: str) -> None:
            nonlocal step_counter, last_progress_at
            if progress_token is None:
                return
            now = time.monotonic()
            if now - last_progress_at < 2.0 and not stage.startswith("tool:"):
                return
            last_progress_at = now
            step_counter += 1
            # The loop holds tasks only weakly: keep each send referenced until it is done.
            task = loop.create_task(
                self.send(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {
                            "progressToken": progress_token,
                            "progress": step_counter,
                            "message": stage,
                        },
                    }
                )
            )
            progress_sends.add(task)
            task.add_done_callback(progress_sends.discard)

        try:
            res = await call_hub_consult(args, on_progress=on_progress)
            if not res.get("ok"):
                raise RuntimeError(res.get("error") or "Unknown Hub error")
            await self.send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": str(res.get("text") or "")}],
                        "isError": False,
                    },
                }
            )
        except asyncio.CancelledError:
            return
        except Exception as exc:
            await self.send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"consult_gemini error: {exc}"}],
                        "isError": True,
                    },
                }
            )

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=64 * 1024 * 1024)
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
        tasks: set[asyncio.Task[None]] = set()
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    msg = json.loads(text)
                except ValueError:
                    continue
                if isinstance(msg, dict):
                    req_id = msg.get("id")
                    task = asyncio.create_task(self.handle_message(msg))
                    tasks.add(task)
                    if req_id is not None:
                        self._inflight[req_id] = task
                    task.add_done_callback(
                        lambda t, rid=req_id: (tasks.discard(t), self._inflight.pop(rid, None))
                    )
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await notify_hub_client_exit()


def main() -> int:
    try:
        asyncio.run(McpStdioServer().run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
