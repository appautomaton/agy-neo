"""Shared Unix-domain-socket Hub daemon so N Claude Code MCP instances share ONE `agy acp` process."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
from typing import Any, Callable

from .service import (
    ACP_APP_DATA_SUBDIR,
    CONSULT_MAX_SEC,
    DEFAULT_GEMINI_DIR,
    ConsultService,
    normalize_cwd,
)

HUB_IDLE_SHUTDOWN_SEC = float(os.environ.get("AGY_CONSULT_HUB_IDLE_SEC", "1800"))


def hub_paths(gemini_dir: pathlib.Path = DEFAULT_GEMINI_DIR) -> tuple[pathlib.Path, pathlib.Path]:
    acp_dir = gemini_dir / ACP_APP_DATA_SUBDIR
    acp_dir.mkdir(parents=True, exist_ok=True)
    return acp_dir / "hub.sock", acp_dir / "hub.lock"


class ConsultHubDaemon:
    """Single-instance local Unix socket server multiplexing `consult_gemini` requests onto one `agy acp`."""

    def __init__(self) -> None:
        self.sock_path, _ = hub_paths()
        self.service = ConsultService()
        self.active_clients = 0
        self.last_activity = time.monotonic()
        self._server: asyncio.AbstractServer | None = None
        self._stop_event = asyncio.Event()
        self._handlers: set[asyncio.Task[Any]] = set()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handler = asyncio.current_task()
        if handler is not None:
            self._handlers.add(handler)
        self.active_clients += 1
        self.last_activity = time.monotonic()
        write_lock = asyncio.Lock()

        async def send_event(payload: dict[str, Any]) -> None:
            async with write_lock:
                if writer.is_closing():
                    return
                writer.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
                await writer.drain()

        try:
            line = await reader.readline()
            if not line:
                return
            req = json.loads(line.decode("utf-8", "replace"))
            op = req.get("op")
            if op == "ping":
                await send_event({"event": "pong", "pid": os.getpid()})
                return
            if op == "client_exit":
                cid = str(req.get("client_id") or "")
                await self.service.close_client_idle_sessions(
                    client_id=cid,
                    keep_session_id=None,
                    cancel_inflight=True,
                )
                await send_event({"event": "closed"})
                return

            loop = asyncio.get_running_loop()
            progress_sends: set[asyncio.Task[None]] = set()

            def on_progress(stage: str) -> None:
                self.last_activity = time.monotonic()
                # The loop holds tasks only weakly: keep each send referenced until it is done.
                task = loop.create_task(send_event({"event": "progress", "stage": stage}))
                progress_sends.add(task)
                task.add_done_callback(progress_sends.discard)

            consult_task = asyncio.create_task(
                self.service.consult(
                    prompt=str(req.get("prompt") or ""),
                    client_id=str(req.get("client_id") or ""),
                    cwd=req.get("cwd"),
                    session_id=req.get("session_id"),
                    flash=bool(req.get("flash", False)),
                    effort=req.get("effort"),
                    allow_writes=bool(req.get("allow_writes", False)),
                    on_progress=on_progress,
                )
            )
            eof_task = asyncio.create_task(reader.read(1))
            try:
                done, _ = await asyncio.wait(
                    {consult_task, eof_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if eof_task in done and not consult_task.done():
                    consult_task.cancel()
                    try:
                        await consult_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    return
                res = await consult_task
            finally:
                if not eof_task.done():
                    eof_task.cancel()
                if not consult_task.done():
                    consult_task.cancel()
            include_thoughts = bool(req.get("include_thoughts", False))
            await send_event(
                {
                    "event": "result",
                    "ok": True,
                    "text": res.format_markdown(include_thoughts=include_thoughts),
                    "session_id": res.session_id,
                    "hub_pid": os.getpid(),
                    "acp_pid": self.service.client.proc.pid if self.service.client.proc else None,
                }
            )
        except Exception as exc:
            await send_event({"event": "result", "ok": False, "error": str(exc)})
        finally:
            if handler is not None:
                self._handlers.discard(handler)
            self.active_clients = max(0, self.active_clients - 1)
            self.last_activity = time.monotonic()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _reaper_loop(self) -> None:
        while not self._stop_event.is_set():
            await asyncio.sleep(30.0)
            await self.service.sweep_dead_clients_and_ttl()
            idle_for = time.monotonic() - self.last_activity
            if self.active_clients == 0 and self.service.inflight_count == 0 and idle_for >= HUB_IDLE_SHUTDOWN_SEC:
                self._stop_event.set()
                break

    async def serve(self) -> None:
        if self.sock_path.exists():
            try:
                self.sock_path.unlink()
            except OSError:
                pass
        self._server = await asyncio.start_unix_server(
            self.handle_client,
            path=str(self.sock_path),
            limit=64 * 1024 * 1024,
        )
        os.chmod(self.sock_path, 0o600)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._stop_event.set)
        reaper = asyncio.create_task(self._reaper_loop())
        try:
            await self._stop_event.wait()
        finally:
            reaper.cancel()
            self._server.close()
            # Dropping each connection cancels its consult, as a caller hanging up would.
            self._server.close_clients()
            await self._server.wait_closed()
            # Let those consults send their `session/cancel` while `agy acp` is still there to take it.
            if self._handlers:
                await asyncio.wait(set(self._handlers), timeout=5.0)
            if self.sock_path.exists():
                try:
                    self.sock_path.unlink()
                except OSError:
                    pass
            await self.service.shutdown()


async def _can_connect(sock_path: pathlib.Path) -> bool:
    if not sock_path.exists():
        return False
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(sock_path)), timeout=1.5)
        writer.write(b'{"op":"ping"}\n')
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=1.5)
        writer.close()
        await writer.wait_closed()
        return b"pong" in line
    except Exception:
        return False


async def ensure_hub_running() -> pathlib.Path:
    """Connect to the singleton Hub socket, spawning the Hub daemon if needed."""
    sock_path, lock_path = hub_paths()
    if await _can_connect(sock_path):
        return sock_path

    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if await _can_connect(sock_path):
            return sock_path

        pkg_root = str(pathlib.Path(__file__).resolve().parent.parent)
        env = dict(os.environ)
        env["PYTHONPATH"] = f"{pkg_root}:{env.get('PYTHONPATH', '')}".rstrip(":")
        subprocess.Popen(
            [sys.executable, "-m", "consult_gemini.hub"],
            cwd=pkg_root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if await _can_connect(sock_path):
                return sock_path
            await asyncio.sleep(0.05)
        raise RuntimeError(f"Failed to start consult_gemini Hub daemon at {sock_path}")
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


async def call_hub_consult(
    arguments: dict[str, Any],
    on_progress: Callable[[str], None] | None = None,
    # The Hub ends every turn within CONSULT_MAX_SEC; the margin covers opening its session first.
    timeout: float = CONSULT_MAX_SEC + 300.0,
) -> dict[str, Any]:
    """Send one `consult` request to the shared Hub daemon and stream progress events."""
    sock_path = await ensure_hub_running()
    reader, writer = await asyncio.open_unix_connection(str(sock_path), limit=64 * 1024 * 1024)
    try:
        resolved_cwd = normalize_cwd(arguments.get("cwd"), fallback_cwd=os.getcwd())
        payload = {"op": "consult", "client_id": str(os.getpid()), **arguments, "cwd": resolved_cwd}
        writer.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        await writer.drain()

        deadline = time.monotonic() + timeout
        while True:
            remaining = max(1.0, deadline - time.monotonic())
            line = await asyncio.wait_for(reader.readline(), timeout=remaining)
            if not line:
                raise RuntimeError("Hub closed connection before returning result")
            event = json.loads(line.decode("utf-8", "replace"))
            kind = event.get("event")
            if kind == "progress":
                if on_progress and event.get("stage"):
                    on_progress(str(event["stage"]))
            elif kind == "result":
                return event
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def notify_hub_client_exit() -> None:
    """Tell the shared Hub that this MCP stdio process is exiting so its sessions can be closed immediately."""
    sock_path, _ = hub_paths()
    if not sock_path.exists():
        return
    try:
        _, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(sock_path)), timeout=1.0)
        payload = {"op": "client_exit", "client_id": str(os.getpid())}
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


def main() -> int:
    try:
        asyncio.run(ConsultHubDaemon().serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
