#!/usr/bin/env python3
"""Loopback relay that keeps an idle agy session's implicit prompt cache warm.

hub-wrapper.sh starts one relay per interactive agy process and points agy's
CLOUD_CODE_URL at it (the CLI has no --cloud_code_endpoint flag; only --hub does).
When agy runs with modelProvider "gemini", the wrapper also points
GOOGLE_GEMINI_BASE_URL here and passes the original as --gemini-upstream (CPA).
Requests then flow through unchanged: /v1internal paths to Cloud Code, the rest to
the Gemini upstream. For each main-session streamGenerateContent the relay
remembers the last body and its headers, keyed by the conversation id that agy
writes into systemInstruction (".../brain/<id>"), and records the time in
/tmp/agy_cache_<id>.dat as "ANCHOR_TS TOUCHES STATUS". Title and safety calls carry
no brain path and are ignored.

statusline.sh reads that file for the cache countdown and, at CACHE_REFRESH_AT
(4m30s by default, 30s before the 5-minute implicit-cache TTL lapses), POSTs
/_touch/<id>. Policy lives in ~/.gemini/antigravity-cli/agy-neo.conf (overridden
by AGY_CACHE_* env vars) and reloads on mtime change. The relay replays the last
body with a fresh requestId, reads the first SSE event (prefill done, cache
touched), and closes the stream. It stops after CACHE_MAX_TOUCHES idle replays or
any failure, until the next request upstream accepts resets it.

The relay prints its port on stdout, then exits when the --parent process does.
The relay never initiates a touch on its own.
"""
import argparse
from dataclasses import dataclass
import fcntl
import glob
import http.client
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

CLOUD_CODE = "https://daily-cloudcode-pa.googleapis.com"
gemini_upstream: str | None = None
DEFAULT_MAX_TOUCHES = 4
DEFAULT_MODELS = ("argon", "carbon", "hydrogen")  # 1M-window Gemini 4 families
DEFAULT_CONF_PATH = Path.home() / ".gemini/antigravity-cli/agy-neo.conf"
FALSE_VALUES = {"0", "false", "off", "no"}


@dataclass(frozen=True)
class RelayPolicy:
    keepalive: bool = True
    max_touches: int = DEFAULT_MAX_TOUCHES
    models: tuple[str, ...] = DEFAULT_MODELS


_conf_cache: tuple[Path, int | None, dict[str, str]] = (DEFAULT_CONF_PATH, None, {})
_conf_lock = threading.Lock()


def _parse_conf(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        else:
            val = re.sub(r"\s+#.*$", "", val)
        values[key] = val
    return values


def get_policy() -> RelayPolicy:
    """Load policy from agy-neo.conf (cached by mtime) with AGY_CACHE_* env overrides."""
    global _conf_cache
    path = Path(os.environ.get("AGY_NEO_CONFIG") or DEFAULT_CONF_PATH)
    try:
        mtime_ns: int | None = path.stat().st_mtime_ns
    except OSError:
        mtime_ns = None
    with _conf_lock:
        cached_path, cached_mtime, file_vals = _conf_cache
        if path != cached_path or mtime_ns != cached_mtime:
            try:
                file_vals = _parse_conf(path.read_text()) if mtime_ns is not None else {}
            except OSError:
                file_vals = {}
            _conf_cache = (path, mtime_ns, file_vals)

    def pick(env_key: str, conf_key: str, default: str) -> str:
        env_val = os.environ.get(env_key)
        if env_val is not None and env_val != "":
            return env_val.strip()
        conf_val = file_vals.get(conf_key)
        return conf_val if conf_val is not None and conf_val != "" else default

    keepalive = pick("AGY_CACHE_KEEPALIVE", "CACHE_KEEPALIVE", "on").lower() not in FALSE_VALUES
    try:
        max_touches = max(0, int(pick("AGY_CACHE_MAX_TOUCHES", "CACHE_MAX_TOUCHES", str(DEFAULT_MAX_TOUCHES))))
    except ValueError:
        max_touches = DEFAULT_MAX_TOUCHES
    models_raw = pick("AGY_CACHE_MODELS", "CACHE_MODELS", ",".join(DEFAULT_MODELS))
    models = tuple(m.strip().lower() for m in models_raw.split(",") if m.strip())
    return RelayPolicy(keepalive=keepalive, max_touches=max_touches, models=models)
LOG_PATH = "/tmp/agy_cache_relay.log"
LOG_KEEP = 200  # ~30KB
SESSION_RE = re.compile(r"brain/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![0-9a-f])")
# A compaction request, manual (/compact) or automatic, ends with a user turn that is this
# instruction, appended by CheckpointHandler after the /compact turn itself. Replaying it would
# only keep the pre-compaction prefix warm, which the next turn no longer uses. Matched at the
# start of a part: user messages begin with <USER_REQUEST>, so one quoting it is not mistaken.
COMPACT_PROMPT = "You have been working on the task described above but have not yet completed"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "te",
              "trailer", "upgrade", "host", "content-length"}

sessions: dict[str, dict] = {}
sessions_lock = threading.Lock()


def log(message: str) -> None:
    """Append to the shared log, keeping only its last LOG_KEEP lines across all relays."""
    line = f"{time.strftime('%m-%d %H:%M:%S')} {message}"
    try:
        with open(LOG_PATH, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            lines = f.read().splitlines()[-(LOG_KEEP - 1):] + [line]
            f.truncate(0)
            f.write("\n".join(lines) + "\n")
    except OSError:
        print(line, file=sys.stderr, flush=True)


def sweep_state(max_age: float = 86400) -> None:
    """Drop state files of conversations untouched for a day; each conversation leaves one."""
    cutoff = time.time() - max_age
    for path in glob.glob("/tmp/agy_cache_*.dat"):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass


def route(path: str) -> tuple[str, str]:
    """(origin, upstream path) for a request path received by the relay."""
    base = CLOUD_CODE if path.startswith("/v1internal") or not gemini_upstream else gemini_upstream
    parts = urlsplit(base)
    return f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/") + path


def connect(origin: str, timeout: float) -> http.client.HTTPConnection:
    parts = urlsplit(origin)
    host = "127.0.0.1" if parts.hostname == "localhost" else parts.hostname  # CPA binds IPv4 only
    cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    return cls(host, parts.port, timeout=timeout)


def write_state(sid: str, anchor: int, touches: int, status: str) -> None:
    path = f"/tmp/agy_cache_{sid}.dat"
    tmp = f"{path}.{os.getpid()}"
    with open(tmp, "w") as f:
        f.write(f"{anchor} {touches} {status}\n")
    os.replace(tmp, path)


def inspect_request(body: bytes) -> tuple[str | None, str, str, bool]:
    """The main session's id, the body's model field, a one-line shape, and whether it is /compact.

    The id is read from systemInstruction only, since contents may quote other paths.
    The shape (model, tool count, turn count, last turn) tells request kinds apart in the
    log, e.g. a compaction call from an ordinary agent step.
    """
    try:
        root = json.loads(body)
    except ValueError:
        return None, "", "", False
    request = root.get("request", root)
    sid = None
    for part in (request.get("systemInstruction") or {}).get("parts") or []:
        if match := SESSION_RE.search(part.get("text", "")):
            sid = match.group(1)
            break
    contents = request.get("contents") or []
    last = contents[-1] if contents else {}
    kinds = ",".join(sorted({key for part in last.get("parts") or [] for key in part if key != "thoughtSignature"}))
    tools = sum(len(t.get("functionDeclarations") or [1]) for t in request.get("tools") or [])
    model = str(root.get("model", ""))
    compact = last.get("role") == "user" and any(
        part.get("text", "").startswith(COMPACT_PROMPT) for part in last.get("parts") or [])
    shape = (f"model={model or '-'} tools={tools} turns={len(contents)} "
             f"last={last.get('role', '-')}:{kinds or '-'} {len(body) // 1024}KB{' compact' if compact else ''}")
    return sid, model, shape, compact


def with_fresh_request_id(body: bytes) -> bytes:
    """Swap the per-request UUID in the top-level requestId; every other byte stays identical.

    agy formats it as agent/<trajectoryId>/<epochMs>/<requestUuid>/<n>, so only the last
    UUID changes and the trajectory id survives.
    """
    request_id = json.loads(body).get("requestId")
    if not isinstance(request_id, str):
        return body
    matches = list(UUID_RE.finditer(request_id))
    if not matches:
        return body
    last = matches[-1]
    fresh = request_id[:last.start()] + str(uuid.uuid4()) + request_id[last.end():]
    old = json.dumps({"requestId": request_id}, separators=(",", ":"))[1:-1].encode()
    new = json.dumps({"requestId": fresh}, separators=(",", ":"))[1:-1].encode()
    return body.replace(old, new, 1)


def touch(sid: str) -> tuple[int, str]:
    policy = get_policy()
    if not policy.keepalive or policy.max_touches <= 0:
        return 403, "keepalive disabled"
    with sessions_lock:
        entry = sessions.get(sid)
    if entry is None or entry["body"] is None:
        return 404, "no captured request"
    if not entry["lock"].acquire(blocking=False):
        return 409, "touch in flight"
    try:
        with sessions_lock:
            if entry["inflight"]:
                return 409, "turn in flight"
            if entry["status"] != "live" or entry["touches"] >= policy.max_touches:
                return 429, f"{entry['status']} after {entry['touches']} touches"
            seq, origin, path, body = entry["seq"], entry["origin"], entry["path"], entry["body"]
            # Plain text, so the first SSE event is visible without decompressing.
            headers = {k: v for k, v in entry["headers"].items() if k.lower() != "accept-encoding"}
        headers["Accept-Encoding"] = "identity"
        conn = connect(origin, timeout=120)
        sent, status, events = int(time.time()), 0, 0
        try:
            conn.request("POST", path, body=with_fresh_request_id(body), headers=headers)
            resp = conn.getresponse()
            status = resp.status
            # The first event proves prefill ran. Streams report cachedContentTokenCount only
            # in the final event, so a hit cannot be confirmed without paying for the whole
            # generation; a miss still re-writes the cache, which is what a touch is for.
            while status == 200 and not events and (chunk := resp.read1(65536)):
                events = chunk.count(b"data:")
        except (OSError, http.client.HTTPException) as err:
            log(f"touch {sid[:8]} error: {err}")
        finally:
            conn.close()  # abort generation after the first event
        with sessions_lock:
            # A real turn that began meanwhile owns the state now, whatever this touch's outcome.
            superseded = entry["seq"] != seq
            if not superseded:
                if status == 200 and events:
                    entry["touches"] += 1
                    entry["anchor"] = sent
                else:
                    entry["status"] = "fail"
                write_state(sid, entry["anchor"], entry["touches"], entry["status"])
        outcome = "superseded by a turn" if superseded else f"-> {entry['status']}"
        log(f"touch {sid[:8]} #{entry['touches']} http={status} {outcome}")
        return 200, json.dumps({"status": entry["status"], "touches": entry["touches"]})
    finally:
        entry["lock"].release()


class Relay(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream: http.client.HTTPConnection | None = None
    upstream_origin = ""

    def log_message(self, *_):
        pass

    def read_body(self) -> bytes:
        if length := self.headers.get("Content-Length"):
            return self.rfile.read(int(length))
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            chunks = []
            while size := int(self.rfile.readline().split(b";")[0], 16):
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            self.rfile.readline()
            return b"".join(chunks)
        return b""

    def reply(self, status: int, text: str) -> None:
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def relay(self) -> None:
        body = self.read_body()
        if self.command == "POST" and self.path.startswith("/_touch/"):
            return self.reply(*touch(self.path.rsplit("/", 1)[-1]))

        started = int(time.time())
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        origin, path = route(self.path)
        if self.upstream is not None and self.upstream_origin != origin:
            self.upstream.close()
            self.upstream = None
        entry, sid, parsed = None, None, False
        try:
            for _ in range(2):
                reused = self.upstream is not None
                if not reused:
                    self.upstream, self.upstream_origin = connect(origin, timeout=600), origin
                try:
                    self.upstream.request(self.command, path, body=body or None, headers=headers)
                    if not parsed:  # parse while upstream prefills, so the hot path pays nothing
                        parsed = True
                        if ":streamGenerateContent" in self.path:
                            sid, model, shape, compact = inspect_request(body)
                            if sid:
                                log(f"turn {sid[:8]} {self.path.split('?')[0].rsplit('/', 1)[-1]} {shape}")
                        if sid:
                            # Only configured CACHE_MODELS are worth keeping warm. The genai path
                            # names the model; Cloud Code bodies carry it in "model".
                            policy = get_policy()
                            target = f"{self.path} {model}".lower()
                            warm = any(m in target for m in policy.models)
                            status = "live" if warm and not compact else "off"
                            # Register the turn: touches wait for it, and one already
                            # waiting on its first event will not commit over it.
                            with sessions_lock:
                                entry = sessions.setdefault(sid, {"lock": threading.Lock(), "inflight": 0, "seq": 0, "body": None})
                                entry["inflight"] += 1
                                entry["seq"] += 1
                    resp = self.upstream.getresponse()
                    break
                except ConnectionError:
                    # Upstreams close idle keep-alive connections; retry once on a fresh one.
                    self.upstream.close()
                    self.upstream = None
                    if not reused:
                        raise
            if entry is not None and resp.status == 200:
                # Commit before streaming: the request is accepted and prefill writes the
                # cache, so even a turn the user interrupts (Esc) is the freshest prefix.
                # A rejected one (4xx/5xx) wrote nothing and leaves the previous state.
                with sessions_lock:
                    entry.update(anchor=started, touches=0, status=status, origin=origin, path=path,
                                 headers=headers, body=body if status == "live" else None)
                    write_state(sid, started, 0, status)
            self.forward(resp)
        except (OSError, http.client.HTTPException) as err:
            self.upstream = None
            log(f"relay error {self.path}: {err!r}")
            if not self.close_connection:
                self.reply(502, json.dumps({"error": str(err)}))
        finally:
            if entry is not None:
                with sessions_lock:
                    entry["inflight"] -= 1
        if os.environ.get("AGY_CACHE_RELAY_DEBUG"):
            log(f"{self.command} {self.path} {len(body)}B session={sid}")

    def forward(self, resp: http.client.HTTPResponse) -> None:
        self.send_response(resp.status, resp.reason)
        for key, value in resp.getheaders():
            if key.lower() not in HOP_BY_HOP:
                self.send_header(key, value)
        bodiless = self.command == "HEAD" or resp.status in (204, 304)
        if not bodiless:
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            while not bodiless and (chunk := resp.read1(65536)):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
            if not bodiless:
                self.wfile.write(b"0\r\n\r\n")
        except (OSError, http.client.HTTPException):
            # Headers are already out, so no 502: drop both sides. Closing upstream also
            # stops generation when the client went away (Esc in the TUI).
            self.upstream.close()
            self.close_connection = True
            raise
        if resp.will_close:
            self.upstream = None

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = relay


def watch_parent(pid: int) -> None:
    while True:
        time.sleep(2)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            os._exit(0)
        except PermissionError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--parent", type=int, required=True, help="exit when this pid exits")
    ap.add_argument("--gemini-upstream", help="original GOOGLE_GEMINI_BASE_URL, for non-/v1internal paths")
    args = ap.parse_args()
    global gemini_upstream
    gemini_upstream = args.gemini_upstream
    sweep_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Relay)
    server.daemon_threads = True
    threading.Thread(target=watch_parent, args=(args.parent,), daemon=True).start()
    print(server.server_port, flush=True)
    log(f"relay :{server.server_port} for pid {args.parent} gemini={gemini_upstream}")
    server.serve_forever()


if __name__ == "__main__":
    main()
