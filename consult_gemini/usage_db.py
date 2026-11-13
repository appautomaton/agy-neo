"""Read per-step token usage and timing from Antigravity's local SQLite conversation store.

`agy acp` writes one row per generation into `<app-data-dir>/conversations/<sessionId>.db`
(table `gen_metadata`, Protobuf blob `metadata`). Decoding it gives exact `inputTokens`,
`cachedReadTokens`, `outputTokens`, `thoughtTokens`, TTFT, and decode throughput (TPS).
"""

from __future__ import annotations

import pathlib
import sqlite3
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class TurnUsage:
    input_tokens: int = 0
    cached_read_tokens: int = 0
    cached_write_tokens: int = 0
    output_tokens: int = 0
    thought_tokens: int = 0
    ttft_seconds: float = 0.0
    stream_tps: float = 0.0
    steps: int = 0

    def format_summary(self) -> str:
        parts = []
        total_in = self.input_tokens + self.cached_read_tokens
        if total_in > 0:
            cache_pct = int(round(100.0 * self.cached_read_tokens / total_in))
            parts.append(f"in={total_in:,} ({cache_pct}% cached)")
        if self.output_tokens > 0 or self.thought_tokens > 0:
            parts.append(f"out={self.output_tokens:,} (thought={self.thought_tokens:,})")
        if self.ttft_seconds > 0:
            parts.append(f"ttft={self.ttft_seconds:.1f}s")
        if self.stream_tps > 0:
            parts.append(f"tps={self.stream_tps:.0f}")
        return ", ".join(parts) if parts else "n/a"


def _read_varint(buf: bytes, pos: int) -> tuple[int, int] | None:
    val = 0
    shift = 0
    for i in range(10):
        if pos + i >= len(buf):
            return None
        b = buf[pos + i]
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos + i + 1
        shift += 7
    return None


def _iter_proto_fields(buf: bytes):
    pos = 0
    n = len(buf)
    while pos < n:
        tag_res = _read_varint(buf, pos)
        if tag_res is None:
            return
        tag, pos = tag_res
        field_no, wire = tag >> 3, tag & 0x7
        if field_no <= 0:
            return
        if wire == 0:
            val_res = _read_varint(buf, pos)
            if val_res is None:
                return
            val, pos = val_res
            yield field_no, wire, val
        elif wire == 2:
            len_res = _read_varint(buf, pos)
            if len_res is None:
                return
            length, pos = len_res
            if length < 0 or pos + length > n:
                return
            yield field_no, wire, buf[pos : pos + length]
            pos += length
        elif wire == 1:
            if pos + 8 > n:
                return
            pos += 8
        elif wire == 5:
            if pos + 4 > n:
                return
            pos += 4
        else:
            return


def _parse_timestamp(buf: bytes) -> float:
    sec = 0
    nanos = 0
    for fno, wire, val in _iter_proto_fields(buf):
        if wire == 0 and fno == 1:
            sec = struct.unpack("<q", struct.pack("<Q", val & ((1 << 64) - 1)))[0]
        elif wire == 0 and fno == 2:
            nanos = struct.unpack("<q", struct.pack("<Q", val & ((1 << 64) - 1)))[0]
    return float(sec) + float(nanos) / 1e9


def _parse_model_usage(buf: bytes) -> dict[str, int]:
    out = {"in": 0, "out": 0, "cache_write": 0, "cache_read": 0, "thought": 0}
    for fno, wire, val in _iter_proto_fields(buf):
        if wire != 0:
            continue
        if fno == 2:
            out["in"] = max(0, val)
        elif fno == 3:
            out["out"] = max(0, val)
        elif fno == 4:
            out["cache_write"] = max(0, val)
        elif fno == 5:
            out["cache_read"] = max(0, val)
        elif fno == 9:
            out["thought"] = max(0, val)
    return out


def _decode_gen_metadata_blob(blob: bytes) -> tuple[dict[str, int], float, float] | None:
    """Decode one `gen_metadata.data` row into (usage_dict, ttft_s, stream_s)."""
    inner = None
    for fno, wire, val in _iter_proto_fields(blob):
        if fno == 1 and wire == 2:
            inner = val
    if not inner:
        return None
    usage = None
    ttft = 0.0
    stream_s = 0.0
    for fno, wire, val in _iter_proto_fields(inner):
        if wire == 2:
            if fno == 4:
                usage = _parse_model_usage(val)
            elif fno == 11:
                ttft = max(0.0, _parse_timestamp(val))
            elif fno == 12:
                stream_s = max(0.0, _parse_timestamp(val))
    if not usage or (usage["in"] + usage["cache_read"] + usage["out"] + usage["thought"] == 0):
        return None
    return usage, ttft, stream_s


def get_max_gen_idx(db_path: pathlib.Path) -> int:
    if not db_path.exists():
        return -1
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
        try:
            row = conn.execute("SELECT MAX(idx) FROM gen_metadata").fetchone()
            return int(row[0]) if row and row[0] is not None else -1
        finally:
            conn.close()
    except Exception:
        return -1


def read_turn_usage_since(db_path: pathlib.Path, after_idx: int) -> tuple[TurnUsage | None, int]:
    """Read and aggregate all `gen_metadata` rows with `idx > after_idx`."""
    if not db_path.exists():
        return None, after_idx
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
        try:
            rows = conn.execute(
                "SELECT idx, data FROM gen_metadata WHERE idx > ? ORDER BY idx ASC",
                (after_idx,),
            ).fetchall()
        finally:
            conn.close()
    except Exception:
        return None, after_idx

    if not rows:
        return None, after_idx

    max_idx = after_idx
    tot_in = tot_cr = tot_cw = tot_out = tot_th = 0
    first_ttft = 0.0
    tot_stream_s = 0.0
    steps = 0

    for idx, raw in rows:
        idx_int = int(idx)
        if idx_int > max_idx:
            max_idx = idx_int
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            continue
        decoded = _decode_gen_metadata_blob(bytes(raw))
        if decoded is None:
            continue
        u, ttft, stream_s = decoded
        steps += 1
        tot_in += u["in"]
        tot_cr += u["cache_read"]
        tot_cw += u["cache_write"]
        tot_out += u["out"]
        tot_th += u["thought"]
        if steps == 1 and ttft > 0:
            first_ttft = ttft
        tot_stream_s += stream_s

    if steps == 0:
        return None, max_idx

    gen_tokens = tot_out + tot_th
    tps = (gen_tokens / tot_stream_s) if tot_stream_s > 0.05 else 0.0
    return (
        TurnUsage(
            input_tokens=tot_in,
            cached_read_tokens=tot_cr,
            cached_write_tokens=tot_cw,
            output_tokens=tot_out,
            thought_tokens=tot_th,
            ttft_seconds=first_ttft,
            stream_tps=tps,
            steps=steps,
        ),
        max_idx,
    )
