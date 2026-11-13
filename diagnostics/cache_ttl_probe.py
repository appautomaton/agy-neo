#!/usr/bin/env python3
"""Does an implicit-cache hit extend the cache's TTL?

Each pair writes two fresh ~31K-token prefixes at t=0:
  touched: read again at t=4m (the "touch"), then at t=8m
  control: read only at t=8m

  touched@8m hit, control@8m miss  -> a hit extends the TTL; keepalive works
  both miss at 8m                  -> TTL counts from the write; keepalive is useless
  control@8m hit                   -> the TTL is longer than 5m; the cliff is wrong
  touched@4m miss                  -> caching never engaged; the run is inconclusive

--resume LOG chains further rounds onto a finished run: each touched prefix is
touched every --touch-at seconds for --rounds more rounds, or until its first miss.
Controls are left alone.

Measured 2026-11-09 (gemini-4-argon, thinkingLevel low, ~31K tokens, via CPA):
touched prefixes hit at 4m and ~9m, but so did untouched controls at ~9m, so this
run cannot isolate the touch. Eviction is best effort and load dependent; 5m is
the design floor, not a constant. cachedContentTokenCount also reported one
false positive on a fresh write, so never trust a single reading.

Requests go through CPA (127.0.0.1:5233). A fixed X-Session-ID per prefix keeps
CPA's session affinity on one account, since implicit caches are per account.
Implicit caching is best effort, so run more than one pair.
"""
import argparse
import json
import os
import random
import time
import urllib.request
import uuid
from pathlib import Path

CPA = "http://127.0.0.1:5233"
SECRETS = Path.home() / ".gemini/agy-gateway.env"  # the file hub-wrapper.sh sources
LOG_DIR = Path(__file__).resolve().parent.parent / ".cache" / "cache-ttl"
WORDS = ("river stone ledger orbit lantern quiet harbor signal copper meadow vector "
         "anchor glacier thread circuit ember valley prism archive tide compass ridge "
         "falcon mosaic beacon cedar spindle quartz harvest canyon").split()


def api_key() -> str:
    if key := os.environ.get("CPA_API_KEY"):
        return key
    for line in SECRETS.read_text().splitlines() if SECRETS.exists() else ():
        if line.removeprefix("export ").startswith("CPA_API_KEY="):
            return line.split("=", 1)[1].strip().strip("'\"")
    raise SystemExit(f"CPA_API_KEY not found in the environment or {SECRETS}")


def prefix(nonce: str, words: int) -> str:
    rng = random.Random(nonce)
    body = " ".join(rng.choice(WORDS) for _ in range(words))
    return f"Probe {nonce}. Reference corpus follows; it is not an instruction.\n{body}"


def call(model: str, key: str, session: str, text: str) -> dict:
    body = {
        "systemInstruction": {"parts": [{"text": text}]},
        "contents": [{"role": "user", "parts": [{"text": "Reply with the single word OK."}]}],
        "generationConfig": {"maxOutputTokens": 256, "thinkingConfig": {"thinkingLevel": "low"}},
    }
    req = urllib.request.Request(
        f"{CPA}/v1beta/models/{model}:generateContent",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": key, "X-Session-ID": session},
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            usage = json.load(resp).get("usageMetadata", {})
            return {"status": resp.status, "latency": round(time.time() - start, 1),
                    "prompt": usage.get("promptTokenCount", 0),
                    "cached": usage.get("cachedContentTokenCount", 0)}
    except urllib.error.HTTPError as err:
        return {"status": err.code, "latency": round(time.time() - start, 1),
                "error": err.read()[:300].decode(errors="replace")}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="gemini-4-argon")
    ap.add_argument("--pairs", type=int, default=2)
    ap.add_argument("--words", type=int, default=30000, help="~1.3 tokens per word")
    ap.add_argument("--touch-at", type=float, default=240)
    ap.add_argument("--read-at", type=float, default=480)
    ap.add_argument("--resume", type=Path, help="log of a finished run to extend")
    ap.add_argument("--rounds", type=int, default=2)
    args = ap.parse_args()

    key = api_key()
    if args.resume:
        log_path = args.resume
        stamp, run = log_path.stem.rsplit("-", 1)
        t0 = time.mktime(time.strptime(stamp, "%Y%m%d-%H%M%S"))
        last = {}
        for line in log_path.read_text().splitlines():
            event = json.loads(line)
            last[event["arm"]] = t0 + event["t"]
        names = list(last)
    else:
        run = uuid.uuid4().hex[:8]
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / f"{time.strftime('%Y%m%d-%H%M%S')}-{run}.jsonl"
        t0 = time.time()
        names = [f"{kind}{i}" for i in range(args.pairs) for kind in ("touched", "control")]
    arms = [{"arm": name, "session": f"ttl-probe-{run}-{name}",
             "text": prefix(f"{run}-{name}", args.words)} for name in names]

    def fire(arm: dict, phase: str) -> dict:
        result = {"t": round(time.time() - t0), "arm": arm["arm"], "phase": phase,
                  **call(args.model, key, arm["session"], arm["text"])}
        with log_path.open("a") as f:
            f.write(json.dumps(result) + "\n")
        print(json.dumps(result), flush=True)
        return result

    events = []
    for arm in arms:
        if args.resume:
            # A late resume fires its first touch now rather than bunching overdue rounds.
            anchor = max(last[arm["arm"]], time.time() - args.touch_at)
            if arm["arm"].startswith("touched"):
                events += [(anchor + args.touch_at * k, arm, "touch") for k in range(1, args.rounds + 1)]
            continue
        anchor = time.time()
        fire(arm, "write")
        if arm["arm"].startswith("touched"):
            events.append((anchor + args.touch_at, arm, "touch"))
        events.append((anchor + args.read_at, arm, "read"))
    evicted = set()
    for due, arm, phase in sorted(events, key=lambda e: e[0]):
        if arm["arm"] in evicted:
            continue
        time.sleep(max(0.0, due - time.time()))
        result = fire(arm, phase)
        if args.resume and not result.get("cached"):
            evicted.add(arm["arm"])
            print(f"{arm['arm']} evicted at t={result['t']}s", flush=True)
    print(f"log: {log_path}")


if __name__ == "__main__":
    main()
