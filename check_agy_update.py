#!/usr/bin/env python3
"""Ask the agy updater whether a newer release exists, without touching the installed binary.

`agy update` replaces the patched binary in place. This reads the same manifest it reads and
stops there; `--fetch DIR` also downloads the release into an empty directory, verifies it
against the manifest's SHA-512, and unpacks it there, ready to patch with `--binary`.

Exit status: 0 when up to date, 1 when a newer release exists, 2 on any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import tarfile
import urllib.request

# The base and path that `updater.GetManifestURLFromBase` builds: `%s/manifests/%s_%s%s.json`.
UPDATER_BASE = "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app"
INSTALLED = pathlib.Path.home() / ".local/bin/agy"
ARCHES = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}


def manifest_url() -> str:
    os_name = platform.system().lower()
    arch = ARCHES.get(platform.machine().lower(), platform.machine().lower())
    return f"{UPDATER_BASE}/manifests/{os_name}_{arch}.json"


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.strip().split("."))


def installed_version() -> str:
    out = subprocess.run([str(INSTALLED), "--version"], capture_output=True, text=True, timeout=30)
    return out.stdout.strip().splitlines()[0]


def fetch(manifest: dict, dest: pathlib.Path) -> pathlib.Path:
    """Download the release into `dest`, verify its SHA-512, unpack it, and return its binary."""
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise RuntimeError(f"{dest} is not empty; give an empty directory for the release")
    archive = dest / pathlib.Path(manifest["url"]).name
    digest = hashlib.sha512()
    received, total = 0, None
    # http.client ends a body that stops short without raising, so a dropped connection would
    # otherwise surface as a hash mismatch, which reads as tampering. Resume from where it stopped.
    for _ in range(6):
        request = urllib.request.Request(manifest["url"], headers={"Range": f"bytes={received}-"} if received else {})
        with urllib.request.urlopen(request, timeout=60) as resp:
            if received and resp.status != 206:  # the server ignored the range: start over
                digest, received = hashlib.sha512(), 0
            length = resp.headers.get("Content-Length")
            total = received + int(length) if length is not None else None
            with archive.open("ab" if received else "wb") as out:
                while chunk := resp.read(1 << 20):
                    digest.update(chunk)
                    out.write(chunk)
                    received += len(chunk)
        if total is None or received >= total:
            break
    else:
        archive.unlink()
        raise RuntimeError(f"download cut short at {received:,} of {total:,} bytes after 6 attempts; run it again")
    if digest.hexdigest() != manifest["sha512"].lower():
        archive.unlink()
        raise RuntimeError("SHA-512 mismatch: the download does not match the manifest, and was deleted")
    unpacked = dest / "unpacked"
    with tarfile.open(archive) as tar:
        tar.extractall(unpacked, filter="data")
    binaries = [p for p in unpacked.iterdir() if p.is_file() and os.access(p, os.X_OK)]
    if len(binaries) != 1:
        raise RuntimeError(f"expected one executable in {unpacked}, found {[p.name for p in binaries]}")
    return binaries[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fetch", type=pathlib.Path, metavar="DIR",
                        help="when a newer release exists, download, verify, and unpack it into this empty directory")
    args = parser.parse_args()

    try:
        url = manifest_url()
        with urllib.request.urlopen(url, timeout=20) as resp:
            manifest = json.load(resp)
        latest, current = manifest["version"], installed_version()
        print(f"installed {current}, latest {latest}  ({url})")
        if version_key(latest) <= version_key(current):
            print("Up to date.")
            return 0
        print(f"Newer release: {latest}\n  {manifest['url']}")
        if args.fetch:
            binary = fetch(manifest, args.fetch)
            print(f"Verified and unpacked: {binary}")
            print(f"Patch this copy to try the release, with templates/v{latest}/ in place:")
            patcher = pathlib.Path(__file__).resolve().parent / "patch_agy.py"
            print(f"  python3 {patcher} --apply --binary {binary}")
            print(f"  python3 {patcher} --status -v --binary {binary}")
        return 1
    except Exception as exc:
        print(f"check_agy_update: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
