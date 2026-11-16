#!/usr/bin/env python3
"""Fail if names that must never appear in this public repository are found in tracked files or inside any tracked
archive (.skill, .zip, .jar: every entry is decompressed and scanned).

  python3 .github/scripts/public-content-guard.py [--extra-archive PATH ...]

The pattern is written with bracket classes so this file does not match itself. To add a term, add it the same way.
"""
import argparse
import io
import re
import subprocess
import sys
import zipfile

PATTERN = re.compile(rb"def[c]on|log-?[c]2|cy[r]oid|stock[s]pan", re.I)
ARCHIVES = (".skill", ".zip", ".jar")


def scan_bytes(label, data, hits, depth=0):
    for m in PATTERN.finditer(data):
        line = data[:m.start()].count(b"\n") + 1
        hits.append("%s:%d: %r" % (label, line, data[max(0, m.start() - 30):m.end() + 30]))
    if depth < 3 and label.lower().endswith(ARCHIVES):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return
        for n in z.namelist():
            scan_bytes("%s!%s" % (label, n), z.read(n), hits, depth + 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extra-archive", action="append", default=[], help="a built archive to scan as well")
    a = ap.parse_args()
    files = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.split(b"\0")
    hits = []
    for f in [x.decode() for x in files if x] + a.extra_archive:
        try:
            with open(f, "rb") as fh:
                data = fh.read()
        except (FileNotFoundError, IsADirectoryError):
            continue
        scan_bytes(f, data, hits)
    for h in hits:
        print("::error::" + h)
    print("%d hit(s) in %d tracked file(s)%s" % (len(hits), len(files) - 1,
          " and %d extra archive(s)" % len(a.extra_archive) if a.extra_archive else ""))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
