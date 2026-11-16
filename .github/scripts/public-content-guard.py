#!/usr/bin/env python3
"""Fail if names that must never appear in this public repository are found anywhere in it.

  python3 .github/scripts/public-content-guard.py                       # every tracked file (and its path)
  python3 .github/scripts/public-content-guard.py --commits BASE..HEAD  # ... plus those commit messages
  python3 .github/scripts/public-content-guard.py --files A B --no-tree # only the named files (tests)

What is looked at:
- every tracked file and its path; with --commits, every commit message in the range; --extra-archive files;
- archives found by their signature, not their extension (zip - so jar, docx, xlsx, whl, skill; gzip; bzip2; xz;
  tar inside them), recursively, under a total decompression budget (--budget). Exceeding it is a failure, never a
  silent skip. PDFs are refused outright: their streams can hide anything;
- text decoded as UTF-8, or UTF-16 by BOM or NUL pattern; NFKC-normalised (full-width letters become ASCII); with
  invisible format characters (zero-width space/joiner, soft hyphen, BOM) removed; and again after HTML-entity,
  percent and base64 decoding.

Rules (reported by number only, so the CI log of this public repository never repeats what it caught):
  1-4  the private names, with any run of separators between their parts (space, _, ., -, punctuation);
  5    a GUID whose SHA-256 is in KNOWN_PRIVATE_SHA256 (identifiers that must not be published; only their hashes
       are kept here);
  6    a GUID within 100 characters of a tenant/directory keyword that is not an obvious placeholder (fewer than 8
       distinct hex digits, e.g. 00000000-0000-4000-8000-000000000001). Use a placeholder in docs and tests.

The patterns are written so that this file does not match itself; keep it that way when adding one.
"""
import argparse
import base64
import binascii
import bz2
import hashlib
import html
import io
import lzma
import re
import subprocess
import sys
import tarfile
import unicodedata
import zipfile
import zlib
from urllib.parse import unquote

TERMS = [re.compile(p, re.I) for p in (
    # No lookbehind: a name glued to other letters is still the name. The lookahead keeps ordinary code such as
    # Python's "def configure(" or C's "#undef CONFIG" out.
    r"def[\W_]*con(?:[\W_]*ai|(?![a-z]))",
    r"log[\W_]*c[\W_]*2(?![0-9])",
    r"cy[\W_]*roid",
    r"stock[\W_]*span",
)]
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
TENANT_WORD = re.compile(r"tenant|\btid\b|directory[\W_]*id|microsoftonline|entra[\W_]*id", re.I)
KNOWN_PRIVATE_SHA256 = {
    "01e99522f9aacd25f2502640c0ef4e6543eba06bf8556f518a3e3c4223d8c200",
}
B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{8,}={0,2}")
DEFAULT_BUDGET = 512 * 1024 * 1024


class BudgetExceeded(Exception):
    pass


class Scanner:
    def __init__(self, budget):
        self.budget = budget
        self.hits = []

    # ---- text --------------------------------------------------------------------------------------------
    @staticmethod
    def decode(data):
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return [data.decode("utf-16", "replace")]
        out = [data.decode("utf-8", "replace")]
        sample = data[:4096]
        if len(sample) >= 4 and sample.count(0) * 4 >= len(sample):      # NUL pattern: UTF-16 without a BOM
            out += [data.decode("utf-16-le", "replace"), data.decode("utf-16-be", "replace")]
        return out

    @staticmethod
    def normalise(text):
        text = unicodedata.normalize("NFKC", text)
        return "".join(c for c in text if unicodedata.category(c) != "Cf")

    def text_variants(self, text):
        seen = set()
        cands = [text]
        if "&" in text or "%" in text:
            cands += [html.unescape(text), unquote(text), unquote(html.unescape(text)), html.unescape(unquote(text))]
        for t in cands:
            t = self.normalise(t)
            if t not in seen:
                seen.add(t)
                yield t

    def check_text(self, where, text):
        for t in self.text_variants(text):
            for i, rx in enumerate(TERMS, 1):
                if rx.search(t):
                    self.hit(where, "rule %d (private name)" % i)
            for m in GUID.finditer(t):
                g = m.group(0).lower()
                if hashlib.sha256(g.encode()).hexdigest() in KNOWN_PRIVATE_SHA256:
                    self.hit(where, "rule 5 (a known private identifier)")
                elif len(set(g.replace("-", ""))) >= 8 and TENANT_WORD.search(t[max(0, m.start() - 100):m.end() + 100]):
                    self.hit(where, "rule 6 (a real-looking GUID next to a tenant/directory keyword - use a placeholder)")

    def hit(self, where, what):
        h = "%s: %s" % (where, what)
        if h not in self.hits:
            self.hits.append(h)

    # ---- containers ---------------------------------------------------------------------------------------
    def spend(self, n):
        self.budget -= n
        if self.budget < 0:
            raise BudgetExceeded()

    def inflate(self, fn, data):
        """Decompress with the remaining budget as a hard cap."""
        out = fn(data, self.budget + 1)
        self.spend(len(out))
        return out

    @staticmethod
    def _gunzip(data, cap):
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, cap)
        while not d.unconsumed_tail and d.unused_data[:2] == b"\x1f\x8b" and len(out) < cap:   # concatenated members
            rest = d.unused_data
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out += d.decompress(rest, cap - len(out))
        return out

    @staticmethod
    def _stream(decomp_cls):
        def run(data, cap):
            return decomp_cls().decompress(data, max_length=cap)
        return run

    def scan(self, where, data, depth=0):
        if data[:5] == b"%PDF-":
            self.hit(where, "a PDF - PDFs are refused (their compressed streams cannot be checked reliably)")
            return
        if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            try:
                z = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                self.hit(where, "an unreadable zip archive")
                return
            for info in z.infolist():
                self.check_text("%s!%s" % (where, info.filename), info.filename)
                if info.file_size > self.budget:
                    raise BudgetExceeded()
                with z.open(info) as fh:
                    member = fh.read(self.budget + 1)
                self.spend(len(member))
                self.scan("%s!%s" % (where, info.filename), member, depth + 1)
            return
        for magic, fn, label in ((b"\x1f\x8b", self._gunzip, "gzip"), (b"BZh", self._stream(bz2.BZ2Decompressor), "bzip2"),
                                 (b"\xfd7zXZ\x00", self._stream(lzma.LZMADecompressor), "xz")):
            if data.startswith(magic):
                try:
                    inner = self.inflate(fn, data)
                except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError):
                    self.hit(where, "an unreadable %s stream" % label)
                    return
                self.scan("%s!(%s)" % (where, label), inner, depth + 1)
                return
        if len(data) > 262 and data[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as t:
                    for m in t.getmembers():
                        self.check_text("%s!%s" % (where, m.name), m.name)
                        if m.isfile():
                            self.scan("%s!%s" % (where, m.name), t.extractfile(m).read(), depth + 1)
            except tarfile.TarError:
                self.hit(where, "an unreadable tar archive")
            return
        for text in self.decode(data):
            self.check_text(where, text)
        # base64 runs: decoded, then scanned like any other content (archives inside included)
        if depth < 8:
            for m in B64_RUN.finditer(data):
                run = m.group(0)
                for dec in (base64.b64decode, base64.urlsafe_b64decode):
                    try:
                        raw = dec(run + b"=" * (-len(run) % 4))
                    except (binascii.Error, ValueError):
                        continue
                    if not raw or not self.worth_decoding(raw):
                        continue
                    self.spend(len(raw))
                    self.scan("%s(base64@%d)" % (where, m.start()), raw, depth + 1)

    MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"%PDF-", b"\xff\xfe", b"\xfe\xff")

    @classmethod
    def worth_decoding(cls, raw):
        """Base64 that decodes to text or to a container; random identifiers decode to binary noise."""
        if raw.startswith(cls.MAGICS):
            return True
        text = raw.decode("utf-8", "replace")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return printable >= 0.85 * len(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--commits", metavar="RANGE", help="also scan the messages of these commits (git log RANGE)")
    ap.add_argument("--extra-archive", action="append", default=[], help="a built file to scan as well")
    ap.add_argument("--files", nargs="*", default=[], help="scan these files")
    ap.add_argument("--no-tree", action="store_true", help="do not scan the tracked files")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="total bytes the scan may decompress or decode")
    a = ap.parse_args()
    s = Scanner(a.budget)
    paths = list(a.files) + list(a.extra_archive)
    if not a.no_tree:
        out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
        paths += [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
    try:
        for p in paths:
            s.check_text("%s (path)" % p, p)
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
            except (FileNotFoundError, IsADirectoryError):
                continue
            s.spend(len(data))
            s.scan(p, data)
        if a.commits:
            log = subprocess.run(["git", "log", "--format=%H%x00%B%x00", a.commits], capture_output=True, check=True).stdout
            parts = log.split(b"\0")
            for sha, msg in zip(parts[0::2], parts[1::2]):
                s.scan("commit %s message" % sha.strip().decode()[:12], msg)
    except BudgetExceeded:
        print("::error::scan budget of %d bytes exceeded - an archive or encoding expands too far to check; "
              "refusing rather than skipping it" % a.budget)
        return 1
    for h in s.hits:
        print("::error::" + h)
    print("%d finding(s); %d path(s)%s scanned" % (len(s.hits), len(paths), " and commits %s" % a.commits if a.commits else ""))
    return 1 if s.hits else 0


if __name__ == "__main__":
    sys.exit(main())
