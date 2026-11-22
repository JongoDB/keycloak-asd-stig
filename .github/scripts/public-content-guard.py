#!/usr/bin/env python3
"""Fail if names that must never appear in this public repository are found anywhere in it.

  python3 .github/scripts/public-content-guard.py                       # every tracked file (and its path)
  python3 .github/scripts/public-content-guard.py --commits BASE..HEAD  # ... plus those commit messages
  python3 .github/scripts/public-content-guard.py --files A B --no-tree # only the named files (tests)

What is looked at:
- every tracked file and its path; with --commits, every commit message in the range; --extra-archive files;
- containers recognised by a full signature, never by extension: zip (a valid local header, or an
  end-of-central-directory record anywhere - so jar, docx, xlsx, whl, skill, self-extracting files and prepended
  junk), gzip, bzip2, xz, and tar inside them. They are opened recursively under a total decompression budget
  (--budget); exceeding it fails the run. Decompression runs chunk by chunk, so a stream that breaks part-way still
  has everything before the break scanned, and a container that cannot be read completely is itself a finding
  (fail closed), also when it was found inside decoded base64;
- refused outright, by signature: PDFs (a header in the first 1 KB, or object and cross-reference structure
  anywhere), OLE2 compound files (.doc, .xls, .ppt, .msg), and archives this script cannot open (7z, zstd, RAR,
  LZ4) - their content cannot be checked, so they must not be committed;
- Office and ODF documents (XML inside a zip): each XML member is also checked with its tags removed and its text
  joined, so a name split across runs (<w:t>Def</w:t><w:t>...) is still seen; PNG text chunks (tEXt, zTXt, iTXt,
  compressed or not); e-mail bodies in quoted-printable (soft line breaks removed);
- text: UTF-8, Latin-1 (every byte as a character, so nothing is skipped as "binary") and UTF-16 (BOM or NUL
  pattern) decodings; NFKC-normalised (full-width letters become ASCII); invisible format characters (zero-width
  space/joiner, soft hyphen, BOM) removed; and again after HTML-entity, percent, JSON \\u and RTF \\'hh escapes
  and base64 decoding. Base64 is
  decoded per run at all four alignments, and line-wrapped base64 blocks are joined and decoded as one.

Rules (reported by number only, so the CI log of this public repository never repeats what it caught):
  1-4  the private names, with any run of separators between their parts (space, _, ., -, punctuation);
  5    a GUID whose SHA-256 is in KNOWN_PRIVATE_SHA256 (identifiers that must not be published; only their hashes
       are kept here);
  6    a GUID within 100 characters of a tenant/directory keyword that is not an obvious placeholder (fewer than 8
       distinct hex digits, e.g. 00000000-0000-4000-8000-000000000001). Use a placeholder in docs and tests.
  7    an abbreviation of a private name left behind by a rename (case-blind; spelled here with hyphens so this file
       does not match itself): l-c-2 glued or not; lower-case l-c_<name> (not the locale's l-c_all; upper-case L-C_* are POSIX locale categories); l-c-sec, l-c-t, l-c-x, l-c-m;
       c-y<...>user (not cyber-user); no-c-y, no-d-a-i; lab.c-y.<tag>; c-y = ... . Checked only on plain UTF-8 text (not decoded base64,
       binary data or PNG chunks), and ignored inside long base64-like runs, where random letters would trip it.

Threat model and limits. This is a safety net against ACCIDENTAL leaks: a name pasted into a comment, test,
default value, commit message, generated report or packaged archive, including in the encodings that tooling
produces on its own (archives, base64 payloads, UTF-16, HTML entities, wrapped lines). It is not a control against
a determined insider: anyone who means to publish a name can encrypt it, split it across files or commits, spell
it phonetically, put it in an image, or use an encoding not listed here, and no scanner of this kind can rule that
out. It also sees only what is committed - not issues, PR comments, CI logs, release assets or anything already in
history (see `git log` for that). Matching is deliberately broad, so innocent hits are expected and accepted -
for example a Python definition of a function named `con`, a C undefine of a macro named `CON`, the name of a
well-known security conference, or the textbook stock-price problem; reword the text rather than weaken a pattern. Treat a green run as "nothing accidental found", never as proof that nothing is there.

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
import quopri
import re
import struct
import subprocess
import sys
import tarfile
import unicodedata
import zipfile
import zlib
from urllib.parse import unquote

TERMS = [re.compile(p, re.I) for p in (
    # No lookbehind: a name glued to other letters is still the name. Written together, the first name matches
    # whatever follows (bar the word "defconfig"); with a separator in between, the lookahead keeps ordinary code
    # such as Python's "def configure(" or C's "#undef CONFIG" out.
    r"d[e]f(?:c[o]n(?!f)|[\W_]+c[o]n(?:[\W_]*ai|(?![a-z])))",
    r"log[\W_]*c[\W_]*2(?![0-9])",
    r"cy[\W_]*roid",
    r"stock[\W_]*span",
)]
# Rule 7: abbreviations of the private names left behind by a rename - identifiers built from their first letters
# (the shapes are listed in the module docstring, spelled there so that this file does not match itself). Case-blind;
# a match inside a long base64-like run (random encoded data) is ignored, see abbrev_hit().
ABBREV = re.compile(r"l[c]2"
                    r"|(?<![A-Za-z0-9])(?:(?-i:l[c]_(?!all\b)[a-z]\w*)"
                    r"|c[y](?:user|[a-z]{0,6}(?<!ber)user)"
                    r"|no(?:c[y]|d[a]i)"
                    r")(?![A-Za-z0-9])"
                    r"|(?<![A-Za-z0-9])l[c](?:sec|t|x|m)(?![A-Za-z])"
                    r"|\blab\.c[y]\."
                    r"|(?<![A-Za-z0-9_.])c[y]\s*=(?!=)",
                    re.I)
B64_LONG_RUN = re.compile(r"[A-Za-z0-9+/]{20,}+")


def abbrev_hit(t):
    """A rule-7 match outside long base64-like runs (>= 20 characters of [A-Za-z0-9+/]): those runs are blanked first,
    in one linear pass, so random encoded data cannot trip it."""
    return bool(ABBREV.search(B64_LONG_RUN.sub(" ", t)))


GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
TENANT_WORD = re.compile(r"tenant|\btid\b|directory[\W_]*id|microsoftonline|entra[\W_]*id", re.I)
KNOWN_PRIVATE_SHA256 = {
    "01e99522f9aacd25f2502640c0ef4e6543eba06bf8556f518a3e3c4223d8c200",
}
B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{8,}={0,2}")
# Line-wrapped base64: anchored at line starts, with possessive quantifiers (Python 3.11+) so a multi-megabyte
# single-line file cannot make it backtrack.
# Lines before the last may not end in "=" (padding ends a base64 stream: such a line starts a new one).
B64_BLOCK = re.compile(rb"(?m)(?:^[ \t]*+[A-Za-z0-9+/]{16,}+[ \t]*+\r?\n){2,}+[ \t]*+[A-Za-z0-9+/]*+={0,2}+")
# Signatures, assembled so that this file contains none of them literally.
PDF_HEAD = b"%" + b"PDF-"
PDF_OBJECT = (b"end" + b"obj", b"/Flate" + b"Decode")
PDF_XREF = (b"trail" + b"er", b"start" + b"xref")
GZIP_MAGIC = b"\x1f\x8b\x08"
XZ_MAGIC = b"\xfd7zXZ\x00"
BZ2_MAGIC = re.compile(rb"BZh[1-9]")
ZIP_LOCAL, ZIP_END = b"PK\x03\x04", b"PK\x05\x06"
# Formats refused by signature: their content is not checked here. (label, signature, search window)
REFUSED = (
    ("an OLE2 compound file (.doc/.xls/.ppt/.msg)", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 1024),
    ("a 7z archive", b"7z\xbc\xaf\x27\x1c", 1024),
    ("a RAR archive", b"Rar!\x1a\x07", 1024),
    ("a zstd stream", b"\x28\xb5\x2f\xfd", 4),
    ("an LZ4 frame", b"\x04\x22\x4d\x18", 4),
)
PNG_SIG = b"\x89PNG\r\n\x1a\n"
QP_HEADER = re.compile(rb"content-transfer-encoding:[ \t]*quoted-printable", re.I)
JSON_U = re.compile(r"\\u([0-9a-fA-F]{4})")
RTF_HEX = re.compile(r"\\'([0-9a-fA-F]{2})")
TAG = re.compile(rb"<[^<>]{0,4096}>")
ZIP_METHODS = {0, 8, 9, 12, 14, 93, 95, 98}
CHUNK = 1 << 20
DEFAULT_BUDGET = 512 * 1024 * 1024
MAX_EMBEDDED = 64
MAX_LOCAL_ENTRIES = 100000
# Everything zipfile can raise on hostile or damaged input.
ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError, struct.error, KeyError,
              NotImplementedError, RuntimeError, OverflowError)


class BudgetExceeded(Exception):
    pass


def zip_local_header_ok(data, pos=0):
    """A plausible zip local file header at pos (signature, version, method and name length all sane)."""
    if data[pos:pos + 4] != ZIP_LOCAL or len(data) < pos + 30:
        return False
    version, _flags, method = struct.unpack_from("<HHH", data, pos + 4)
    name_len = struct.unpack_from("<H", data, pos + 26)[0]
    return version <= 63 and method in ZIP_METHODS and 0 < name_len <= 1024


def container_kind(data):
    if zip_local_header_ok(data) or (data[:4] == ZIP_END and len(data) >= 22):
        return "zip"
    if data.startswith(GZIP_MAGIC):
        return "gzip"
    if BZ2_MAGIC.match(data):
        return "bzip2"
    if data.startswith(XZ_MAGIC):
        return "xz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def is_pdf(data):
    if PDF_HEAD in data[:1024]:
        return True
    return any(m in data for m in PDF_OBJECT) and any(m in data for m in PDF_XREF)


class Scanner:
    def __init__(self, budget):
        self.budget = budget
        self.hits = []
        self.broken_seen = 0    # broken-container findings so far (including the one suppressed kind)
        self.first_line_of_clean_block = False   # see broken()

    # ---- bookkeeping -------------------------------------------------------------------------------------
    def hit(self, where, what):
        h = "%s: %s" % (where, what)
        if h not in self.hits:
            self.hits.append(h)

    def broken(self, where, what, truncated_gzip=False):
        """A container that cannot be read completely: a finding (fail closed). One exception: a truncated gzip
        decoded from the FIRST line of a line-wrapped base64 block whose joined decode opened completely - the
        first line of a wrapped gzip payload is necessarily a truncated stream on its own. Nothing else is
        suppressed, and name and identifier findings never are."""
        self.broken_seen += 1
        if truncated_gzip and self.first_line_of_clean_block:
            return
        self.hit(where, what)

    def spend(self, n):
        self.budget -= n
        if self.budget < 0:
            raise BudgetExceeded()

    # ---- text --------------------------------------------------------------------------------------------
    @staticmethod
    def decodings(data):
        out = [data.decode("utf-8", "replace")]
        if not data.isascii():
            out.append(data.decode("latin-1"))
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            out.append(data.decode("utf-16", "replace"))
        else:
            sample = data[:4096]
            if len(sample) >= 4 and sample.count(0) * 4 >= len(sample):      # NUL pattern: UTF-16 without BOM
                out += [data.decode("utf-16-le", "replace"), data.decode("utf-16-be", "replace")]
        return out

    # Invisible format characters (category Cf: zero-width space/joiner, soft hyphen, BOM, bidi marks), deleted
    # with str.translate rather than a per-character loop.
    STRIP_CF = {cp: None for cp in range(sys.maxunicode + 1) if unicodedata.category(chr(cp)) == "Cf"}

    @classmethod
    def normalise(cls, text):
        if text.isascii():          # NFKC and Cf removal cannot change pure ASCII
            return text
        return unicodedata.normalize("NFKC", text).translate(cls.STRIP_CF)

    def text_variants(self, text):
        seen = set()
        cands = [text]
        if "&" in text or "%" in text:
            cands += [html.unescape(text), unquote(text), unquote(html.unescape(text)), html.unescape(unquote(text))]
        if "\\u" in text:                     # JSON / JavaScript \uXXXX escapes
            cands.append(JSON_U.sub(lambda m: chr(int(m.group(1), 16)), text))
        if "\\'" in text:                     # RTF \'hh escapes
            cands.append(RTF_HEX.sub(lambda m: chr(int(m.group(1), 16)), text))
        for t in cands:
            t = self.normalise(t)
            if t not in seen:
                seen.add(t)
                yield t

    def check_text(self, where, text, abbrev=True):
        for t in self.text_variants(text):
            for i, rx in enumerate(TERMS, 1):
                if rx.search(t):
                    self.hit(where, "rule %d (private name)" % i)
            if abbrev and abbrev_hit(t):
                self.hit(where, "rule 7 (an abbreviation of a private name)")
            for m in GUID.finditer(t):
                g = m.group(0).lower()
                if hashlib.sha256(g.encode()).hexdigest() in KNOWN_PRIVATE_SHA256:
                    self.hit(where, "rule 5 (a known private identifier)")
                elif len(set(g.replace("-", ""))) >= 8 and TENANT_WORD.search(t[max(0, m.start() - 100):m.end() + 100]):
                    self.hit(where, "rule 6 (a real-looking GUID next to a tenant/directory keyword - use a placeholder)")

    # ---- decompression, chunk by chunk: returns (output so far, complete?) ---------------------------------
    def _zlib(self, data, wbits):
        d = zlib.decompressobj(wbits)
        out = bytearray()
        buf = data
        try:
            while True:
                piece = d.decompress(buf, CHUNK)
                out += piece
                self.spend(len(piece))
                buf = d.unconsumed_tail
                if buf:
                    continue
                if d.eof and wbits > 15 and d.unused_data.startswith(GZIP_MAGIC):    # concatenated gzip members
                    buf = d.unused_data
                    d = zlib.decompressobj(wbits)
                    continue
                break
            return bytes(out), d.eof
        except zlib.error:
            return bytes(out), False

    def _stream(self, make, data):
        d = make()
        out = bytearray()
        try:
            piece = d.decompress(data, CHUNK)
            while True:
                out += piece
                self.spend(len(piece))
                if d.eof or d.needs_input:
                    break
                piece = d.decompress(b"", CHUNK)
            return bytes(out), d.eof
        except (OSError, EOFError, lzma.LZMAError, ValueError):
            return bytes(out), False

    def decompress(self, kind, data):
        if kind == "gzip":
            return self._zlib(data, 16 + zlib.MAX_WBITS)
        if kind == "bzip2":
            return self._stream(bz2.BZ2Decompressor, data)
        return self._stream(lzma.LZMADecompressor, data)

    # ---- containers ---------------------------------------------------------------------------------------
    def scan_zip(self, where, data, depth):
        """Open with zipfile; if the archive or a member is damaged, recover what the local headers allow."""
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except ZIP_ERRORS:
            z = None
            first = data.find(ZIP_LOCAL)
            if first > 0:
                try:
                    z = zipfile.ZipFile(io.BytesIO(data[first:]))
                except ZIP_ERRORS:
                    z = None
        if z is None:
            self.broken(where, "an unreadable zip archive - refused rather than skipped")
            self.scan_zip_local_headers(where, data, depth)
            return
        for info in z.infolist():
            name = "%s!%s" % (where, info.filename)
            self.check_text(name, info.filename)
            if info.file_size > self.budget:
                raise BudgetExceeded()
            member = bytearray()
            try:
                with z.open(info) as fh:
                    while True:
                        piece = fh.read(CHUNK)
                        if not piece:
                            break
                        member += piece
                        self.spend(len(piece))
            except ZIP_ERRORS:
                self.broken(name, "an unreadable zip member - refused; its readable part was scanned")
            self.scan(name, bytes(member), depth + 1)
            self.check_markup(name, info.filename, member)
        # Every local header too: a prepended or appended zip, or entries left out of the central directory, are
        # invisible to zipfile but still on disk. Nothing is skipped on the strength of what a header claims
        # (name, CRC, flags); findings are deduplicated by their label instead.
        self.scan_zip_local_headers(where, data, depth)

    def scan_zip_local_headers(self, where, data, depth):
        """Scan the entry behind every valid local file header."""
        pos, n = data.find(ZIP_LOCAL), 0
        while pos >= 0 and n < MAX_LOCAL_ENTRIES:
            n += 1
            if zip_local_header_ok(data, pos):
                flags, method = struct.unpack_from("<HH", data, pos + 6)
                csize = struct.unpack_from("<I", data, pos + 18)[0]
                name_len, extra_len = struct.unpack_from("<HH", data, pos + 26)
                raw_name = data[pos + 30:pos + 30 + name_len]
                name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", "replace")
                body = data[pos + 30 + name_len + extra_len:]
                label = "%s!(local entry %s)" % (where, name)
                self.check_text(label, name)
                if method == 0:
                    if flags & 0x8:     # size in a data descriptor after the data: up to the next local header
                        nxt = body.find(ZIP_LOCAL)
                        body = body if nxt < 0 else body[:nxt]
                    else:
                        body = body[:csize]
                    self.scan(label, body, depth + 1)
                    self.check_markup(label, name, body)
                elif method == 8:
                    inflated = self._zlib(body, -15)[0]
                    self.scan(label, inflated, depth + 1)
                    self.check_markup(label, name, inflated)
            pos = data.find(ZIP_LOCAL, pos + 4)

    def check_markup(self, where, name, data):
        """Office/ODF XML (and other markup) inside an archive: also check the text with every tag removed and the
        pieces joined, so a name split across runs or spans is seen whole."""
        if name.lower().endswith((".xml", ".rels", ".xhtml", ".htm", ".html", ".svg")) or data.lstrip()[:1] == b"<":
            joined = TAG.sub(b"", data)
            for text in self.decodings(joined):
                self.check_text(where + " (markup text)", text)

    def scan_png_text(self, where, data):
        """PNG text chunks: tEXt (Latin-1), zTXt (zlib), iTXt (UTF-8, optionally zlib)."""
        pos = 8
        while pos + 12 <= len(data):
            length = struct.unpack_from(">I", data, pos)[0]
            ctype = data[pos + 4:pos + 8]
            body = data[pos + 8:pos + 8 + length]
            if ctype == b"tEXt":
                self.check_text(where + " (PNG tEXt)", body.decode("latin-1"), False)
            elif ctype == b"zTXt" and b"\0" in body:
                key, rest = body.split(b"\0", 1)
                self.check_text(where + " (PNG zTXt)", key.decode("latin-1") + " " + self._zlib(rest[1:], 15)[0].decode("latin-1"), False)
            elif ctype == b"iTXt" and body.count(b"\0") >= 4:
                key, rest = body.split(b"\0", 1)
                compressed, rest = rest[0:1] == b"\1", rest[2:]
                _lang, _tkey, text = rest.split(b"\0", 2)
                if compressed:
                    text = self._zlib(text, 15)[0]
                self.check_text(where + " (PNG iTXt)", key.decode("latin-1") + " " + text.decode("utf-8", "replace"), False)
            elif ctype == b"IEND":
                break
            pos += 12 + length

    def scan_container(self, where, kind, data, depth):
        if kind == "zip":
            self.scan_zip(where, data, depth)
        elif kind == "tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as t:
                    for m in t.getmembers():
                        self.check_text("%s!%s" % (where, m.name), m.name)
                        if m.isfile():
                            self.scan("%s!%s" % (where, m.name), t.extractfile(m).read(), depth + 1)
            except (tarfile.TarError, EOFError, OSError):
                self.broken(where, "an unreadable tar archive - refused")
                for text in self.decodings(data):
                    self.check_text(where, text)
        else:
            inner, complete = self.decompress(kind, data)
            if not complete:
                self.broken(where, "an unreadable or truncated %s stream - refused; its readable part was scanned" % kind,
                            truncated_gzip=(kind == "gzip"))
            self.scan("%s!(%s)" % (where, kind), inner, depth + 1)

    def scan_embedded(self, where, data, depth):
        """Containers that do not start at offset 0: self-extracting files and prepended junk."""
        if ZIP_END in data:                                      # end-of-central-directory anywhere: open it
            self.scan_zip("%s!(embedded zip)" % where, data, depth)
        else:
            pos = data.find(ZIP_LOCAL, 1)
            if pos > 0 and zip_local_header_ok(data, pos):          # entries without a directory: recover them
                self.scan_zip_local_headers("%s!(embedded zip)" % where, data, depth)
        for magic, kind in ((GZIP_MAGIC, "gzip"), (XZ_MAGIC, "xz")):
            pos, n = data.find(magic, 1), 0
            while pos > 0 and n < MAX_EMBEDDED:
                n += 1
                inner, _ = self.decompress(kind, data[pos:])      # random bytes that look like a header: skip
                if inner:
                    self.scan("%s!(embedded %s@%d)" % (where, kind, pos), inner, depth + 1)
                pos = data.find(magic, pos + 1)

    # ---- base64 -------------------------------------------------------------------------------------------
    def scan_base64(self, where, data, depth):
        """Line-wrapped blocks are joined and decoded as one; every single run is decoded on its own as well (also
        inside a block: a line can be a stream of its own). A block's lines are quiet about broken containers only
        when the joined decode was clean."""
        clean_first_lines = set()           # start offsets of the first line of each block that decoded cleanly
        for m in B64_BLOCK.finditer(data):
            before = self.broken_seen
            if self.decode_run(where, m.start(), re.sub(rb"\s+", b"", m.group(0)), depth) and self.broken_seen == before:
                first = re.match(rb"[ \t]*", m.group(0)).end()
                clean_first_lines.add(m.start() + first)
        for m in B64_RUN.finditer(data):
            saved = self.first_line_of_clean_block
            self.first_line_of_clean_block = m.start() in clean_first_lines
            try:
                self.decode_run(where, m.start(), m.group(0), depth)
            finally:
                self.first_line_of_clean_block = saved

    def decode_run(self, where, start, run, depth):
        """Decode one run at all four alignments and scan what comes out. True if any alignment decoded."""
        run = run.rstrip(b"=")
        urlsafe = b"-" in run or b"_" in run
        any_decoded = False
        for off in range(4):
            seg = run[off:]
            if len(seg) < 8:
                break
            rem = len(seg) % 4
            seg = seg[:-1] if rem == 1 else seg + b"=" * ((4 - rem) % 4)
            try:
                raw = base64.urlsafe_b64decode(seg) if urlsafe else base64.b64decode(seg, validate=True)
            except (binascii.Error, ValueError):
                continue
            if raw:
                any_decoded = True
                self.spend(len(raw))
                self.scan("%s(base64@%d+%d)" % (where, start, off), raw, depth + 1, derived=True)
        return any_decoded

    # ---- one blob -----------------------------------------------------------------------------------------
    def scan(self, where, data, depth=0, derived=False):
        """derived: the bytes came from decoding base64. Every decoding of them is still checked as text, and a
        full container signature is still opened and fails closed; only nested base64 inside binary noise is
        not followed further (cost)."""
        if is_pdf(data):
            self.hit(where, "a PDF - PDFs are refused (their compressed streams cannot be checked reliably)")
            return
        for label, sig, window in REFUSED:
            if sig in data[:window]:
                self.hit(where, "%s - refused (its content cannot be checked here)" % label)
                return
        kind = container_kind(data)
        if kind:
            self.scan_container(where, kind, data, depth)
            return
        # rule 7 only on plain text: not inside decoded base64, binary data or anything that is not clean UTF-8,
        # where three random letters would trip it
        abbrev = "base64@" not in where and b"\x00" not in data and not data.startswith(PNG_SIG)
        if abbrev:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                abbrev = False
        for text in self.decodings(data):
            self.check_text(where, text, abbrev)
        if data.startswith(PNG_SIG):
            self.scan_png_text(where, data)
        if QP_HEADER.search(data[:65536]):     # e-mail: soft line breaks and =XX escapes would split a name
            for text in self.decodings(quopri.decodestring(data)):
                self.check_text(where + " (quoted-printable)", text)
        self.scan_embedded(where, data, depth)
        if depth < 8 and (not derived or self.mostly_text(data)):
            self.scan_base64(where, data, depth)

    PRINTABLE = bytes(range(0x20, 0x7f)) + b"\t\n\r"

    @classmethod
    def mostly_text(cls, raw):
        return len(raw.translate(None, cls.PRINTABLE)) <= 0.15 * len(raw)


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
                # A message is text, never a file: the name and identifier rules apply (with every decoding,
                # base64 included); the PDF and container rules do not, so describing them is allowed.
                label = "commit %s message" % sha.strip().decode()[:12]
                for text in s.decodings(msg):
                    s.check_text(label, text)
                s.scan_base64(label, msg, 0)
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
