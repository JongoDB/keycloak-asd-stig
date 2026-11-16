#!/usr/bin/env python3
"""Tests for public-content-guard.py.

  python3 .github/scripts/test_public_content_guard.py

Every fixture is generated at test time in a temporary directory, so this repository never holds the strings the
guard exists to keep out. The names are assembled from reversed pieces (no source line spells them).
The bypass set mirrors a reviewer's: control, base64, HTML entity, percent-encoding, full-width letters, zero-width
joiner, UTF-16 with and without BOM, separators, gzip, gzip'd tar, nested zip, zip with no extension, .whl, .docx,
a commit message - plus PDF refusal, the decompression budget, and the GUID rules. Ordinary code must not trip it.
"""
import base64
import gzip
import hashlib
import importlib.util
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import uuid
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "public-content-guard.py")

NAME = "nocfeD"[::-1]                   # the first private name, mixed case
NAME_AI = NAME + " " + "IA"[::-1]
NAME2 = "2Cgol"[::-1]                   # the second
PART_A, PART_B = "gol"[::-1], "2c"[::-1]   # two halves of the second name


# PDF signatures, assembled so this file is not itself a PDF to the guard
PDF_H = b"%" + b"PDF-"
FLATE, ENDOBJ, TRAILER, STARTXREF = b"/Flate" + b"Decode", b"end" + b"obj", b"trail" + b"er", b"start" + b"xref"


def zipped(name, data):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return b.getvalue()


def tgz(name, data):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return b.getvalue()


def nested_zip(data, levels):
    blob = zipped("a.txt", data)
    for i in range(1, levels + 1):
        blob = zipped("l%d.zip" % i, blob)
    return blob


BYPASSES = {
    "control.txt": NAME.encode(),
    "b64.txt": base64.b64encode(NAME_AI.encode()),
    "entity.html": ("&#%d;" % ord(NAME[0].lower()) + NAME.lower()[1:]).encode(),
    "pct.txt": (NAME.lower()[0] + "%%%02x" % ord(NAME.lower()[1]) + NAME.lower()[2:]).encode(),
    "fullwidth.txt": "".join(chr(ord(c) + 0xFEE0) for c in NAME.upper()).encode(),
    "zwj.txt": (NAME[:3] + "​" + NAME[3:]).encode(),
    "zwj2.txt": (NAME[:2] + "‍­" + NAME[2:]).encode(),
    "utf16.txt": NAME_AI.encode("utf-16"),
    "utf16-nobom.txt": NAME_AI.encode("utf-16-le"),
    "underscore.txt": ("%s_%s and %s %s and %s.%s" % (PART_A, PART_B, PART_A, PART_B, PART_A.title(), PART_B.upper())).encode(),
    "separators.txt": (NAME[:3] + " - " + NAME[3:] + "_" + "ia"[::-1]).encode(),
    "glued.txt": ("x" * 10 + NAME).encode(),
    "file.gz": gzip.compress(NAME.encode()),
    "raw.tgz": gzip.compress(("x" * 10 + NAME).encode()),
    "real.tgz": tgz("inner/readme.txt", NAME2.encode()),
    "deep.zip": nested_zip(NAME.encode(), 4),
    "noext": zipped("a.txt", NAME.encode()),
    "wheel.whl": zipped("a.py", NAME.encode()),
    "doc.docx": zipped("word/document.xml", NAME.encode()),
    "path-only.txt": b"nothing here",
    "b64-in-zip.zip": zipped("cfg.json", b'{"x": "' + base64.b64encode(NAME.encode()) + b'"}'),
    "doc.pdf": b"%PDF-1.4\n1 0 obj << /Length 9 /Filter /FlateDecode >> stream\nxxxxxxxxx\nendstream\nendobj\n",
    # containers that do not start at offset 0
    "sfx.exe": b"MZ\x90\x00" + hashlib.sha256(b"stub").digest() * 64 + zipped("a.txt", NAME.encode()),
    "junk-then-zip.bin": b"#!/bin/sh\nexit 0\n" + zipped("payload/readme", NAME.encode()),
    "junk-then-gzip.bin": b"some header text\n" + gzip.compress(NAME.encode()),
    "junk-then-pdf.pdf": b"x" * 600 + b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
    # PDFs: no version after the header; or object + cross-reference structure with no header at all
    "pdf-noversion.bin": b"junk " + PDF_H + b"\n",
    "pdf-structure.txt": b"1 0 obj << /Filter " + FLATE + b" >> stream\nx\nendstream\n" + ENDOBJ + b"\n" + TRAILER
                         + b" << >>\n" + STARTXREF + b"\n0\n",
    # broken containers: the readable part is scanned, and the break itself is a finding
    "gzip-truncated.gz": gzip.compress(NAME.encode() + b" " + hashlib.sha512(b"t").digest() * 200)[:60],
    "zip-broken-directory.zip": zipped("a.txt", NAME.encode())[:-30],
    # decoded base64 that carries a full container signature, broken: still opened, and fails closed
    "b64-of-truncated-gzip.txt": base64.b64encode(gzip.compress(NAME.encode() * 50)[:40]),
    "b64-of-gzip.txt": base64.b64encode(gzip.compress(NAME.encode())),
    "b64-of-junk-then-zip.txt": base64.b64encode(b"\x00\x01junk" + zipped("x.txt", NAME.encode())),
    # decoded base64 that is mostly binary but carries the name: Latin-1 sees every byte
    "b64-binary-around.txt": base64.b64encode(hashlib.sha512(b"a").digest() * 4 + NAME.encode() + hashlib.sha512(b"b").digest() * 4),
    # line-wrapped base64 (as embedded payloads are): only meaningful once the lines are joined
    "b64-wrapped.sh": b"PAYLOAD='\n" + b"\n".join(
        base64.b64encode(gzip.compress(hashlib.sha512(b"w").digest() * 30 + NAME.encode()))[i:i + 64]
        for i in range(0, 400, 64)) + b"\n'\n",
    # two zips back to back: zipfile reads only the last central directory; the first zip's entry hides
    "concat.zip": zipped("hidden.txt", NAME.encode()) + zipped("visible.txt", b"nothing here"),
    "junk-concat.bin": b"header\n" + zipped("hidden.txt", NAME.encode()) + zipped("visible.txt", b"clean"),
    # a block of 18-character base64 lines: joined, their decode is misaligned; one line is a stream of its own
    "b64-block-hidden-line.txt": b"\n".join(
        [base64.b64encode(hashlib.sha256(bytes([i])).digest()[:13]).rstrip(b"=") for i in range(3)]
        + [base64.b64encode((NAME + "+" * (13 - len(NAME))).encode()).rstrip(b"=")]
        + [base64.b64encode(hashlib.sha256(bytes([i])).digest()[:13]).rstrip(b"=") for i in range(3, 6)]) + b"\n",
    # a padded line in the middle ends one stream; the next lines are another
    "b64-block-padded-middle.txt": b"\n".join(
        [base64.b64encode(hashlib.sha512(bytes([i])).digest()[:48]) for i in range(2)]
        + [base64.b64encode((NAME_AI + " " + NAME_AI + "!").encode())]     # 28 characters, ends in "="
        + [base64.b64encode(hashlib.sha512(bytes([i])).digest()[:48]) for i in range(2, 4)]) + b"\n",
    # base64 glued to other base64-alphabet characters, at each misalignment
    "b64-off1.txt": b"Q" + base64.b64encode(NAME_AI.encode()),
    "b64-off2.txt": b"Qz" + base64.b64encode(NAME_AI.encode()),
    "b64-off3.txt": b"QzA" + base64.b64encode(NAME_AI.encode()),
    "b64-urlsafe-off2.txt": b"ab" + base64.urlsafe_b64encode(("??" + NAME + "??").encode()),
}
BROKEN_WITHOUT_NAME = {
    "b64-of-broken-gzip.txt": base64.b64encode(b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\xff" * 40),
    "broken.gz": b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\xff" * 40,
}
CLEAN = {
    "python.py": b"def configure(self):\n    return self.connect()\n\ndef control(): pass\n",
    "c.h": b"#undef CONFIG_X\n#define CONSOLE 1\n",
    "words.txt": b"a catalog, a dialog, cyan, stockholm, spanner, log c3, decor\n",
    "placeholder-guid.txt": b"tenant: 00000000-0000-4000-8000-000000000001\ntenant 11111111-2222-4333-8444-555555555555\n",
    "plain-guid.txt": ("realmId=%s user=%s\n" % (uuid.uuid4(), uuid.uuid4())).encode(),   # GUIDs away from tenant words
    "random.bin": hashlib.sha512(b"seed").digest() * 50,
}


def run(*args, cwd=None):
    r = subprocess.run([sys.executable, GUARD] + list(args), capture_output=True, text=True, cwd=cwd, timeout=120)
    return r.returncode, r.stdout + r.stderr


class Guard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = cls.tmp.name
        for name, data in list(BYPASSES.items()) + list(CLEAN.items()):
            with open(os.path.join(cls.dir, name), "wb") as f:
                f.write(data)
        # a file whose only problem is its name
        cls.named = os.path.join(cls.dir, "notes-%s.txt" % NAME.lower())
        with open(cls.named, "wb") as f:
            f.write(b"nothing here")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_bypass_is_caught(self):
        for name in BYPASSES:
            if name == "path-only.txt":
                continue
            with self.subTest(fixture=name):
                rc, out = run("--no-tree", "--files", os.path.join(self.dir, name))
                self.assertEqual(rc, 1, out)
                self.assertIn("::error::", out)

    def test_the_log_never_repeats_the_name(self):
        rc, out = run("--no-tree", "--files", *[os.path.join(self.dir, n) for n in BYPASSES if n != "path-only.txt"])
        self.assertEqual(rc, 1)
        guard = importlib.util.spec_from_file_location("g", GUARD)
        g = importlib.util.module_from_spec(guard)
        guard.loader.exec_module(g)
        printed = out.replace(self.dir, "")
        self.assertFalse(any(rx.search(printed) for rx in g.TERMS), "the guard printed what it caught")

    def test_broken_containers_fail_closed(self):
        for name, data in BROKEN_WITHOUT_NAME.items():
            with self.subTest(fixture=name):
                p = os.path.join(self.dir, name)
                with open(p, "wb") as f:
                    f.write(data)
                rc, out = run("--no-tree", "--files", p)
                self.assertEqual(rc, 1, out)
                self.assertIn("unreadable", out)

    def test_a_file_name_is_checked(self):
        rc, out = run("--no-tree", "--files", self.named)
        self.assertEqual(rc, 1, out)
        self.assertIn("(path)", out)

    def test_pdf_refused(self):
        rc, out = run("--no-tree", "--files", os.path.join(self.dir, "doc.pdf"))
        self.assertEqual(rc, 1)
        self.assertIn("PDF", out)

    def test_ordinary_content_passes(self):
        for name in CLEAN:
            with self.subTest(fixture=name):
                rc, out = run("--no-tree", "--files", os.path.join(self.dir, name))
                self.assertEqual(rc, 0, out)

    def test_budget_exceeded_fails(self):
        bomb = os.path.join(self.dir, "bomb.gz")
        with open(bomb, "wb") as f:
            f.write(gzip.compress(b"\0" * (8 * 1024 * 1024)))
        rc, out = run("--no-tree", "--budget", str(1024 * 1024), "--files", bomb)
        self.assertEqual(rc, 1)
        self.assertIn("budget", out)
        rc, out = run("--no-tree", "--files", bomb)          # the default budget covers it, and it is clean
        self.assertEqual(rc, 0, out)

    def test_tenant_guid_next_to_keyword(self):
        p = os.path.join(self.dir, "tenant.txt")
        with open(p, "wb") as f:
            f.write(("tenant_id = %s\n" % uuid.uuid4()).encode())       # real-looking ids made at test time
        rc, out = run("--no-tree", "--files", p)
        self.assertEqual(rc, 1)
        self.assertIn("rule 6", out)

    def test_known_private_guid_anywhere(self):
        spec = importlib.util.spec_from_file_location("g2", GUARD)
        g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g)
        fake = str(uuid.uuid4())
        g.KNOWN_PRIVATE_SHA256.add(hashlib.sha256(fake.encode()).hexdigest())
        s = g.Scanner(1 << 30)
        s.scan("x", ("user=" + fake.upper()).encode())
        self.assertTrue(any("rule 5" in h for h in s.hits), s.hits)
        self.assertTrue(len(g.KNOWN_PRIVATE_SHA256) >= 2)

    def test_commit_messages(self):
        with tempfile.TemporaryDirectory() as repo:
            def git(*a):
                subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.test", *a], cwd=repo,
                               check=True, capture_output=True)
            git("init", "-q")
            git("commit", "-q", "--allow-empty", "-m", "base")
            git("commit", "-q", "--allow-empty", "-m", "clean change")
            rc, out = run("--commits", "HEAD~1..HEAD", cwd=repo)
            self.assertEqual(rc, 0, out)
            git("commit", "-q", "--allow-empty", "-m", "fix for " + NAME[:3] + "_" + NAME[3:] + " realm")
            rc, out = run("--commits", "HEAD~2..HEAD", cwd=repo)
            self.assertEqual(rc, 1, out)
            self.assertIn("message", out)

    def test_guard_does_not_match_itself(self):
        rc, out = run("--no-tree", "--files", GUARD, os.path.abspath(__file__))
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
