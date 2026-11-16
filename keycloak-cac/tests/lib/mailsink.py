#!/usr/bin/env python3
"""A minimal SMTP sink for the image tests (standard library only): accepts every message and writes it to a file.

  mailsink.py <port> <out-dir>        listens on 0.0.0.0:<port>; message N -> <out-dir>/N.eml

Plain SMTP, no TLS, no authentication: for a throwaway test container only, never for a real mail server.
"""
import os, socketserver, sys, threading

PORT, OUT = int(sys.argv[1]), sys.argv[2]
os.makedirs(OUT, exist_ok=True)
lock, counter = threading.Lock(), [0]

class Handler(socketserver.StreamRequestHandler):
    def send(self, line):
        self.wfile.write((line + "\r\n").encode()); self.wfile.flush()

    def handle(self):
        self.send("220 mailsink ESMTP")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode("utf-8", "replace").strip().upper()
            if cmd.startswith(("EHLO", "HELO")):
                self.send("250 mailsink")
            elif cmd.startswith(("MAIL", "RCPT", "RSET", "NOOP")):
                self.send("250 OK")
            elif cmd == "DATA":
                self.send("354 end with <CRLF>.<CRLF>")
                body = []
                while True:
                    l = self.rfile.readline()
                    if not l or l in (b".\r\n", b".\n"):
                        break
                    body.append(l[1:] if l.startswith(b"..") else l)
                with lock:
                    counter[0] += 1
                    n = counter[0]
                with open(os.path.join(OUT, "%04d.eml" % n), "wb") as f:
                    f.write(b"".join(body))
                self.send("250 OK queued as %d" % n)
            elif cmd == "QUIT":
                self.send("221 bye"); return
            else:
                self.send("502 not implemented")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

Server(("0.0.0.0", PORT), Handler).serve_forever()
