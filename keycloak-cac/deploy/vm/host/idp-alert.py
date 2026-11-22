#!/usr/bin/env python3
"""Mail an alert when a shared-IdP unit fails (systemd OnFailure=idp-alert@%n.service). Independent of Keycloak, so
it still works when Keycloak is what failed. Settings: /srv/idp/config/alert.env (ALERT_TO, SMTP_HOST, SMTP_PORT,
SMTP_USER, SMTP_FROM; written by idp-admin.py smtp --alert-to), password /srv/idp/secrets/smtp_password.
Never prints the password. Exit 0 sent, 1 not sent (the journal still has the failure).

  idp-alert.py <unit>            e.g. idp-guard.service: mails the unit's last 60 journal lines
  idp-alert.py <name> -          mails the text on stdin instead (e.g. idp-tls: the deploy hook skipped a restart)
"""
import os, smtplib, socket, ssl, subprocess, sys
from email.message import EmailMessage

unit = sys.argv[1] if len(sys.argv) > 1 else "unknown"
cfg = {}
try:
    for line in open("/srv/idp/config/alert.env"):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1); cfg[k] = v
    pw = open("/srv/idp/secrets/smtp_password").read().strip()
except OSError as e:
    print("idp-alert: not configured (%s)" % e, file=sys.stderr); sys.exit(1)
if not unit.replace("@", "").replace(".", "").replace("-", "").replace("_", "").isalnum():
    sys.exit("idp-alert: bad unit name")
m = EmailMessage()
m["From"], m["To"] = cfg["SMTP_FROM"], cfg["ALERT_TO"]
if len(sys.argv) > 2 and sys.argv[2] == "-":
    m["Subject"] = "[shared IdP %s] %s needs attention" % (socket.gethostname(), unit)
    m.set_content(sys.stdin.read()[:20000])
else:
    log = subprocess.run(["journalctl", "-u", unit, "-n", "60", "--no-pager", "-o", "short-iso"], capture_output=True, text=True).stdout
    m["Subject"] = "[shared IdP %s] %s FAILED" % (socket.gethostname(), unit)
    m.set_content("%s failed on %s. Exit 2 from idp-guard means a violation was found (and, with --fix, removed): read "
                  "the STIG-* lines. Anything else is a failure to run. Last journal lines:\n\n%s" % (unit, socket.gethostname(), log))
try:
    with smtplib.SMTP(cfg["SMTP_HOST"], int(cfg.get("SMTP_PORT", "587")), timeout=30) as s:
        s.starttls(context=ssl.create_default_context()); s.login(cfg["SMTP_USER"], pw); s.send_message(m)
except Exception as e:      # noqa: BLE001 - reported, never raised past systemd
    print("idp-alert: send failed: %s" % type(e).__name__, file=sys.stderr); sys.exit(1)
print("idp-alert: %s -> %s" % (unit, cfg["ALERT_TO"]))
