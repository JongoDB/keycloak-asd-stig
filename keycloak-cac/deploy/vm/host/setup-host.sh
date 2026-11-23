#!/usr/bin/env bash
# keycloak-cac on one VM: everything ON the VM. Idempotent; run as root from an extracted copy of this repository
# (the same git archive as KCAS_TAR), keycloak-cac/deploy/vm/host/:
#   sudo PUBLIC_HOST=idp.example.mil REALM=example REALM_DISPLAY="Example sign-in" \
#        KCAS_TAR=/root/keycloak-asd-stig.tar KCAS_COMMIT=<sha> \
#        STORAGE_ACCOUNT=<storage account> KEY_VAULT=<key vault> ACME_ZONE=acme.example.mil ACME_RG=<resource group> \
#        [CLIENTS_DIR=<dir of client files>] [THEME_DIR=<dir of a login theme>] [ADMIN_HOST=<second name>] \
#        ./setup-host.sh
# Secrets are generated here, on the VM, with openssl; nothing is printed. Re-running keeps existing secrets,
# certificates and data, rebuilds images only when KCAS_COMMIT changes, and re-renders configuration.
# No DNS-provider credential is ever placed on this host: DNS-01 writes delegated Azure TXT records through the VM's
# identity (idp-acme-hook). Run ../azure/azure-provision.sh first, and have the _acme-challenge CNAMEs in the parent zone.
# Instance data (client registrations, a brand theme, idp-admin.json) is NOT in this repository: CLIENTS_DIR and
# THEME_DIR point at your own copy; /srv/idp/config/idp-admin.json starts as the example and is yours to edit.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../../../.." && pwd)"
VALIDATOR="$REPO/keycloak-rp-integration/scripts/validate-client-request.py"
[ -f "$VALIDATOR" ] || { echo "setup-host: run it from a copy of the whole repository (no $VALIDATOR)" >&2; exit 1; }
: "${PUBLIC_HOST:?}" "${KCAS_COMMIT:?}" "${STORAGE_ACCOUNT:?}" "${KEY_VAULT:?}" "${REALM:?}" "${REALM_DISPLAY:?}"
: "${ACME_ZONE:?ACME_ZONE (the delegated Azure DNS zone, e.g. acme.example.mil)}" "${ACME_RG:?ACME_RG (its resource group)}"
CAC_ADMINS="${CAC_ADMINS:-breakglass.none=no-such-alt-token.invalid@mil}"   # see keycloak-cac.env.template
FIPS="${FIPS:-true}"; KC_VERSION="${KC_VERSION:-26.8.2}"; POSTGRES_REF="${POSTGRES_REF:-mirror.gcr.io/library/postgres:17}"
S=/srv/idp
log() { echo "setup-host: $*"; }

# ---- packages (Ubuntu archive only), automatic security updates
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null || ! command -v certbot >/dev/null || ! command -v dig >/dev/null \
   || ! command -v rsync >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq docker.io docker-compose-v2 certbot bind9-dnsutils gnupg jq unattended-upgrades gettext-base rsync >/dev/null
fi
systemctl enable --now docker unattended-upgrades >/dev/null 2>&1
cat > /etc/docker/daemon.json <<'J'
{"live-restore": true, "no-new-privileges": true, "log-driver": "json-file", "log-opts": {"max-size": "50m", "max-file": "5"}}
J
systemctl reload docker 2>/dev/null || systemctl restart docker
printf 'PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nX11Forwarding no\nMaxAuthTries 3\n' \
  > /etc/ssh/sshd_config.d/10-idp-hardening.conf && systemctl reload ssh

# ---- data disk (LUN 0) at /srv/idp: everything stateful lives here
DISK=/dev/disk/azure/data/by-lun/0
if ! mountpoint -q $S; then
  blkid "$DISK" >/dev/null 2>&1 || mkfs.ext4 -q -L idpdata "$(readlink -f $DISK)"
  mkdir -p $S; UUID=$(blkid -s UUID -o value "$(readlink -f $DISK)")
  grep -q "$UUID" /etc/fstab || echo "UUID=$UUID $S ext4 defaults,nofail,noatime 0 2" >> /etc/fstab
  mount $S
fi
mkdir -p $S/{config,secrets,pki,tls,clients,pgdata,compose,src,backup}
chmod 0750 $S/secrets $S/pki $S/tls; chmod 0700 $S/backup
# the last good CRLs (public data), written by Keycloak (1000) and installed by a new container before it starts
install -d -o 1000 -g 1000 -m 0750 $S/crl-cache

# ---- secrets: generated once, never printed. 0440 root:1000 (Keycloak runs as 1000:1000); db_password is also
#      read by PostgreSQL (uid 999). Lengths: >= 14 for strict FIPS, >= 24 for the automation secret.
gen() { [ -s "$S/secrets/$1" ] || ( umask 077; openssl rand -hex "$2" | tr -d '\n' > "$S/secrets/$1" ); }
gen db_password 24; gen automation_secret 32; gen backup_passphrase 32
[ -f $S/config/.master-hardened ] || gen bootstrap_admin_password 24
chown 999:1000 $S/secrets/db_password; chmod 0440 $S/secrets/db_password
for f in bootstrap_admin_password automation_secret; do if [ -f $S/secrets/$f ]; then chown root:1000 $S/secrets/$f; chmod 0440 $S/secrets/$f; fi; done
chown root:root $S/secrets/backup_passphrase; chmod 0400 $S/secrets/backup_passphrase
[ -f $S/secrets/entra_client_secret ] && { chown root:1000 $S/secrets/entra_client_secret; chmod 0440 $S/secrets/entra_client_secret; }
chown root:1000 $S/secrets; chmod 0750 $S/secrets

# ---- PostgreSQL TLS: a private CA on this host for the one internal hop (Keycloak verifies with verify-full)
if [ ! -s $S/pki/db.crt ]; then
  ( umask 077; cd $S/pki
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -sha256 -subj "/CN=idp db CA" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout db-ca.key -out db-ca.crt 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=db" -keyout db.key -out db.csr 2>/dev/null
    printf 'subjectAltName=DNS:db\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' > db.ext
    openssl x509 -req -in db.csr -CA db-ca.crt -CAkey db-ca.key -CAcreateserial -days 825 -sha256 -extfile db.ext -out db.crt 2>/dev/null
    rm -f db.csr db.ext )
fi
chown root:root $S/pki/db-ca.key; chmod 0400 $S/pki/db-ca.key
chown root:1000 $S/pki/db-ca.crt; chmod 0444 $S/pki/db-ca.crt
chown 999:999 $S/pki/db.crt $S/pki/db.key; chmod 0400 $S/pki/db.key; chmod 0444 $S/pki/db.crt
chown root:1000 $S/pki; chmod 0755 $S/pki
cat > $S/config/pg_hba.conf <<'H'
# TLS only, SCRAM only, one database and one role. The local socket (peer) is for pg_dump/psql via docker exec.
local   all       all                    peer map=ops
hostssl keycloak  keycloak  0.0.0.0/0    scram-sha-256
hostssl keycloak  keycloak  ::/0         scram-sha-256
host    all       all       0.0.0.0/0    reject
host    all       all       ::/0         reject
H
printf '# the container OS user (postgres, uid 999) may act as the keycloak role over the local socket only
ops postgres keycloak
' > $S/config/pg_ident.conf
chmod 0444 $S/config/pg_hba.conf $S/config/pg_ident.conf
chown 999:999 $S/pgdata; chmod 0700 $S/pgdata

# ---- server certificate: Let's Encrypt via DNS-01, both names, renewed by certbot.timer. The challenge is answered by
#      idp-acme-hook writing delegated TXT records in Azure DNS (ACME_ZONE); no DNS-provider credential here.
ACME_PARENT="${PUBLIC_HOST#*.}"
printf 'ACME_ZONE=%s\nACME_RG=%s\nACME_PARENT=%s\nACME_DOMAINS="%s"\n' "$ACME_ZONE" "$ACME_RG" "$ACME_PARENT" \
  "$PUBLIC_HOST${ADMIN_HOST:+ $ADMIN_HOST}" > /etc/default/idp-acme
chown root:root /etc/default/idp-acme; chmod 0644 /etc/default/idp-acme
install -o root -g root -m 0755 "$HERE/acme-hook.sh" /usr/local/sbin/idp-acme-hook
install -D -m 0755 "$HERE/tls-deploy-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/idp-tls.sh
RENEWAL=/etc/letsencrypt/renewal/$PUBLIC_HOST.conf
if [ ! -d "/etc/letsencrypt/live/$PUBLIC_HOST" ] || ! grep -qx 'authenticator = manual' "$RENEWAL" 2>/dev/null \
   || ! grep -qx 'manual_auth_hook = /usr/local/sbin/idp-acme-hook auth' "$RENEWAL" \
   || ! grep -qx 'manual_cleanup_hook = /usr/local/sbin/idp-acme-hook cleanup' "$RENEWAL"; then
  # first certificate, or a renewal conf not wired to this hook (e.g. still the Cloudflare plugin): (re-)issue
  certbot certonly -n --agree-tos --register-unsafely-without-email --manual --preferred-challenges dns \
    --manual-auth-hook "/usr/local/sbin/idp-acme-hook auth" --manual-cleanup-hook "/usr/local/sbin/idp-acme-hook cleanup" \
    --force-renewal --cert-name "$PUBLIC_HOST" -d "$PUBLIC_HOST" ${ADMIN_HOST:+-d "$ADMIN_HOST"} --key-type ecdsa
fi
# no DNS-provider token may remain on the host
[ -f /etc/letsencrypt/cloudflare.ini ] && shred -u /etc/letsencrypt/cloudflare.ini
for p in python3-certbot-dns-cloudflare python3-cloudflare; do
  dpkg -s "$p" >/dev/null 2>&1 && apt-get purge -y -qq "$p" >/dev/null
done
RENEWED_LINEAGE="/etc/letsencrypt/live/$PUBLIC_HOST" IDP_NO_RESTART=1 /etc/letsencrypt/renewal-hooks/deploy/idp-tls.sh
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

# ---- images: keycloak-cac built here from a git archive of this repository at KCAS_COMMIT (no GitHub
#      credential on this host), the public variant derived from it, PostgreSQL pinned by digest.
SHORT=${KCAS_COMMIT:0:7}; SUFFIX=$([ "$FIPS" = true ] && echo -fips || true)
IMG="idp/keycloak-cac:${KC_VERSION}${SUFFIX}-${SHORT}"
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  : "${KCAS_TAR:?KCAS_TAR (git archive of keycloak-asd-stig at KCAS_COMMIT) is needed to build}"
  rm -rf "$S/src/keycloak-asd-stig-$SHORT"; mkdir -p "$S/src/keycloak-asd-stig-$SHORT"
  tar -xf "$KCAS_TAR" -C "$S/src/keycloak-asd-stig-$SHORT"
  log "building $IMG (FIPS=$FIPS) from keycloak-asd-stig@$KCAS_COMMIT"
  docker build -q -f "$S/src/keycloak-asd-stig-$SHORT/keycloak-cac/Containerfile" --build-arg FIPS="$FIPS" \
    --label org.opencontainers.image.revision="$KCAS_COMMIT" -t "$IMG" "$S/src/keycloak-asd-stig-$SHORT" >/dev/null
fi
docker pull -q "$POSTGRES_REF" >/dev/null
PG_DIGEST=$(docker image inspect -f '{{index .RepoDigests 0}}' "$POSTGRES_REF")
cat > $S/compose/.env <<E
KEYCLOAK_IMAGE=$IMG
POSTGRES_IMAGE=$PG_DIGEST
E
{ echo "# image IDs (content digests) in use, written $(date -u +%FT%TZ)"; echo "keycloak-asd-stig commit: $KCAS_COMMIT"
  echo "$IMG $(docker image inspect -f '{{.Id}}' "$IMG")"; echo "$PG_DIGEST"; } > $S/compose/images.lock

# ---- configuration
export PUBLIC_HOST REALM REALM_DISPLAY CAC_ADMINS
envsubst '${PUBLIC_HOST} ${REALM} ${REALM_DISPLAY} ${CAC_ADMINS}' < "$HERE/keycloak-cac.env.template" > $S/config/keycloak-cac.env
chmod 0444 $S/config/keycloak-cac.env
install -m 0444 "$HERE/compose.yaml" $S/compose/compose.yaml
# optional login theme (THEME_DIR, your own; brand is instance data), bind-mounted read-only by compose.yaml once you
# uncomment its THEME line, and selected through CAC_PROFILE_JSON. One command per line: set -e does not stop on a
# failure inside an && list, only on its last command. Synced INTO the existing directory, never replaced: the bind
# mount holds the directory itself, so rm -rf + mv would leave a running Keycloak on the deleted, emptied copy. Theme
# changes still need a Keycloak restart.
if [ -n "${THEME_DIR:-}" ]; then
  T="$(basename "$THEME_DIR")"
  rm -rf "$S/theme/$T.new"
  mkdir -p "$S/theme/$T"
  cp -R "$THEME_DIR" "$S/theme/$T.new"
  find "$S/theme/$T.new" -type d -exec chmod 0755 {} +
  find "$S/theme/$T.new" -type f -exec chmod 0644 {} +
  chown -R root:root "$S/theme/$T.new"
  rsync -a --delete "$S/theme/$T.new/" "$S/theme/$T/"
  rm -rf "$S/theme/$T.new"
fi
# Keycloak container egress (README, "Egress firewall"): in place and verified before any compose up (checked again
# right before it); docker.service requires the unit from the next boot on. Applying the rules while dockerd runs
# restarts nothing.
install -m 0755 "$HERE/egress.sh" /usr/local/sbin/idp-egress
install -m 0644 "$HERE/idp-egress.service" /etc/systemd/system/idp-egress.service
if [ ! -f /etc/default/idp-egress ]; then
  printf 'EGRESS_SUBNET=172.31.250.0/24\nBACKEND_SUBNET=172.31.251.0/24\n' > /etc/default/idp-egress
fi
systemctl daemon-reload
systemctl enable idp-egress.service
/usr/local/sbin/idp-egress
/usr/local/sbin/idp-egress --check || { log "egress rules not in place"; exit 1; }
# client registrations (instance data): only from CLIENTS_DIR, never from this repository; afterwards add-client
# maintains /srv/idp/clients itself
if [ -n "${CLIENTS_DIR:-}" ]; then for c in "$CLIENTS_DIR"/*.json; do install -m 0444 "$c" $S/clients/; done; fi

# ---- run. First start: bootstrap admin exists only while Keycloak is reachable from this host alone (127.0.0.1:443);
#      once the image has hardened the master realm (bootstrap deleted), 443 is published and the bootstrap env is gone.
# No container starts unless the egress unit is enabled (fail closed at the next boot) and its rules are in place now.
systemctl is-enabled --quiet idp-egress.service || { log "idp-egress.service is not enabled: not starting the stack"; exit 1; }
/usr/local/sbin/idp-egress --check || { log "egress rules not in place: not starting the stack"; exit 1; }
C="docker compose --env-file $S/compose/.env -f $S/compose/compose.yaml"
if [ ! -f $S/config/.master-hardened ]; then
  install -m 0444 "$HERE/compose.bootstrap.yaml" $S/compose/compose.bootstrap.yaml
  $C -f $S/compose/compose.bootstrap.yaml up -d --remove-orphans
  for i in $(seq 1 120); do docker logs idp-keycloak-1 2>&1 | grep -q "bootstrap temporary admin 'bootstrap' deleted" && break; sleep 10; done
  docker logs idp-keycloak-1 2>&1 | grep -q "bootstrap temporary admin 'bootstrap' deleted" || { log "master realm not hardened; 443 NOT published"; exit 1; }
  touch $S/config/.master-hardened; shred -u $S/secrets/bootstrap_admin_password $S/compose/compose.bootstrap.yaml 2>/dev/null || true
fi
$C up -d --remove-orphans

# ---- daily encrypted backup to the storage account (identity auth), passphrase escrowed in Key Vault
install -m 0755 "$HERE/backup.sh" /usr/local/sbin/idp-backup
install -m 0755 "$HERE/restore.sh" /usr/local/sbin/idp-restore
install -m 0755 "$HERE/idp-admin.py" /usr/local/sbin/idp-admin.py
# its per-instance configuration (applications, delegations, mail and Entra defaults): the example once, never
# overwritten; edit it for your deployment (host/idp-admin.example.json documents every key)
[ -e $S/config/idp-admin.json ] || install -o root -g root -m 0600 "$HERE/idp-admin.example.json" $S/config/idp-admin.json
# the client-request validator add-client applies, from this same repository (keycloak-rp-integration)
install -d -m 0755 /usr/local/lib/idp
install -m 0644 "$VALIDATOR" /usr/local/lib/idp/validate-client-request.py
install -m 0755 "$HERE/idp-events.sh" /usr/local/sbin/idp-events
install -m 0755 "$HERE/restart.sh" /usr/local/sbin/idp-restart
install -m 0755 "$HERE/idp-alert.py" /usr/local/sbin/idp-alert
printf 'STORAGE_ACCOUNT=%s\nKEY_VAULT=%s\n' "$STORAGE_ACCOUNT" "$KEY_VAULT" > /etc/default/idp-backup
cat > /etc/systemd/system/idp-backup.service <<U
[Unit]
Description=Encrypted backup of the shared IdP (PostgreSQL + configuration) to Azure Blob Storage
After=docker.service
OnFailure=idp-alert@%n.service
[Service]
Type=oneshot
EnvironmentFile=/etc/default/idp-backup
ExecStart=/usr/local/sbin/idp-backup
U
cat > /etc/systemd/system/idp-backup.timer <<U
[Unit]
Description=Daily shared IdP backup
[Timer]
OnCalendar=*-*-* 03:30:00 UTC
RandomizedDelaySec=15m
Persistent=true
[Install]
WantedBy=timers.target
U
cat > /etc/systemd/system/idp-guard.service <<U
[Unit]
Description=Shared IdP: protect administrators from delegates; strip untrusted factors from new ones; fail loudly
OnFailure=idp-alert@%n.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/idp-admin.py guard --fix
U
cat > /etc/systemd/system/idp-alert@.service <<U
[Unit]
Description=Mail an alert: %i failed
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/idp-alert %i
U
cat > /etc/systemd/system/idp-guard.timer <<U
[Unit]
Description=Shared IdP guard every 10 minutes
[Timer]
OnBootSec=5m
OnUnitActiveSec=10m
[Install]
WantedBy=timers.target
U
# a renewed certificate Keycloak is not serving (the TLS hook skipped the restart on client drift): mailed daily
cat > /etc/systemd/system/idp-cert-check.service <<U
[Unit]
Description=Shared IdP: the certificate on disk is the one Keycloak serves (else a restart is pending)
OnFailure=idp-alert@%n.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/idp-admin.py cert-check
U
cat > /etc/systemd/system/idp-cert-check.timer <<U
[Unit]
Description=Shared IdP certificate check, daily
[Timer]
OnCalendar=*-*-* 09:00:00 UTC
Persistent=true
[Install]
WantedBy=timers.target
U
systemctl daemon-reload
systemctl enable --now idp-backup.timer idp-guard.timer idp-cert-check.timer
log "done: https://$PUBLIC_HOST/realms/$REALM (admin console: https://$PUBLIC_HOST/admin/$REALM/console/)"
