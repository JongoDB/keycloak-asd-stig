# keycloak-cac on a single VM

A complete, hardened recipe for running the `keycloak-cac` image on one Linux VM (Ubuntu 24.04) with Docker Compose:
Keycloak plus PostgreSQL, a container egress firewall, encrypted off-host backups, Let's Encrypt certificates over
DNS-01 with no DNS-provider credential on the host, failure alerts by mail, and an operator CLI for accounts,
clients and delegated administration. The Azure scripts provision the VM; everything under `host/` is plain Linux
and works on any cloud or on premises once the Azure-specific pieces (IMDS identity for backups and ACME, the data
disk path) are swapped.

| Path | What it is |
|---|---|
| `azure/azure-provision.sh` | Resource group, NSG (443 and the card port 8444 from the internet, 22 from the operator only), VNet, static public IP, Trusted Launch VM with a data disk and a system identity, a private storage account for backups, a Key Vault for the backup passphrase, and an Azure DNS zone the parent zone delegates ACME challenges to. Every name is a required variable. |
| `azure/check-escrow-lockdown.sh` | Install step 6: checks that the backup passphrase is escrowed and the VM can only read it (read-only; exit 1 with what to do otherwise). |
| `azure/cloudflare-dns.sh`, `azure/cloudflare-mail-dns.sh` | DNS-only A records for the IdP; the mail records (verification, SPF, DKIM, DMARC) for an Azure Communication Services sender domain. |
| `host/setup-host.sh` | Everything on the VM, idempotent: packages, Docker and SSH hardening, the data disk at `/srv/idp`, secrets, the database's private CA, the certificate, the image build, configuration, the egress firewall, the stack, and the systemd timers. |
| `host/compose.yaml`, `host/compose.bootstrap.yaml`, `host/keycloak-cac.env.template` | The stack. The bootstrap overlay is used on the first start only. |
| `host/egress.sh`, `host/idp-egress.service` | The container egress firewall (`/usr/local/sbin/idp-egress`). |
| `host/backup.sh`, `host/restore.sh` | Encrypted backup to Blob Storage and restore (`idp-backup`, `idp-restore`). |
| `host/acme-hook.sh`, `host/tls-deploy-hook.sh` | certbot DNS-01 hook and deploy hook. |
| `host/idp-events.sh`, `host/idp-alert.py` | Sign-in event view; failure mail. |
| `host/restart.sh` | `idp-restart`: restart Keycloak or switch it to another local image, and wait until it is healthy (see "Restarting Keycloak"). |
| `host/idp-admin.py`, `host/idp-admin.example.json` | The operator CLI and its per-instance configuration (see below). |
| `tests/` | Offline and on-host tests (see "Tests"). |

## Layout on the host

Everything stateful lives on the data disk, mounted at `/srv/idp`:

| Path | Contents | Mode |
|---|---|---|
| `config/` | `keycloak-cac.env` (rendered), `pg_hba.conf`, `pg_ident.conf`, `idp-admin.json`, `alert.env` | 0444 / 0600 |
| `secrets/` | `db_password`, `automation_secret`, `backup_passphrase`, optional `entra_client_secret`, `smtp_password` | 0440 root:1000 (0400 for the passphrase) |
| `pki/` | the private CA and certificate for the Keycloak to PostgreSQL hop (`verify-full`) | |
| `tls/` | `tls.crt`, `tls.key`, installed by the certbot deploy hook | 0440 root:1000 |
| `clients/` | one `<client>.json` per relying application, read by the image at every start | 0444 |
| `state/` | `idp-admin.py`'s state: the vetted-administrator allowlist and guard records | root only |
| `pgdata/` | PostgreSQL | 0700, uid 999 |
| `compose/` | `compose.yaml`, `.env` (image references), `images.lock` (image IDs in use) | |
| `crl-cache/` | the last good DoD CRLs (public data), written by every refresh and installed by a new container before Keycloak starts | 0750, uid 1000 |
| `src/` | extracted copies of this repository, one per commit the image was built from | |
| `theme/` | an optional login theme of your own | |

Keycloak runs as 1000:1000 with a read-only root, all capabilities dropped and `/opt/keycloak/data` on tmpfs (rebuilt
from the image on every start). The CRLs Keycloak reads live there too, so a CRL from a retired CA can never survive an
upgrade. `crl-cache/` is not that directory: at start the image installs from it only the CRLs whose signature verifies
against its current anchors (`CAC_CRL_CACHE_DIR`).

## Install

1. **Azure resources**, from an operator machine with `az` logged in:
   ```bash
   SUB=<subscription> RG=<resource group> N=<vm name> SA=<storage account> KV=<key vault> \
   ACME_ZONE=acme.example.mil ACME_NAMES="idp" OWNER=<owner tag> ./azure/azure-provision.sh
   ```
2. **DNS**: an A record for the public name (`ZONE=example.mil NAMES=idp CF_TOKEN_FILE=... ./azure/cloudflare-dns.sh <ip>`),
   and in the parent zone an NS delegation of `ACME_ZONE` to the Azure DNS zone plus a CNAME
   `_acme-challenge.idp.example.mil -> _acme-challenge.idp.acme.example.mil`. The records must be DNS-only (not
   proxied): the card has to reach Keycloak's own TLS handshake.
3. **Copy this repository to the VM** as a git archive (the host needs no Git credential), and extract it:
   ```bash
   git archive --format=tar <commit> > kcas.tar && scp kcas.tar <vm>:/root/keycloak-asd-stig.tar
   ssh <vm> 'sudo mkdir -p /root/kcas && sudo tar -xf /root/keycloak-asd-stig.tar -C /root/kcas'
   ```
4. **Run the host setup** from the extracted copy:
   ```bash
   cd /root/kcas/keycloak-cac/deploy/vm/host
   sudo PUBLIC_HOST=idp.example.mil REALM=example REALM_DISPLAY="Example sign-in" \
        KCAS_TAR=/root/keycloak-asd-stig.tar KCAS_COMMIT=<commit> \
        STORAGE_ACCOUNT=<storage account> KEY_VAULT=<key vault> ACME_ZONE=acme.example.mil ACME_RG=<resource group> \
        [CLIENTS_DIR=<your client files>] [THEME_DIR=<your theme>] ./setup-host.sh
   ```
   The first start runs with a temporary bootstrap admin while Keycloak is reachable from the host's loopback only.
   Once the image has hardened the master realm (Alt Token-only, password grant denied, bootstrap admin deleted),
   setup removes the bootstrap secret and publishes 443 and 8444.
5. **Edit `/srv/idp/config/idp-admin.json`** for your applications (it starts as the example), then
   `sudo idp-admin.py roles-setup` and `sudo idp-admin.py guard`.
6. **Escrow the backup passphrase and lock it down** (required): run the first backup on the VM
   (`sudo systemctl start idp-backup`; its log says `passphrase escrowed`), then re-run `azure/azure-provision.sh` from
   the operator machine (it now leaves the VM read-only on the secret), then
   `SUB=... RG=... N=... KV=... ./azure/check-escrow-lockdown.sh`, which must print `OK`. Until then the VM can still
   write versions of the passphrase.

Client registrations, a brand theme and the CLI configuration are instance data and are not in this repository.
Keep them in your own (private) repository and point `CLIENTS_DIR` / `THEME_DIR` at it.

## Egress firewall

`idp-egress` (from `host/egress.sh`) lets Keycloak reach the public internet (DoD CRL and OCSP, a brokered identity
provider, the mail relay, relying applications' JWKS and back-channel URLs) and nothing internal. It is the control
behind `idp-admin.py add-client`'s add-time check that those URLs resolve to public addresses: DNS can change after
the check, and the network refuses internal destinations whatever name led there.

- New connections from the Keycloak egress network to loopback, link-local (including the instance metadata
  service), RFC 1918, CGNAT, multicast, reserved space, or the Azure WireServer (other than DNS) are logged and
  dropped. The backend network (Keycloak to PostgreSQL) may talk only within itself.
- No container network can open a connection to a host listener.
- The metadata endpoints are unreachable from anything but the host itself (raw table).
- It fails closed: `idp-egress.service` runs before `docker.service`, which requires it, so no container starts
  without the rules. **Never `systemctl restart` or `stop` it** (that restarts or stops dockerd). To re-apply, run
  `sudo idp-egress`; to verify, `sudo idp-egress --check` (exact rule-for-rule comparison).
- The bridge names and subnets are fixed in `compose.yaml` and must match `/etc/default/idp-egress`.
- IPv4 only; anything holding the Docker socket is root and outside this control.

## Backup and restore

`idp-backup.timer` runs daily: a `pg_dump` plus `/srv/idp/{config,secrets,clients,pki,compose,state}` and
`/etc/letsencrypt`, as one tarball encrypted with gpg (AES-256), uploaded to the storage account with the VM's
managed identity (the account allows no shared keys). The passphrase is escrowed in Key Vault on the first run.

A compromised VM cannot destroy its own backups: the `backups` container has a time-based immutability policy
(`BACKUP_RETENTION_DAYS`, default 90; lock it with `LOCK_BACKUP_IMMUTABILITY=1` once the period is settled - locking
is irreversible), blob and container soft delete, and the VM's identity holds a custom role with read, create and
write only (no delete). Backups expire through lifecycle management the day after their immutability ends. In Key
Vault (purge protection on) the VM's identity reaches only the passphrase secret (`KV_SECRET`), through a custom role
with get, set and read-metadata only: no delete, purge, recover, backup or restore. `azure-provision.sh` creates the
secret as a placeholder for `idp-backup` to replace on its first run. Once the first backup has logged
`passphrase escrowed`, re-run `azure-provision.sh` (install step 6): as soon as any version of the secret is
escrowed it leaves the VM get and read-metadata only by default
(`KEEP_PASSPHRASE_WRITE=1` opts out), so it can no longer write new versions over the real passphrase. `idp-restore fetch` tries the
host's passphrase file, then every Key Vault version (all pages) newest first, until one decrypts the backup;
`RESTORE_SECRET_VERSION=<version id>` pins one known-good version and tries nothing else. More than
`RESTORE_MAX_VERSIONS` (default 10) enabled versions is treated as possible tampering: refused unless `RESTORE_FORCE=1`.

Every backup first checks that the escrowed passphrase is this host's (compared in memory) and refuses to run, alerting,
when it is not - so a rebuilt VM's fresh passphrase, or a rotated one, never silently produces backups the escrow cannot
decrypt. To fix it, either put the escrowed passphrase back in `/srv/idp/secrets/backup_passphrase` (e.g. after a
restore onto a new VM), or, deliberately, escrow the host's current passphrase as a new version of the secret from the
operator machine (`az keyvault secret set --vault-name <kv> -n <secret> --file <0600 file> --content-type "gpg
passphrase for idp backups"`); earlier versions stay, so older backups remain decryptable.

**Applying this to an existing deployment includes irreversible steps.** On a new install the hardening is what you
want from the start. Re-running a current `azure-provision.sh` against resources an earlier version created does more:
- it enables Key Vault purge protection, which cannot be undone;
- it puts an immutability policy on the existing `backups` container. The policy covers backups already stored, and
  cannot be undone once locked (`LOCK_BACKUP_IMMUTABILITY=1`);
- it swaps the VM's roles. If the passphrase is already escrowed, the VM becomes read-only on it at once.

Review those steps, and get the owner's approval, before re-running it against a running deployment.

```bash
sudo idp-restore list
sudo idp-restore fetch <blob> /root/restore      # download, decrypt, unpack
sudo idp-restore db /root/restore                # DESTRUCTIVE: replace the database
```

On a new VM: run `setup-host.sh` first, then `fetch`, put the backup's `secrets/`, `clients/` and `state/` back (the
automation secret must match the database; restore `state/` before the guard timer runs), then `db`.

## TLS certificate

certbot issues and renews the certificate over DNS-01. `idp-acme-hook` writes the challenge into the delegated
Azure DNS zone with the VM's identity, which may write exactly the TXT record sets of its own names, so a compromised
host can change no other DNS record. Its configuration (`/etc/default/idp-acme`) is parsed as data, never sourced.

The deploy hook installs the renewed certificate and restarts Keycloak (the strict-FIPS image converts it at start)
**only if `idp-admin.py check-clients` reports no drift**, because a restart re-applies every file in
`/srv/idp/clients`. On drift it installs the certificate, does not restart, and mails an alert. `idp-cert-check.timer`
mails daily while the served certificate differs from the one on disk.

## Alerts

`idp-alert@.service` is the `OnFailure=` of the backup, guard and certificate-check units: it mails the unit's last
60 journal lines through the configured SMTP relay, independently of Keycloak. Configure it with
`sudo idp-admin.py smtp --user <smtp user> --alert-to <address>` (the password comes from
`/srv/idp/secrets/smtp_password`). `idp-events [minutes]` prints recent sign-in, sign-out, error and admin-gate
events.

## Restarting Keycloak

Use `idp-restart`; do not restart the container by hand and treat "running" as "ready".

```bash
sudo idp-restart                                   # restart, wait until healthy
sudo idp-restart --image <tag>                     # run another image already built or loaded on this host
```

It refuses to start unless the egress rules are in place (`idp-egress --check`) and `idp-admin.py check-clients`
reports no drift, then restarts (or, with `--image`, recreates) the `keycloak` service and waits up to 15 minutes
(`--timeout <s>`) for the container to be **healthy**. Healthy means Keycloak is ready, the realm is applied and **every
expected CRL is installed**: a container still missing one reports `not ready: N of M CRLs not installed: <names>`
(`docker inspect idp-keycloak-1`, or `docker exec idp-keycloak-1 /opt/keycloak-cac/bin/cac-entrypoint.sh health`) and
logs `STIG-CRL-INCOMPLETE` while it retries every minute. Card sign-in for a CA whose CRL is missing is refused
(`STIG-CRL-NO-ISSUER-CRL`, "Certificate revoked or incorrect"), never allowed without it.

Why a restarted container has CRLs at once: the CRLs Keycloak reads are on tmpfs and start empty, and the image
downloads ~140 MB of DoD CRLs in the background. Without a cache every restart refused the cards of each CA whose CRL had not arrived yet, for the length of that
download. With `/srv/idp/crl-cache` the entrypoint installs the last good CRLs before Keycloak starts (each signature
checked against the current anchors); the download then only replaces them. Only a host's very first start, or one
with an emptied cache, has that window, and the container stays unhealthy for its length.

`--image <tag>` writes `/srv/idp/compose/.env` and the keycloak line of `images.lock` from
`docker image inspect <tag>` (the tag with **its own** image ID, the commit from its revision label), the way
`setup-host.sh` does, and after the restart checks that the container runs exactly that image ID. Never edit
`images.lock` by hand: a new tag paired with the previous image's ID records an image that is not running. Before
rewriting, it keeps the previous pair as `.env.prev-<UTC time>` and `images.lock.prev-<UTC time>`; if anything fails
after that, it prints one `ROLLBACK` line (copy both back and `up -d --no-deps keycloak`, or
`idp-restart --image <old tag>`).

A timeout that lists CRLs not installed is usually a CRL-source outage, not a bad image: Keycloak may already be serving
sign-in, and only the cards of those CAs are refused until their CRLs arrive. Rolling back would not help (the previous
image needs the same CRLs); check `docker logs idp-keycloak-1 | grep STIG-CRL` first.

`idp-egress` is a systemd unit (`idp-egress.service`), not a compose service, and is never part of a restart: see
"Egress firewall". If the rules are missing, `sudo idp-egress` re-applies them without restarting anything.

## Upgrades

1. Take a backup (`sudo systemctl start idp-backup`) and confirm `sudo idp-admin.py guard` is clean.
2. Copy the new commit's archive to the VM and re-run `setup-host.sh` with the new `KCAS_COMMIT`: it builds the new
   image only when the commit changes, re-renders the configuration and recreates the stack.
3. Before any Keycloak restart, `sudo idp-admin.py check-clients` must report no drift (`idp-restart` checks it).
4. To roll back, re-run with the previous `KCAS_COMMIT` (its image is still present) or restore the backup.

## Break-glass

The master realm has no usable sign-in. Recovery is `kc.sh bootstrap-admin service` inside the Keycloak container
on the VM. Day-to-day administration is the application realm's own admin console, by realm role.

## Account administration: `idp-admin.py`

`host/idp-admin.py` (installed as `/usr/local/sbin/idp-admin.py`) runs on the VM as root, inside the Keycloak
container's network namespace, as the `stig-automation` service account. It invites and creates users (card,
password + TOTP, brokered), registers and checks clients without a restart, sets up per-application delegated user
managers and service-account delegates, and runs the administrator guard every 10 minutes. Its per-instance
configuration (applications and their role groups, delegations, mail and broker defaults) is
`/srv/idp/config/idp-admin.json`; `IDP_ADMIN_CONFIG` overrides the path. `host/idp-admin.example.json` documents every
key. The account procedures are in [docs/vm-accounts.md](../../../docs/vm-accounts.md).

## Tests

| Test | Where it runs |
|---|---|
| `tests/tls_hook_test.sh <tls-deploy-hook.sh>` | anywhere as root (stubs docker and the CLI) |
| `tests/restart_test.sh <restart.sh>` | anywhere as root (stubs docker, the CLI and idp-egress) |
| `tests/egress_netns_test.sh <egress.sh>` | anywhere as root with `ip netns` and iptables (a privileged container works) |
| `tests/run-e2e.sh` | on the VM: password + TOTP path, lockout, banner, concurrent sessions, forged header (`E2E_CLIENT`, `E2E_REDIRECT`) |
| `tests/hardening_test.py`, `tests/card_allowlist_gate.sh`, `tests/in_keycloak_netns.py` | on the VM |
| `tests/pw_session_limit.py`, `tests/forged_header_check.py` | driven by `run-e2e.sh` |
