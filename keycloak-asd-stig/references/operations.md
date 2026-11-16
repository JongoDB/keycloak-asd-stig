# Operations runbook (procedures assessors ask for)

## Contents
1. Break-glass / admin recovery
2. Unlocking a locked account (V-222433)
3. Temporary and emergency accounts (V-222409, V-222410)
4. CRL refresh (V-222553)
5. Audit off-load and alerts (V-222481..V-222485, V-222417..V-222422)
6. Re-running apply / verify (drift control)
7. Upgrading Keycloak
8. Delegated account creation: allowed e-mail domains (stig-accounts)

## 1. Break-glass / admin recovery
After hardening, the admin realm has no password grant (ROPC denied), the bootstrap admin is deleted, and
admins log in only with the Alt Token. If every admin is locked out:
```
# on the Keycloak host, same image/config/DB as the running server
export RECOVERY_SECRET=$(openssl rand -hex 24)
docker compose run --rm --no-deps -e RECOVERY_SECRET keycloak \
  bootstrap-admin service --client-id=break-glass-recovery --client-secret:env=RECOVERY_SECRET --optimized
```
Kubernetes: run the same command as a one-off pod with the Keycloak Deployment's image, env and secret volumes
(e.g. `kubectl debug deploy/keycloak --copy-to=kc-recovery --container=keycloak -- /opt/keycloak/bin/kc.sh
bootstrap-admin service --client-id=break-glass-recovery --client-secret:env=RECOVERY_SECRET --optimized`, with
RECOVERY_SECRET added to the copy's env), then delete the copy. (Tested with Compose against the same database.)

This creates a temporary admin *service client* (flagged `is_temporary_admin`). Use it via
`KC_CLIENT_ID=break-glass-recovery KC_CLIENT_SECRET=$RECOVERY_SECRET kcstig.py ...` to repair, then run
`kcstig.py apply --profile p.json --admin-only --harden-master --remove-bootstrap-admin` with the normal
automation credentials - it deletes temporary admin users AND clients, and `verify` fails
`master.no_bootstrap_admin` until it is gone. Log the event and notify the ISSO (tested in the lab).

## 2. Unlocking a locked account (V-222433)
`permanentLockout=true`: after 3 failures in 15 minutes the account stays disabled until an admin acts.
Approved procedure (have the ISSM/ISSO sign it):
1. The user contacts the service desk; identity is verified in person or by a callback to the number of record
   plus a second identity attribute (never by e-mail alone).
2. Admin console > realm > Users > the user > toggle *Enabled* (or Sessions/Brute force "Unlock").
3. If a password compromise is suspected: Credentials > Reset password (temporary) - the user must change it
   at next login (V-222547).
4. Record ticket number, verifier, time. The admin event (`STIG-ACCOUNT-EVENT action=ENABLED_OR_MODIFIED`)
   is the system record.

## 3. Temporary and emergency accounts
- Temporary: create with attribute `account_type=temporary`; workflow `stig-temp-account-72h` disables it
  72 h after creation. The runner interval (`step-runner-task-interval=900` s) bounds the lateness to 15 min.
- Emergency: `account_type=emergency` exempts the account from the 35-day inactivity workflow. Restrict who
  may delete such accounts (fine-grained admin permissions) and review them quarterly.
- Inactivity: workflow `stig-disable-inactive-35d` (`on: user-created or user-authenticated`,
  `restart-in-progress: true`) disables users 35 days after creation or their last logon.

## 4. CRL refresh
`scripts/fetch_dod_pki.sh /srv/keycloak-stig --crl-only` daily, e.g. systemd timer or
`17 3 * * * root /opt/kcstig/scripts/fetch_dod_pki.sh /srv/keycloak-stig --crl-only >> /var/log/kc-crl.log 2>&1`.
Alert if a CRL's nextUpdate is within 24 h (Keycloak refuses stale CRLs: logins would fail closed).

## 5. Audit off-load and alerts
- Events reach the SIEM through `log=console,syslog` (`log-syslog-endpoint`), JSON console, and the HTTP access
  log. User events (LOGIN, LOGIN_ERROR, LOGOUT, CODE_TO_TOKEN, REFRESH_TOKEN, UPDATE_PASSWORD ...) and admin
  events (with representation) are logged by `jboss-logging` at INFO/WARN.
- SIEM alert rules to create:
  - `STIG-ACCOUNT-EVENT` -> notify SA + ISSO (account create/modify/disable/enable/remove).
  - `STIG-CONCURRENT-LOGON` -> notify (concurrent logons from different workstations, V-222672).
  - `error="user_temporarily_disabled"` / lockouts -> notify.
  - syslog silence > 5 min from a Keycloak node -> audit-failure alert (V-222484/V-222485).
- Retention: 30 months (12 online + 18 cold), 5 years for SAMI (V-222621) in the SIEM. `eventsExpiration` in
  Keycloak is only the local buffer (default 90 days).

## 6. Drift control
Run `kcstig.py verify --profile p.json --live-url https://... --deploy-dir <stack> --strict` from CI nightly
with the automation service account. Non-zero exit = drift. Attach the generated `.ckl/.cklb` to eMASS.
`apply` is idempotent: flows are rebuilt, workflows are only replaced when their definition changed (so the
inactivity clocks of existing users are preserved).

## 7. Upgrading Keycloak (tested 26.7.5 -> 26.8.2 in place on the same database)
1. `scripts/build_images.sh --base-image <new image> --tag <new>-stig ...` (recompiles the SPI for that version).
2. Roll the Keycloak image; Keycloak migrates the database on start ("Migrating older model to 26.8.0").
3. Run the apply job. Workflows are left untouched when unchanged, so users' 35-day/72-hour timers survive
   (same workflow IDs before and after, verified).
4. **Crossing into 26.8 from an older release:** the admin API starts requiring the `kc-admin-api` audience and the
   existing automation service account does not get that scope during migration - the apply job fails with 401
   (`kcstig.py` prints this diagnosis). Recover once:
   ```
   export RECOVERY_SECRET=$(openssl rand -hex 24)
   <run the new Keycloak image with the same env/secrets>: kc.sh bootstrap-admin service --client-id=break-glass-recovery --client-secret:env=RECOVERY_SECRET --optimized
   KC_CLIENT_ID=break-glass-recovery KC_CLIENT_SECRET=$RECOVERY_SECRET kcstig.py apply --profile p.json --harden-master --automation-secret-file <file>   # adds kc-admin-api
   KC_CLIENT_ID=stig-automation ... kcstig.py apply --profile p.json --harden-master --remove-bootstrap-admin ...           # deletes the recovery client
   ```
5. Run `verify` and `e2e_check.py` (tested: 20/20 and clean verify after the upgrade).
6. Re-check `references/keycloak-notes.md` against the release notes (build-time options, admin API, client-policy
   executors, theme page IDs, workflow syntax).

## 8. Delegated account creation: allowed e-mail domains (stig-accounts)

> **Upgrade note.** The built-in default no longer includes any domain other than `.mil`, and a configured value
> is now authoritative and fails closed. **Before upgrading**, set `stig.accounts.email-domains` (on the realm, or
> on the calling client) to the list you rely on, or creations for those domains are refused with 403.
>
> | Situation | Before | After |
> |---|---|---|
> | Attribute unset on both client and realm | `.mil` plus one built-in non-`.mil` domain | `.mil` only |
> | Client attribute set but blank | fell through to the realm attribute | no domain allowed for that caller |
> | Realm attribute set but blank | fell back to the built-in default | no domain allowed |
> | A list with one malformed entry (`*.mil`, `@x.org`, `x .org`) | the bad entry was skipped and the rest applied | no domain allowed |
> | A well-formed list | applied | applied (unchanged) |
The `stig-accounts` admin endpoint (in `stig-extensions.jar`) lets an IdP user manager, or an application's service
account holding `realm-management/query-users`, create accounts. It creates them only for e-mail addresses in an
allowlist of domains:

| Where | Attribute | Scope |
|---|---|---|
| The caller's client (service-account callers) | `stig.accounts.email-domains` | that caller only; wins over the realm |
| The realm | `stig.accounts.email-domains` | every caller without a client value |

- Value: a comma list. `.mil` matches any domain ending in `.mil`; `example.org` matches exactly that domain, not
  its subdomains. Example: `.mil,example.org`.
- **Unset on both: `.mil` only.** Every other organization's domain must be configured explicitly.
- **Set but with no entries, or with any malformed entry** (`*.mil`, `@example.org`, `x .org`): **no domain is
  allowed**. The endpoint fails closed and refuses every creation with "e-mail domain not allowed for this caller".
  To switch delegated creation off for a caller, set `,`. Keycloak may drop an attribute set to an empty string,
  which would bring back the `.mil` default.
- A configured value replaces the default. Keep `.mil` in it if you still want it.
- `kcstig.py apply` does not touch realm attributes, so the value survives re-runs.

Set it on the realm (every caller):
```bash
kcadm.sh update realms/<realm> -s 'attributes."stig.accounts.email-domains"=".mil,example.org"'
```
or on one calling client:
```bash
kcadm.sh update clients/<client uuid> -r <realm> -s 'attributes."stig.accounts.email-domains"="example.org"'
```
Check it with `kcadm.sh get realms/<realm> --fields attributes`. Refusals are logged as `STIG-ACCOUNTS-REFUSED`
and name the domain list in force.

