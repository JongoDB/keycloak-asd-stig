# What to send your IdP operator, and what comes back

The operator runs the STIG-hardened Keycloak. They register your client from one file, `client-request.json`,
with the IdP skill's `kcstig.py add-client`. That command imports `scripts/validate-client-request.py` (the same
rules, not a copy), so validate before sending and the request registers on the first try. The operator section at
the end describes their side.

## Send

1. **`client-request.json`**, validated:
   ```bash
   python3 scripts/validate-client-request.py client-request.json            # must print "valid"
   python3 scripts/validate-client-request.py --strict client-request.json   # no placeholder hosts, nothing to explain
   ```
   Fields (schema: `assets/client-request.schema.json`; example: `assets/client-request.example.json`):

   | Field | Example | Notes |
   |---|---|---|
   | `client_id` | `myapp-web` | Lowercase letters, digits and hyphens. Use `-dev` / `-test` suffixes per environment. Keycloak's own ids are refused (see below) |
   | `name` | `My App` | Optional display name |
   | `root_url` | `https://myapp.example.mil` | The app's public base URL; same as `APP_BASE_URL` |
   | `redirect_uris` | `["https://myapp.example.mil/oauth2/callback"]` | Exact. No `*`, no fragments |
   | `post_logout_redirect_uris` | `["https://myapp.example.mil/logged-out"]` | Your logged-off page |
   | `backchannel_logout_url` | `https://myapp.example.mil/oauth2/backchannel-logout` | Must be reachable **from the IdP** |
   | `auth` | `client-jwt` | Or `client-secret` |
   | `jwks_url` | `https://myapp.example.mil/.well-known/jwks.json` | `client-jwt` only; reachable from the IdP |
   | `roles` | `["viewer", "editor", "approver"]` | Client roles to create; lowercase, e.g. `report-approver` |
   | `privileged` | `true` | Only for an admin front end: the IdP applies the 10-minute admin idle timeout |
   | `web_origins` | `["https://myapp.example.mil"]` | Only if browser JavaScript calls the IdP directly (rare with a BFF) |
   | `contact` | `{"name", "email", "organization", "phone"}` | Who the operator talks to about this client |
   | `dev_request` | `true` | Development registrations only: allows the host name `localhost` |
   | `notes` | free text | Anything the operator should know (split DNS, a proxy in front of the JWKS, and so on) |

   Every field except `contact`, `dev_request`, `notes` and `$schema` has the same name and meaning as the
   operator's client file (`keycloak-asd-stig/references/profile.md`, `clients[]`).
   `validate-client-request.py --emit-client -` prints exactly what the operator will register.

   **Reserved client ids.** `account`, `account-console`, `admin-cli`, `broker`, `realm-management`,
   `security-admin-console` and any id ending in `-realm` belong to Keycloak itself. Both this validator and the
   operator's `add-client` refuse them. `add-client` also refuses to modify a client it did not create, so an id that
   collides with an existing hand-made client is rejected. Pick a new, app-specific id.

   Every URL must use a **DNS name**. IP addresses are refused in every spelling, because certificates, redirects
   and audit trails are bound to names. Hosts must be ASCII: write internationalized names in punycode (`xn--...`).
   Unicode look-alikes, such as `ſ` for `s` or the Kelvin sign for `k`, are refused rather than normalized. `localhost` is accepted only in a request marked `"dev_request": true`,
   which the operator registers in a non-production realm.

2. **Who needs which role**: a list of people (or the group or process that approves access) for each role.
   Send it the way your organization handles access requests, not inside the request file. The operator, or your
   account-management process, assigns roles in the IdP.

3. **Network facts the operator needs**: which egress path the IdP uses to reach your `jwks_url` and
   `backchannel_logout_url`, and the CA that issues your app's certificate, if the IdP does not already trust it.

4. **The STIG split you are claiming** (optional, but it speeds up the ATO conversation): which rules you will
   mark as inherited (`stig-inheritance.md`). Ask the operator to confirm against their realm.

## The operator's side (for the IdP team)

Treat the file you received as untrusted input, even from a known team. Check **the file you received**, not the
one they say they sent:

```bash
python3 keycloak-rp-integration/scripts/validate-client-request.py --strict client-request.json   # read every line
python3 keycloak-rp-integration/scripts/validate-client-request.py client-request.json --emit-client -   # what will be registered
# a new client
python3 keycloak-asd-stig/scripts/kcstig.py add-client client-request.json --profile profile.json \
    --clients-dir clients.d --owner <owner id> [--secret-out /secure/path/<client_id>.secret]
# a change to an existing client (after step 2 below)
python3 keycloak-asd-stig/scripts/kcstig.py add-client client-request.json --profile profile.json \
    --clients-dir clients.d --owner <owner id> --update <client_id> [--prune-roles]
```

**Registering a new client**

1. Validate the received file with `--strict`, as above, and read every `WARNING` and `NOTE`.
2. Assign an owner id (`--owner`, for example the team or system name in your inventory). Without one, the
   request's contact email becomes the owner. The id is recorded on the client (`stig.owner`, with the contact in
   `stig.owner-contact`) and in `clients.d/<client_id>.json`.
3. Run `add-client`. A new client needs nothing more.

**Changing an existing client**

1. Look up the recorded owner and contact: the client attributes `stig.owner` and `stig.owner-contact`, or
   `clients.d/<client_id>.json`.
2. **Confirm the change with that recorded contact through a second channel** (a phone call, or a ticket raised by
   that team), not by replying to whoever sent the file. A change request that only arrived by email or chat is not
   confirmed. A copied contact email in the request proves nothing.
3. Rerun with `--update <client_id>` and the same `--owner`. `add-client` prints a before/after diff of
   `redirect_uris`, `post_logout_redirect_uris`, `backchannel_logout_url`, `jwks_url`, the auth method and the
   roles. Check the redirect and logout URLs in particular: they decide where users and tokens are sent.
4. Roles the request no longer lists are kept unless you add `--prune-roles`.
5. A request from a different owner is refused even with `--update`. If ownership really moves, confirm with both
   the old and the new contact, then add `--transfer`.

What `add-client` enforces (run it from a checkout of this repository; it finds the validator in
`keycloak-rp-integration/` beside the IdP skill, or at `--validator` / `KCSTIG_RP_VALIDATOR`, and an explicit path
that doesn't exist is an error):

- Validator **errors and warnings** both refuse the request by default (wildcard-DNS services such as nip.io,
  single-label hosts, URLs on another origin, placeholder domains). `--no-strict` overrides warnings, for when you
  have checked each one. A `dev_request` also needs `--allow-dev` (non-production realms only).
- Reserved ids (`account`, `account-console`, `admin-cli`, `broker`, `realm-management`, `security-admin-console`,
  `*-realm`) are refused. `kcstig.py apply`, `render` and `verify` also refuse a profile or clients.d file that
  defines one.
- An existing client needs `--update`. Changing another owner's client also needs `--transfer`. A client that
  `add-client` did not create (no `stig.created-by=add-client`) also needs `--adopt <client_id>`, with a warning.
- An id that another clients.d file or the profile defines, or a `clients.d/<client_id>.json` with no live client
  behind it, is someone else's configuration and is refused (`--adopt` overrides it).
- It applies the client through the admin API (idempotent) and writes `clients.d/<client_id>.json`, owner
  included, so later `apply` runs keep it.
- With `client-secret`, it writes the secret only to `--secret-out` (created 0600, never printed). Deliver it as
  described below, then delete that file.

## Receive

| Item | How | Use it as |
|---|---|---|
| Issuer URL | any channel; it isn't secret | `OIDC_ISSUER`, e.g. `https://idp.example.mil/realms/<realm>` |
| IdP CA bundle | any channel; verify its fingerprint with the operator by a second channel | the app's trust store for the IdP (`OIDC_CA_FILE` and the language equivalents) |
| Realm limits | any channel | Idle, admin idle and max lifespan: configure the app to be equal or stricter |
| Client secret (`client-secret` only) | **out of band**, see below | a file mounted into the app (`OIDC_CLIENT_SECRET_FILE`) |
| IdP checklist + `kcstig.py inherit` output for your client | any channel | ATO evidence for the inherited rules |
| Test accounts or cards for the dev realm | per your organization | the app's own end-to-end tests |

## Receiving a client secret safely

A client secret is a password for your application. Treat it like one:

- **Never** by chat, email, ticket comment, wiki page, screenshot or verbal read-out, and never in this request.
  These channels are logged, searchable and forwarded.
- Use the channel your organization approves for secrets. In order of preference:
  1. The operator writes it straight into the secret store your platform reads (Vault path, cloud secret manager,
     Kubernetes Secret in your namespace) and grants your workload read access. Nobody handles it in between.
  2. A one-time, expiring secret share your organization approves, or an encrypted file (for example `age`, or
     S/MIME with a CAC-backed certificate) addressed to the named contact. The passphrase or link goes by a
     **different** channel.
- On receipt: put it in the secret store, mount it as a file with mode 0400, set `OIDC_CLIENT_SECRET_FILE`, and
  delete every intermediate copy (downloads, decrypted files, clipboard history).
- Never commit it. Add a pre-commit or CI secret scan if the repo doesn't have one.
- If it may have been exposed, ask the operator to **regenerate** it at once. The old value stops working when they
  do, so arrange the switch-over together.
- `client-jwt` avoids all of this: the private key is generated and stays on your side, and only the public half
  (the JWKS URL) goes in the request. Prefer it.

## After registration

1. Configure the app with the issuer, client ID, CA bundle and the key or secret file.
2. Log in as a test user with each role; check the 403 path, log off, back-channel logout (ask the operator to
   sign the test user out at the IdP) and the idle timeout. `tests/e2e/run_e2e.py` shows these checks in code.
3. Any change (new redirect URI, new role, key move) is a new, validated `client-request.json` with the same
   `client_id`, from the same contact. The operator confirms it with you through a second channel before applying
   it with `--update`, so expect that call. Roles you drop from the request are kept unless you ask the operator to
   prune them.
