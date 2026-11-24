# idp-admin.py: account and client administration on a keycloak-cac VM

`host/idp-admin.py` is the operator's command-line tool for a keycloak-cac IdP that runs on one VM under Compose. It
runs on the VM as root and talks to Keycloak from inside the Keycloak container's network namespace (127.0.0.1:8443,
certificate verified for the public host name), as the `stig-automation` service account. `add-client` and
`check-clients` can also run from the operator's workstation over ssh (`--host`). It never prints a secret, except
`client-secret`, which is meant to be piped straight into a secret store.

`idp-admin.py --help` lists every command. In outline:

| Area | Commands |
|---|---|
| Accounts | `invite`, `user-create-cac`, `user-create-pw`, `rename`, `set-password`, `send-setup`, `user-enable`, `user-unlock`, `user-logout`, `user-delete`, `reset-user`, `link-entra`, `entra-amr`, `card-accounts` |
| Administrators | `grant`, `promote`, `revoke`, `allowlist`, `guard [--fix]` (the allowlist gate, containment, alerts) |
| Delegated administration (FGAP v2) | `roles-setup [--retire-app]`, `delegate-setup`, `delegate-client-setup`, `delegate-test-twin`, `delegation-rollback`, `onboarding-client-setup` |
| Clients | `add-client`, `check-clients`, `client-secret`, `client-delete`, `role-delete`, `inheritance-statement` |
| Hand-off intake | `handoff-worker-setup [--rotate-secret]`, `handoffs [list]`, `handoffs done\|refused <id> [--note ...]` |
| Realm | `entra [--endpoint v1\|v2]`, `entra-mfa [--show]`, `smtp`, `cert-check` |

## Per-deployment configuration

Everything that differs between deployments lives in one JSON file, never in the script:
`/srv/idp/config/idp-admin.json` (root, 0600), or the file `$IDP_ADMIN_CONFIG` names. Commands that talk to Keycloak
refuse to run without it, and unknown keys are refused like a typo. Start from
[`host/idp-admin.example.json`](host/idp-admin.example.json).

| Key | Meaning |
|---|---|
| `applications.<client>` | an application with a delegated role-group tree `/<client>/<ROLE>` (one group per client role, made by `roles-setup`) |
| `applications.<client>.userManagerRole` | the client role every holder of `/roles/<client>-user-manager` must also hold; omit for no per-application manager |
| `applications.<client>.adoptable` | `add-client --adopt` may take this pre-existing, file-managed client under add-client |
| `applications.<client>.delegations.<delegate>.groups` | the role groups that delegate's service account may write membership of. A group nobody lists (the bare tree root, a role added later) stays the user managers' alone |
| `applications.<client>.delegations.<delegate>.membershipOnly` | the delegate holds no realm-management role; `delegate-setup <delegate>` creates and converges it |
| `applications.<client>.delegations.<delegate>.name` | display name of that delegate's client (optional) |
| `applications.<client>.preSplitDelegates` | the delegates that existed before the per-group split; `delegation-rollback` keeps only these |
| `onboarding.defaultApps` | the trees `onboarding-client-setup` records when no `--app` is given |
| `onboarding.clientIds` | onboarding clients besides `idp-onboarding`, one per application page (a client has exactly one redirect and origin): `onboarding-client-setup --client-id <id> --redirect-uri <that page's callback> --app <its tree>`. Each is built, recorded and guarded exactly like `idp-onboarding` (drift disables that client alone); `tests/onboarding_live_check.py --client-id <id>` checks one. Never a built-in, an application, a delegate, the hand-off worker or an application's `<app>-user-manager` name; and `onboarding-client-setup` refuses an existing client add-client manages (`stig.created-by=add-client`) or a host client file declares |
| `entra.memberDomain`, `entra.displayName` | the one UPN domain whose tenant members may sign in through Entra (required by `entra`, or `--member-domain`), and the button label |
| `entra.mfaTrustedTenants` | tenant ids (GUIDs) whose own MFA counts as an administrator's second factor after an Entra sign-in; `entra-mfa` applies it, `guard` reports drift (`STIG-IDP-MFA-DRIFT`). Absent or `[]`: never (every administrator needs an enrolled second factor or the card) |
| `smtp.host`, `smtp.port`, `smtp.from`, `smtp.displayName` | defaults for `smtp` (each is otherwise a required option) |
| `handoffIntake.url` | an application's hand-off intake API (optional section): `GET <url>/handoffs?status=open`, `POST <url>/handoffs/<id>/outcome`. One plain https URL on a DNS name |
| `handoffIntake.clientId` | the confidential client whose client-credentials token the intake accepts (`azp`); `handoff-worker-setup` creates it |
| `handoffIntake.audience` | what the intake requires in `aud` (an audience mapper inside the scope below) |
| `handoffIntake.scope` | what the intake requires in `scope`: an optional client scope of that name, the worker's only scope |
| `handoffIntake.app` | the filing application (one of `applications`): `handoffs` suggests a command only for a member of its tree |
| `handoffIntake.name` | display name of the worker client (optional) |
| `operatorSshHost` | only used in the hints the tool prints (`ssh <host> 'sudo ...'`) |
| `repoClientsDir` | with `add-client/check-clients --repo R`, the client files are `R/<repoClientsDir>/` (default `clients`) |

After changing `applications`, run `idp-admin.py roles-setup`. To retire an application, delete it from the config,
then `roles-setup --retire-app <client>`: a plain `roles-setup` refuses while the removed application's delegation is
still live, because its former managers would keep their write power.

## entra-mfa: a tenant's MFA as an administrator's second factor

After an Entra sign-in, an administrator (any realm-management role) must give an enrolled TOTP, and one with none is
refused on the second-factor page - unless `entra-mfa` trusts the tenant and **that sign-in's** validated ID token says
Entra performed MFA (`amr` contains `mfa`). Off until configured.

- `idp-admin.py entra-mfa` applies `entra.mfaTrustedTenants` from the config; `--show` prints the live setting and any
  drift and changes nothing; `--off` trusts no tenant; `--trust-tenant <tid>` (repeatable) is for a lab.
- It moves an earlier post-broker shape (a condition on a stored `entra_amr`, or older) to the current one in place,
  in an order that is never weaker and never leaves the sub-flow absent; removes the retired `amr evidence` mapper and
  clears any stored `entra_amr`; and verifies the WHOLE result by re-reading (shape, every requirement, the condition's
  whole configuration). `entra` re-runs keep the trusted tenants as they are.
- `guard` reports any difference as `STIG-IDP-MFA-DRIFT` (exit 2): a sub-flow or execution not CONDITIONAL / REQUIRED,
  `accept-amr` other than `mfa`, any `accept-acr`, another alias, tenants other than the config's, the old mapper, a
  stored `entra_amr`. `guard --fix` only narrows: requirements restored, the configuration reset to the live tenants
  the config also trusts (never one added), the mapper removed, `entra_amr` cleared.
- Fails closed: another tenant or provider, a guest, no `amr` or a malformed one, an `acr` alone, no config - the
  second factor is still required. Non-administrators, password users and card users are not affected.
- Evidence per sign-in, never stored on the user: the audit line `STIG-ADMIN-SECOND-FACTOR-IDP-MFA accepted|refused
  ... reason=... amr=[...]` and the event details `stig_idp_mfa*`, which `idp-admin.py entra-amr <user>` lists.
- Entra's v2.0 ID token carries `amr` only when the app registration requests it as an optional claim. When that
  cannot be changed, `entra --endpoint v1` brokers Entra's v1.0 endpoints, whose ID tokens always carry `amr` (and the
  UPN as `upn`; the mappers and the member filter follow). A re-run keeps the live endpoint; `--endpoint v2` goes back.

`invite --entra-oid` (not an administrator) creates the account with the terms only - no password, no TOTP, no
set-up e-mail - as stig-accounts' Entra invites: the person signs in with Microsoft Entra.

## link-cac: a card for an existing account

`link-cac` binds a CAC to an account that already exists (it signs in with a password and OTP, or through Entra). The
default proves possession: the operator only *requests* the card, and the person binds it by presenting it.

```bash
sudo idp-admin.py link-cac jane.doe                      # the card jane.doe presents at the next sign-in is bound
sudo idp-admin.py link-cac jane.doe --edipi              # ... only the card whose EDIPI you type at the prompt
sudo idp-admin.py link-cac jane.doe --cancel             # withdraw a pending request
sudo idp-admin.py link-cac --cancel-all                  # withdraw EVERY pending request (the realm-wide stop)
sudo idp-admin.py link-cac jane.doe --bind-edipi --confirm-direct-bind   # only if they cannot present a card
```

- **Possession (the default).** The account gets a link request (`stig_card_link`, the time of the request) and the
  required action `stig-present-card` (stig-extensions' present-card step, the same step that binds the card an Entra +
  CAC invite names). At the next sign-in the person is asked to present their CAC. The card is validated exactly as a
  card sign-in validates it, and its identity is read with the realm's own X.509 mapping. It is bound only if no other
  account holds it or has it reserved, and only if the account does not already hold a different card. A refusal or a
  bind settles the request either way. Both are logged (`STIG-CARD-PRESENT-BOUND` / `-REFUSED request=link`, card
  masked) and recorded as an admin event. The person may continue without the card. They are then asked again at each
  sign-in for 7 days from the request, after which it is ignored. `guard` reports an expired request
  (`STIG-CARD-LINK-EXPIRED`, exit 2) and lists live ones as information.
- **`--edipi`** reserves one card (`cac_edipi_pending`, as an invite does): only a card with that EDIPI binds, and no
  other request or `stig-accounts` create may name it meanwhile. Use it when you have read the EDIPI from the card
  holder. A typo then binds nothing, rather than someone else's card.
- **`--bind-edipi --confirm-direct-bind`** sets `cac_edipi` now, with nobody presenting the card. Use it only when the
  person cannot sign in or cannot present a card, and only after you have verified the card and its holder yourself.
  It is never allowed on an IdP administrator.
- **The EDIPI is typed, never passed as an argument.** `sudo` writes the command line to the auth log, and the shell
  keeps it in its history. `--edipi` and `--bind-edipi` therefore take no value: the number is typed twice at a prompt
  that does not show it, or read as one line on stdin. A number on the command line is refused without being repeated.
  The EDIPI must be exactly 10 digits. It is only ever printed or logged masked (`******7890`).
- **Refused, and nothing changed:**
  - no such account, a disabled account, or a client's service account;
  - an account that already has a card, or carries an invite's pending card, unless you pass `--replace`, which removes
    that card and ends the account's sessions;
  - an EDIPI bound to, or reserved for, another account;
  - for the possession modes, an account with no password and no Entra binding (it could never sign in to present a
    card: `send-setup` first), a browser flow whose X.509 step does not map cards by `cac_edipi`, or a user profile
    that does not declare the request (run `roles-setup`, which declares `stig_card_link` admin-only).
- **IdP administrators.** These are refused unless you pass `--allow-admin`, and even then only with `--edipi`: an
  administrator gets only the card you verified, and only when its holder presents it. A direct bind is never
  allowed. A card on an administrator is its strongest sign-in path, so a typo or a pretext must never be enough to
  attach one. A card bound by presentation is not "set by the operator's tooling" in `binding_provenance` (Keycloak
  records the person, not the tool, as the writer), so a later `promote` of that account refuses it until it is
  reviewed (`--clear-bindings` removes it). That outcome is deliberate.
  The extension enforces the same rule itself, whoever wrote the request: an "any card" request on an account that
  is an IdP administrator (any effective realm-management role, or a member of `/roles` or a group beneath it) is
  refused at the sign-in, before the page is shown, and again at bind time. It is cleared and audited. `link-cac`
  records `<ms> admin` when the account was an administrator at the request, so an account demoted since then still
  gets a named card only.
- **Who can write the request.** `stig_card_link` is declared admin-only with `cac-identity-guard`, so through the
  admin API only a realm administrator (`realm-admin`) or a master-realm administrator may set it. Delegates and user
  managers cannot, and neither can the onboarding client, whose admin-API profile allows only the `stig-accounts`
  calls and group membership. `stig-accounts` never writes it, the person's own account API refuses it (read-only),
  and it is concealed from delegates. The extension ignores a link request while the user profile does not guard
  the attribute this way (`STIG-CARD-LINK-UNGUARDED`; run `roles-setup`).
- **Audit.** Each attempt (requested, bound, cancelled, refused, or failed) writes one `STIG-LINK-CAC` line to the
  system log (facility auth, tag `idp-admin`): `user`, `mode` (present / reserve / bind / cancel), `card` (masked,
  `any`, `invalid`, or `-`), `replace`, `allow_admin`, `operator`, `result`, and `reason` for a refusal.
- **`card-accounts off`** no longer disables the present-card step. The step acts only on an account that has a live
  request, and `link-cac` needs it whether card accounts are on or off. `link-cac` registers and enables the step if
  it has to. To stop every link request at once, run `link-cac --cancel-all`. It writes one audit line per account
  and one for the run.
- **Credentials, not a session.** An "any card" request binds only in a sign-in where the person entered their
  credentials (password + OTP, or the identity provider). A sign-in that reuses an existing SSO session (Keycloak's
  cookie) skips the step: the request stays, and is logged as `STIG-CARD-PRESENT-NEEDS-SIGNIN`. Otherwise someone
  holding an unlocked browser could bind their own card. A named card (`--edipi`) cannot be satisfied by anyone but
  its holder, so it may be presented either way.
- **No full EDIPI in the admin events.** Keycloak stores the request body of a user update in its admin event, so a
  `PUT` carrying `cac_edipi` writes the full number into the event store.
  - The tooling writes bindings server-side through stig-extensions' `stig-bindings` endpoint (realm administrators
    only; its event shows the card masked). This covers `cac_edipi`, `cac_edipi_pending`, `stig_card_link` and
    `entra_oid`, and the removal of `stig_created_by`. It is used by `link-cac`, `user-create-cac`, `invite --edipi`
    / `--entra-oid`, `link-entra`, `reset-user --clear-bindings` and the operator reset at promotion.
  - Every other user update (`rename`, `user-enable`, `set-password`, the factor reset, the guard's disable) goes
    through the same endpoint's `profile` write: username, e-mail, names, the two flags and the required actions,
    with the attributes untouched. A `PUT` that sends no attributes is not enough: the lab showed that Keycloak's admin
    event for it still holds every attribute.
  - On an image without the endpoint (404), the pre-existing commands fall back to the former `PUT`, with a warning.
    `link-cac` refuses instead. Any other refusal fails closed, with one exception: the guard's containment disable.
    If the endpoint refuses that, a `PUT` of exactly `{"enabled": false}` still lands.
  - Two cases remain: `user-create-cac` still takes the EDIPI as an argument (so `sudo` logs it), and admin events
    written before this change keep what they stored.
  - `binding_provenance` reads the masked `stig-bindings` events: a card the operator bound counts as the
    operator's; one its holder presented does not.
- **One card, one account, also at the same moment.** The endpoint and the present-card step both claim the card
  (the same claim key `stig-accounts` uses) before checking and binding it, so two writers cannot bind one card to
  two accounts.
- **Hand-offs.** A `link_cac` hand-off suggests `link-cac <username>` when the account passes the usual hand-off checks.
  If the account already has a card, the suggestion carries a CAUTION about `--replace`.

Tests: `python3 tests/link_cac_unit_test.py` (fake Keycloak, offline). The extension's request rules are tested in
`PendingInviteLinkTest`, which `build.sh` runs.

## Hand-off intake

An application can file requests for the IdP team - link a card or an Entra identity, reset someone's sign-in,
disable, re-enable or unlock an account, change a name or e-mail, delete an account, consider disabling one - and
expose them at an intake API. `handoffs` reads the open ones, oldest first, and prints the `idp-admin.py` command(s)
suggested for each kind (with the username only; anything in `<>` is the operator's to fill in from what they verify
themselves). **Nothing is ever run automatically**: the operator runs the command, then records the outcome with
`handoffs done <id> [--note ...]` or `handoffs refused <id> --note <why>`. Each outcome (recorded, refused by the
intake, or failed) is one `STIG-HANDOFF-OUTCOME` line in the system log (facility auth, tag `idp-admin`).

- **The worker client** (`handoff-worker-setup`): confidential, client credentials only, its service account holding no
  role of any kind (the realm's default roles removed) and in no group, `fullScopeAllowed` off, no default client scope,
  and exactly one OPTIONAL client scope (`handoffIntake.scope`, in the token's `scope`) carrying exactly one audience
  mapper (`handoffIntake.audience`). Its access token lives 300 s. A token therefore carries exactly
  `aud=[audience]`, `scope=scope` and `azp=clientId` (plus `sub`, the service account's id); asking for any other
  scope is refused by Keycloak (`invalid_scope`). Its shape is recorded in `/srv/idp/state/handoff-worker.json`: `guard`
  reports drift (`STIG-HANDOFF-WORKER-DRIFT`, exit 2) and with `--fix` disables the worker; `check-clients` reports it
  too. A save of the client in the admin console makes Keycloak add the `service_account` default scope back, which
  is drift: re-run `handoff-worker-setup` after touching the client by hand. The secret is written to
  `/srv/idp/secrets/handoff_client_secret` (root, 0600); `--rotate-secret` replaces it and the old one stops working.
- **A wrong or compromised intake cannot steer the operator.** `handoffs` looks each username up in Keycloak and
  prints the account's state next to the hand-off (enabled, card bound, Entra bound, application trees, application
  roles held effectively - never the card number or the object id). It suggests NO command, with a WARNING, when the
  account does not exist, is an IdP administrator (`/roles` or a `/roles/*` group, or any effective realm-management
  role), or is not a member of the filing application's tree (`handoffIntake.app`); for `consider_disable`, filed after
  the last role was removed, when the account still holds any application's group or role (direct, composite or
  through a group). A whole-account action (`delete_account`, `reset_credentials`, `disable_enable_unlock`) on an
  account another application also uses keeps its command under a CAUTION. If Keycloak cannot be asked, no command is
  suggested at all.
- **Each request** (`handoffs`): the token comes from the realm's public token endpoint and is checked before use
  (issuer, `azp`, `aud` and `scope` exactly, at most 600 s, no `iat` in the future); the intake is reached over https
  only, its host resolved once and every address public, no redirect followed, 20 s and 1 MiB at most; anything the
  intake returns is printed with control characters removed, and a username a shell command cannot carry gets no
  command line. A note is at most 200 characters, printable, and never holds a run of ten or more digits (checked before
  anything is sent).

The validator `add-client` applies is the relying-party skill's own
[`validate-client-request.py`](../../../keycloak-rp-integration/scripts/validate-client-request.py), unmodified: used
from this checkout when the tool runs from it, else the copy installed in `/usr/local/lib/idp/` (or `$IDP_VCR`).

## Tests

Offline (fake Keycloak, no root, run from a checkout; they load `tests/fixtures/idp-admin.test.json`):

```bash
cd keycloak-cac/deploy/vm
python3 tests/add_client_unit_test.py --kcstig ../../../keycloak-asd-stig
python3 tests/split_delegation_unit_test.py
python3 tests/guard_contain_unit_test.py
python3 tests/rename_unit_test.py
python3 tests/app_admin_enroll_unit_test.py
python3 tests/config_unit_test.py
python3 tests/invite_entra_unit_test.py
python3 tests/entra_mfa_unit_test.py        # tenant-MFA flow: migration never weaker, drift, guard --fix narrows
python3 tests/handoff_unit_test.py          # hand-off intake against a mock intake (needs openssl)
```

Lab (a throwaway keycloak-cac container in lab mode: mock PKI, dev-file database, the host's path filter; Docker
only):

```bash
fgap/onboarding_lab.sh <keycloak-cac image> <this checkout> [report] [onboarding_lab_test.py|multiapp_lab_test.py|
                       entra_autolink_lab_test.py|create_shapes_lab_test.py|delegate_jwt_lab_test.py]
```

`fgap/split_delegation_test.py lab` runs against a plain Keycloak started by hand (see its docstring), and
`fgap/app_admin_fgap.py` sets up and tests an application's own administrator service account.

The remaining `tests/*` (`accounts_endpoint_test.py`, `factor_promotion_test.py`, `grant_extent_test.py`,
`onboarding_live_check.py`, `create_shapes_live_check.py`, `idp_admin_users_test.py`, `admin_console_e2e.py`,
`invite_e2e.py`, `cleanup_test_fixtures.py`) are live checks: they run on the VM as root against the deployed IdP and
clean up after themselves.
