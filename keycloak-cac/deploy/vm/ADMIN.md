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
| Realm | `entra`, `smtp`, `cert-check` |

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
| `entra.memberDomain`, `entra.displayName` | the one UPN domain whose tenant members may sign in through Entra (required by `entra`, or `--member-domain`), and the button label |
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
  prints the account's state next to the hand-off (enabled, card bound, Entra bound, application trees - never the card
  number or the object id). It suggests NO command, with a WARNING, when the account does not exist, is an IdP
  administrator (a `/roles/*` group or any effective realm-management role), or is not a member of the filing
  application's tree (`handoffIntake.app`); for `consider_disable`, filed after the last role was removed, when the
  account still holds any application tree's group. If Keycloak cannot be asked, no command is suggested at all.
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
