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
| `operatorSshHost` | only used in the hints the tool prints (`ssh <host> 'sudo ...'`) |
| `repoClientsDir` | with `add-client/check-clients --repo R`, the client files are `R/<repoClientsDir>/` (default `clients`) |

After changing `applications`, run `idp-admin.py roles-setup`. To retire an application, delete it from the config,
then `roles-setup --retire-app <client>`: a plain `roles-setup` refuses while the removed application's delegation is
still live, because its former managers would keep their write power.

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
