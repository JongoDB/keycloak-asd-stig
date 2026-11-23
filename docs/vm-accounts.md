# Shared IdP on a VM: managing accounts

The how-to for people who add, change and remove accounts on a shared keycloak-cac identity provider run on one VM
with the host kit in `keycloak-cac/deploy/vm/` and its operator CLI, `idp-admin.py`. Where this page and
`idp-admin.py --help` disagree, the script wins. Please fix this page.

The names are examples: the realm is `example`, the IdP is `idp.example.mil`, the operator's SSH alias is `idp-host`,
and three applications are registered: `app-a` (with its own role catalogue, delegated administration and a portal),
and `app-b` / `app-c` (simple four-role apps). Which applications exist, each one's user-manager role, which delegate
may write which role groups, the Entra member domain and the SMTP defaults all come from the operator's config file,
`/srv/idp/config/idp-admin.json` (`IDP_ADMIN_CONFIG` overrides the path; example:
`keycloak-cac/deploy/vm/host/idp-admin.example.json`). Changing them is a config change and a `roles-setup`, never an
edit to the script.

| | |
|---|---|
| Sign-in for every app | `https://idp.example.mil/realms/example` |
| Admin console | `https://idp.example.mil/admin/example/console/` |
| Operator shell | `ssh idp-host` (key `~/.ssh/idp-host`, operator IP only), then `sudo idp-admin.py <command>` |
| Event log | `ssh idp-host 'sudo idp-events 30'` (the last 30 minutes) |

Every command below runs on the IdP VM as `sudo idp-admin.py ...`. From the operator's workstation, wrap it:
`ssh idp-host 'sudo idp-admin.py <command>'`. Without SSH, your cloud's run-command facility runs the same command (the host
README's break-glass section).

**One account per person.** The username is `first.last`, in lower case. An account can have any mix of three
sign-in methods: a CAC/PIV card, a password plus TOTP, and a Microsoft Entra (example.mil) link. A password alone
never signs anyone in.

**Admin is a role, not an account.** Every right on this page comes from group membership. No one gets a second
"admin" account.

---

## 1. The roles

### Who is who

| Who | How they hold it | Where they work |
|---|---|---|
| **Operator** | SSH to `idp-host` plus `sudo`, or run-command rights on the VM's resource group. `idp-admin.py` then acts as the master realm's `stig-automation` service account | `idp-admin.py` on the VM |
| **IdP administrator** | group `/roles/idp-admin` (realm-management `realm-admin`) | admin console, or ask the operator |
| **User manager** | group `/roles/idp-user-manager` | admin console (memberships only), `stig-accounts` API |
| **app-a user manager** (every app-a admin) | group `/roles/app-a-user-manager`, granted by the operator together with `app-a:administrator` | app-a's portal account page, with their own token (`idp-onboarding`); app-a's groups only |
| **Auditor** | group `/roles/idp-auditor` | admin console, read only |
| **app-a's Admin screen** | service account `app-a-admin` | app-a's own Admin screen, at `https://app-a.example.mil` |
| **app-a reader delegate** | service account `app-a-reader-delegate` | app-a's own screens, for a partner lead: `partner-reader` membership of existing app-a members only |
| **Break-glass** | master realm | the VM only, in an emergency |

Keep the operator and IdP administrators few. `sudo idp-admin.py allowlist` lists every vetted
administrator.

### Operator (`idp-admin.py` on the VM)

- **Can do:** everything on this page. It is the only route for the steps that need the most care: mapping a card
  (`user-create-cac`, `invite --edipi`), linking Entra (`link-entra`), making someone an administrator, user manager
  or auditor (`grant`, `promote`, `revoke`), re-enabling after the guard has disabled someone (`reset-user`), and
  registering an application (`add-client`).
- **Cannot do:** nothing is off limits. That is why access to the VM is the real control. Treat a shell on
  `idp-host` as full control of every account.

### IdP administrator (`/roles/idp-admin`)

- **Can do:** full administration of the `example` realm in the console. It is the only role (besides the operator)
  that can see or set a card mapping (`cac_edipi`) or an Entra binding (`entra_oid`). It can enable, disable, delete,
  reset credentials, map roles directly and edit anyone.
- **Must not do in the console:** make someone an administrator. A promotion done in the console is refused at once,
  and the next guard run (every 10 minutes) demotes, resets and disables that account and mails an alert. Use
  `idp-admin.py grant`.
- **Must not do in the console:** change a client (an application's settings). The next Keycloak restart puts the
  client file back. See recipe h.
- **Sign-in rule:** an administrator must use a card, or a password plus a TOTP that is already enrolled. An
  administrator with a password and no TOTP is refused after the password, as if the password were wrong. No TOTP
  set-up page is offered. Sign in by card, then enrol TOTP if you want it.

### User manager (`/roles/idp-user-manager`)

- **Can do, in the console:** see the members of the application role groups (`/app-b/*`,
  `/app-c/*`, `/app-a/*`) and move them between those groups. That is how roles are given and
  taken away.
- **Can do, through the `stig-accounts` API only:** create an account in one application role group (the person gets
  a set-up e-mail), re-send that e-mail, and disable an account. There is no screen for this.
- **The console refuses account creation to a user manager. This is by design.** "Add user" fails for them. Creating
  goes through `stig-accounts`, which allows only `first.last`, an address at `.mil` or `example.mil`, one
  application group, and 20 accounts per hour.
- **Cannot do:** edit anyone, change an e-mail, set or reset a password, touch credentials or Entra links, send
  set-up mail from the console, delete, re-enable, see or set a card mapping, touch `/roles/*` or any role mapping,
  or see or touch anyone outside the application groups. It can never see or touch an administrator.
- **Practical upshot:** a user manager cannot add a CAC holder by card. Ask the operator.

`stig-accounts`, for a script that holds a user manager's token (contract: `keycloak-asd-stig/references/operations.md` section 8):

```
B=https://idp.example.mil/admin/realms/example/stig-accounts
curl -sS -X POST "$B/users" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"<first.last>","email":"<address>","firstName":"<First>","lastName":"<Last>","group":"/<client>/<ROLE>"}'
curl -sS -X POST "$B/users/<user id>/setup-email" -H "Authorization: Bearer $TOKEN"   # re-send (not within 15 min)
curl -sS -X POST "$B/users/<user id>/disable"     -H "Authorization: Bearer $TOKEN"
```

If you do not have such a script, ask the operator to run `invite` (recipe c).

### app-a user manager (`/roles/app-a-user-manager`)

- **Who:** every app-a admin. **Being `administrator` in app-a means the operator also grants this role** (recipe g). It is
  never given automatically from app-a's `administrator` group, because app-a's own service account can write that group.
- **Can do, from app-a's portal, signed in as themselves:** what a user manager can do, but only inside
  `/app-a/*`: create an account in one app-a role group (`partner-lead`, `partner-auditor` and `contractor`
  included), re-send its set-up e-mail, disable, and move people between app-a role groups. Every change needs a sign-in
  in the last 5 minutes; the page asks again when it is older.
- **Cannot do:** anything a user manager cannot (above), nor anything in another application's groups, nor the bare
  `/app-a` group. Card (EDIPI) and Entra binding, password and TOTP resets, re-enabling and deleting stay with
  the operator and IdP admins.
- The guard reports (`STIG-APP-MANAGER-MISALIGNED`, mailed) anyone holding this role without `app-a:administrator`.
  Nothing is changed automatically: fix it with `grant` or `revoke`.

### Auditor (`/roles/idp-auditor`)

- **Can do:** read users, groups and events (sign-ins and admin changes) in the console.
- **Cannot do:** change anything. Card mappings and Entra bindings are hidden, including inside admin events.

### app-a's Admin screen (`app-a-admin`)

- app-a users with `administrator` use it through app-a's own Admin screen. It acts through this service account.
- **Can do:** list the members of the `/app-a` role groups, and move a member between the 6 app-a role
  groups. That changes their app-a role. It can also move members into and out of `partner-reader`. It can never give `partner-lead`,
  `partner-auditor` or `contractor`, and cannot put anyone in the bare `/app-a` group.
- **Cannot do:** create, invite, disable or re-enable anyone; edit, reset or delete anyone; touch anyone who is not
  already an app-a group member; touch an administrator; give a role in any other app. Every `stig-accounts` call is
  refused to it.
- **It cannot see** people whose app-a role is a direct mapping rather than a group. That includes every
  administrator, and accounts made by `user-create-cac` (recipe a).
- **It signs in with app-a's own key** (client-jwt, ES256, JWKS `https://app-a.example.mil/api/v1/admin-client/jwks`)
  (`idp-admin.py delegate-client-setup app-a-admin --jwks-url ...`); no client secret works for it.

### app-a reader delegate (`app-a-reader-delegate`)

Created with `idp-admin.py delegate-setup app-a-reader-delegate`. It holds no
role. A partner lead acting in app-a can, through it, move existing app-a members into or out of `partner-reader` and
nothing else: no other group, nobody outside `/app-a`, no `stig-accounts` call, no impersonation (`fgap/split_delegation_test.py`). `partner-lead`, `partner-auditor` and `contractor` stay with IdP user managers and administrators. It starts on a
client secret and moves to `client-jwt` with its own JWKS the same way as `app-a-admin`
(`delegate-client-setup app-a-reader-delegate --jwks-url ...`).

The four partner roles (`partner-reader`, `partner-auditor`, `partner-lead`, `contractor`) each have their group
`/app-a/<ROLE>`; the config's `applications.app-a.delegations` says which delegate may write which of them.

**A further step:** a separate `app-a-public` realm for contractors without a CAC (passkeys only):
[`passkey-public-realm.md`](passkey-public-realm.md).

### Break-glass (master realm)

The master realm is not reachable from the network. Its only browser admin is a placeholder no card carries.
`idp-admin.py` reaches it from inside the Keycloak container. If every realm administrator is locked out, follow
the host README's break-glass procedure (the cloud's run-command facility, then the recovery client). Nobody uses it for day-to-day accounts.

---

## 2. The services

| Service (client id) | URL | Roles (group `/<client>/<ROLE>`) | Who can grant a role |
|---|---|---|---|
| `app-b` | `https://app-b.example.mil` | `owner`, `maintainer`, `reviewer`, `member` | operator, IdP admin, user manager; `/roles/app-b-user-manager` holders who also hold `owner` |
| `app-c` | `https://app-c.example.mil` | `lead`, `analyst`, `auditor`, `reader` | operator, IdP admin, user manager; `/roles/app-c-user-manager` holders who also hold `lead` |
| `app-a` | `https://app-a.example.mil` | `viewer`, `editor`, `approver`, `planner`, `observer`, `administrator`, plus `partner-reader`, `partner-auditor`, `partner-lead`, `contractor` | operator, IdP admin, user manager. The application's own administrator delegate moves existing members between the six application roles and into or out of `partner-reader`; a membership-only reader delegate writes `partner-reader` alone. `partner-auditor`, `partner-lead` and `contractor` are granted only by the operator, IdP admins and user managers. (Which delegate writes which group is the config's `applications.<app>.delegations`.) |

How a role reaches the app:

- Each group `/<client>/<ROLE>` carries exactly one client role. A member of the group holds that role.
- Administrators hold app roles by **direct mapping** instead, never through a group. `grant` does this for you.
  `user-create-cac` also maps directly.
- The app reads the roles from the token, at `resource_access.<client id>.roles`. **A change shows at the person's
  next sign-in.** To make it happen now, end their session: `sudo idp-admin.py user-logout <first.last>`.
- **app-b** creates its own account at the first sign-in and re-reads the roles at every sign-in. No role for that
  client means sign-in is refused (`no_role`). (How an application treats a first sign-in, a missing role or an existing
  local account of the same name is the application's own business.)
- **An application behind an access proxy** (for example Cloudflare Access) also needs the person let through there.
  That is set in the proxy, not in Keycloak.
- **app-a** reads `resource_access.app-a.roles` and keys each person on their IdP user id (`sub`).

---

## 3. Recipes

Placeholders: `<first.last>` the username, `<EDIPI>` ten digits, `<client>` a client id from the table above,
`<ROLE>` one of its roles, `<address>` an e-mail address.

### a. Add a CAC holder so they can test card sign-in

**1. Get the EDIPI.** It is the 10 digits at the end of the card certificate's common name (CN). A CN looks like
`DOE.JANE.Q.1234567890`, so the EDIPI is `1234567890`. Three ways to get it:

- **Ask the person.** With the card inserted: on macOS, Keychain Access shows the card's certificates, named by CN.
  On Windows, `certmgr.msc` → Personal → Certificates. Any of the card's identity certificates has the same CN.
- **Let them try first.** Send them to the app URL and have them sign in with the card. It fails, because no account
  has their EDIPI yet. Then read the event log:
  ```
  ssh idp-host 'sudo idp-events 15'
  ```
  Look for `error="user_not_found"` with `username="<EDIPI>"`. The line also carries the certificate subject. That
  means "a valid card, but no account is mapped to it".
- **A screenshot of their error page** may show the subject, too. The event log is the dependable source.

**2. Pick the username and the role.** Use `first.last` in lower case. Pick one `<client>:<ROLE>` from section 2.

**3. Create the account** (operator):

```
ssh idp-host 'sudo idp-admin.py user-create-cac <first.last> <EDIPI> <address> <First> <Last> <client>:<ROLE>'
```

Example: `user-create-cac jane.doe 1234567890 jane.doe@example.mil Jane Doe app-a:viewer`.
It prints `created: jane.doe (cac_edipi verified, no identity-provider link), role app-a:viewer`.

What this gives the person: a card-only account. No password, no TOTP, no e-mail is sent. The role is a direct
mapping.

**4. Tell the person** to open the app URL and choose to sign in. Here is what they will see:

1. The app sends them to `idp.example.mil`.
2. The **DoD Notice and Consent banner**. They must accept it before the sign-in form works.
3. The browser asks them to **choose a certificate**. They pick the card's.
4. The card middleware asks for their **PIN**.
5. Keycloak checks the certificate. The chain must lead to a DoD root, and revocation is checked against the DoD
   **CRL and OCSP**. OCSP fails closed: if DISA's OCSP responder is down, card sign-in fails until it is back.
6. Keycloak maps the EDIPI to the account and sends them back to the app with the role.
7. **Previous logon:** the first sign-in has none. From the second sign-in on, the app shows the date and time of the
   last one (if it displays it).

If the account has pending set-up steps (it will not, from `user-create-cac`), Keycloak asks for them right after
the card.

**5. Verify:**

```
ssh idp-host 'sudo idp-events 15'
```

Look for a `type="LOGIN"` line with `clientId="<client>"` and `username="<first.last>"`. Any `*_ERROR` line names the
cause; an `ERROR` line just before a certificate failure gives the PKI reason. Also confirm in the app that the role
is right.

**When to use `invite --edipi` instead:**

| Use | When |
|---|---|
| `user-create-cac` | card only; a quick test; nobody but the operator or an IdP admin needs to change the role later |
| `invite --edipi` | the person also needs a password + TOTP fallback, **or** the role should be managed later by a user manager or app-a's Admin screen (invite puts them in the role group) |

```
ssh idp-host 'sudo idp-admin.py invite <first.last> --email <address> --groups <client>:<ROLE> --edipi <EDIPI>'
```

This also e-mails a set-up link (accept the terms, set a password of 15+ characters, enrol TOTP). It works once and
expires in 12 hours (`--lifespan <seconds>`, at most 86400). If they sign in by card before using the link, Keycloak
asks for the same steps after the card.

**Common errors:**

| Message | Meaning and fix |
|---|---|
| `EDIPI must be the 10 digits at the end of the card's CN` | a typo, or you pasted the whole CN |
| `REFUSED: EDIPI already mapped to another account (<name>)` | one card, one account. Use that account (recipe d), or have an IdP admin clear the mapping from the wrong account |
| `REFUSED: <name> exists (same EDIPI, no links); re-run with --existing to add the role to it` | the account is already this card holder's. Re-run the same command with `--existing` to add the role |
| `REFUSED: <name> exists with a different or no EDIPI` | the username is taken by someone else, or by an account with no card. Pick another username, or see recipe d |
| `user_not_found` in `idp-events` after you created it | the EDIPI on the account differs from the card. Compare the digits |
| no certificate prompt at all | Chrome remembered an earlier choice. See Gotchas |
| card refused, other people's cards fine | look at the `ERROR` line in `idp-events`: often revocation (OCSP/CRL) or an expired certificate |

### b. Add a Microsoft Entra (example.mil) user

Only **members** of your Entra tenant with a UPN in the configured member domain (here `@example.mil`) can use Entra. Guests (`#EXT#`) and other
domains are refused. An Entra sign-in never creates an account. It links only to the account whose `entra_oid` an
administrator set, or - once pending invites are on - to the one Entra-type invite its UPN names (the short way below).

1. **Get their Entra object id:** Entra → Users → the person → Object ID, or
   `az ad user show --id <first.last>@example.mil --query id -o tsv`.
2. **Entra assignment:** nothing to do per person if a staff group is assigned to the broker app (below).
3. **Create the account with the binding** (operator):
   ```
   ssh idp-host 'sudo idp-admin.py invite <first.last> --email <first.last>@example.mil --groups <client>:<ROLE> --entra-oid <object id>'
   ```
   For an account that already exists: `sudo idp-admin.py link-entra <first.last> <object id>`, then give the role
   (recipe d).
4. **The person** opens the app, chooses Microsoft at the IdP, and signs in with their organisation account. The
   tenant's own MFA applies. The invite also mails a set-up link (password + TOTP). Keycloak asks for those steps
   right after the first Microsoft sign-in too, if the link has not been used yet.
5. **Verify:** `sudo idp-events 15` shows an `IDENTITY_PROVIDER_LOGIN` or `LOGIN` for `<first.last>`.
   `sudo idp-admin.py entra-amr <first.last>` shows whether Entra reported MFA.

Administrators get one extra rule: if Entra did not report MFA, Keycloak asks for its own TOTP, and refuses an
administrator who has none.

**The short way (once the pending-invite binding is on: `entra --auto-link-domain example.mil`, on an image with
stig-extensions' pending-invite support): no object id copied anywhere.**

1. Nothing in Entra per person: a staff group is assigned to the broker app (below).
2. A user manager (or an app-a admin on app-a's Invite page) creates the account with **"Signs in with Entra"**: `stig-accounts` `POST /users` with `"signIn": "entra"` and the person's `first.last@example.mil` address.
   No password, no TOTP, no set-up mail; the account is marked pending (`entra_pending`).
3. **The person** signs in with Microsoft. The FIRST Entra sign-in binds their Entra identity to that account when ALL
   hold: Entra's tenant is the configured one; the UPN Entra vouches for (not the e-mail claim) is the account's username or
   e-mail; the account was made through `stig-accounts`, is enabled, has no Entra binding, no password/OTP/passkey and no
   card; and it is at most **7 days** old. Exactly one account may match. Anything else is refused as today.
4. From then on the binding is fixed: a different Entra identity for that account is refused.

`sudo idp-admin.py guard` lists invites still waiting (`ENTRA-INVITE-PENDING`, information) and reports those older than
7 days (`STIG-ENTRA-INVITE-EXPIRED`): they can no longer bind - disable or remove them, or re-invite. A card (EDIPI) is
still bound by the operator only. The manual way above keeps working.

**Entra: who may sign in.** Keep **Assignment required?** on for the broker's enterprise application, so nobody
outside an assigned group gets past Entra (AADSTS50105), and assign one **dynamic** group of enabled staff members to
it (Graph `appRoleAssignedTo`, default role). For example, with your tenant's own naming conventions for separate
administrator and emergency accounts in place of the placeholders:
```
(user.userPrincipalName -notStartsWith "<admin-account-prefix>") and
(user.userPrincipalName -notStartsWith "<emergency-account-prefix>") and
(user.accountEnabled -eq true) and (user.userType -eq "Member")
```
- enabled staff **members** only; separate administrator and emergency accounts and every guest are excluded;
- there is then **no per-person Entra step**: joining the tenant makes someone eligible, leaving it removes them. An
  IdP account still needs an invite (above); an Entra sign-in never creates one.
- Add the optional ID-token claim **acct** to the broker app registration (Token configuration -> + Add optional claim
  -> ID -> acct): it is the guest signal Keycloak requires besides `idp`.
- **Rollback:** Enterprise applications -> the broker app -> **Users and groups** -> remove the group. Then only
  individually assigned users can sign in with Microsoft.

### c. Add a password + TOTP user

**Allowed:** for anyone in the `example` realm who has no card or no Entra account.
**Not allowed:** a password on its own (TOTP is always required); a self-service "Forgot password" (it is off); an
administrator who signs in by password before a TOTP is enrolled. In the coming `app-a-public` realm there will be no
passwords at all (passkeys only).

**The normal way, `invite`** (operator). The person chooses their own password:

```
ssh idp-host 'sudo idp-admin.py invite <first.last> --email <address> --groups <client>:<ROLE>'
```

- The person gets a mail from `noreply@notify.example.mil`. The link works once and expires in 12 hours.
- They accept the terms, set a password of at least 15 characters, and enroll an authenticator app (TOTP).
- After that they sign in at the app with username, password and the 6-digit code.
- Lost or expired link: `sudo idp-admin.py send-setup <first.last>`.
- A user manager can do the same through `stig-accounts` `POST /users` (section 1), for `.mil` and `example.mil`
  addresses only.
- Console equivalent (IdP admin only): Users → Add user → Join groups → Credentials → Send email with Update
  Password, Configure OTP, Terms and Conditions.

**A short-lived test account, `user-create-pw`** (operator). You set the password:

First put the password in a root-only file, `/root/tmp-pw` (mode 0600): at least 15 characters, with upper and
lower case, a digit and a symbol. Then:

```
sudo idp-admin.py user-create-pw <first.last> <address> <First> <Last> <client>:<ROLE> --temp-password-file /root/tmp-pw --temporary
sudo shred -u /root/tmp-pw          # once you have handed the password over safely
```

- The account is marked **temporary and is disabled automatically 72 hours after creation** (STIG V-222409).
- `--temporary` forces a password change at first sign-in. TOTP enrolment follows.
- The role is a direct mapping.

**An existing account that needs a new password:** `sudo idp-admin.py set-password <first.last> > <file>` writes a
temporary password to a file (it refuses to print to a terminal) and requires TOTP. Or re-send the set-up link.

### d. Give an existing person a role in another service

Which command depends on how the account holds its current roles:

| The account | Do this |
|---|---|
| is in a role group (made by `invite`, `stig-accounts` or `grant`) | `sudo idp-admin.py grant <first.last> <client>:<ROLE>`. Or in the console: Groups → `/<client>/<ROLE>` → Members → Add member (IdP admin, or a user manager) |
| is card-only, made by `user-create-cac`, in no group | `sudo idp-admin.py user-create-cac <first.last> <EDIPI> <address> <First> <Last> <client>:<ROLE> --existing` |
| is an administrator, user manager or auditor | `sudo idp-admin.py grant <first.last> <client>:<ROLE>`. It maps the role directly |

`user-create-cac --existing` first proves it is the same person. It refuses unless the account's EDIPI equals
`<EDIPI>`, it has no identity-provider link, no delegate can manage it (it is in no application group), and it has no
password or TOTP. If it has a password or TOTP that you have checked is the person's own, add
`--accept-credentials`.

`grant` on someone who is not an administrator puts them in the group. From then on a user manager (and, for app-a,
app-a's Admin screen) can manage that role, and `user-create-cac --existing` refuses the account.

### e. Move someone between roles

- **Group roles** (most people): add the new group, then leave the old one. In the console: Users → the person →
  Groups → Join group, then select the old group → Leave. An IdP admin or a user manager can do this.
- **app-a's own Admin screen** can move an app-a member from one app-a role to another (and into or
  out of `partner-reader`; never `partner-lead`, `partner-auditor` or `contractor`). It cannot add someone who
  is not already an app-a member, cannot touch an administrator, cannot see a direct-mapped role, and cannot give a
  role in another app.
- **Direct-mapped roles** (administrators, `user-create-cac`, `user-create-pw`): only an IdP admin or the operator.
  Add with `grant <first.last> <client>:<NEW_ROLE>`. Remove in the console: Users → the person → Role mapping →
  select the old role → Unassign.
- Then `sudo idp-admin.py user-logout <first.last>` if the change must apply before their next sign-in.

### f. Remove a role, disable, unlock, reset, log out, delete

| Task | How | Who | Reversible? |
|---|---|---|---|
| **Remove a role** (group) | console: Groups → `/<client>/<ROLE>` → Members → select → Leave | IdP admin, user manager; app-a screen for app-a roles | yes, add it back |
| **Remove a role** (direct mapping) | console: Users → the person → Role mapping → Unassign | IdP admin | yes |
| **Disable** an account | `sudo idp-admin.py user-enable <first.last> false`, or console: Users → the person → Enabled off. User manager: `stig-accounts` `POST /users/<id>/disable` | operator, IdP admin, user manager | yes. Re-enable: operator (`user-enable <first.last> true`) or IdP admin (console), **except an account the guard disabled: run `reset-user <first.last>` first**. A user manager cannot re-enable |
| **Unlock** after wrong passwords | `sudo idp-admin.py user-unlock <first.last>` | operator (IdP admin in the console) | n/a. The lock also expires by itself: 15 minutes, growing to at most 24 hours. Password failures never lock the card |
| **Reset factors** (lost phone, suspected compromise) | `sudo idp-admin.py reset-user <first.last>` | operator | no. It removes every password, TOTP, passkey and Entra link, **clears the e-mail**, and ends sessions. The card mapping and `entra_oid` stay. Then set the address again and `send-setup <first.last>` (see Gotchas, "`reset-user` cleared the e-mail") |
| **Force logout** | `sudo idp-admin.py user-logout <first.last>`, or console: Users → the person → Sessions → Sign out | operator, IdP admin | yes, they just sign in again. Apps with back-channel logout end their session within seconds |
| **Take away admin rights** | `sudo idp-admin.py revoke <first.last>` | operator | yes, `grant` again (with its checks) |
| **Delete** | `sudo idp-admin.py user-delete <first.last>` | operator, IdP admin | **no**. A new account gets a new user id, and apps key people on that id, so applications see a stranger. Prefer disable |

Two things disable accounts automatically: **35 days without a sign-in** (counted from creation or the last sign-in),
and **72 hours** for a temporary account from `user-create-pw`. Re-enable with `user-enable <first.last> true`.

`user-enable ... true` is refused if the guard disabled the account. Read the reason it prints. Then run
`reset-user <first.last>` (or a `grant` that passes its checks) before enabling.

### g. Make someone a user manager, auditor or IdP admin

Operator only. **Never do this in the console.**

```
ssh idp-host 'sudo idp-admin.py grant <first.last> idp-user-manager'    # or idp-auditor, or idp-admin
```

**An app-a admin**: one grant gives both the app-a role and the right to manage app-a's
accounts from the portal. `grant` refuses the manager role unless `administrator` is in the same grant or is
already mapped directly (holding it only through app-a's `administrator` group does not count):

```
ssh idp-host 'sudo idp-admin.py grant <first.last> app-a-user-manager app-a:administrator'
```

The rules `grant` enforces:

- **The allowlist.** Only accounts `grant` or `promote` vetted may hold any admin right
  (`/srv/idp/state/admins.json`, published to Keycloak). Anyone else holding one is refused at sign-in and on the
  admin API, and the guard demotes, resets and disables them within 10 minutes and mails an alert.
- **A strong sign-in first.** The role is granted at once only if the account has a card mapping the operator set,
  or a TOTP nobody else set. Otherwise the result is `PENDING` and a set-up link is mailed. Once the person has
  enrolled TOTP: `sudo idp-admin.py promote <first.last>`.
- **Refused if anyone else touched the account.** Examples: a user manager moved it, a delegate created it
  (`stig-accounts`), or someone else planted a password, TOTP or link. Re-run with `--reset-credentials`; for a
  delegate-created account add `--email <address you have checked>`. The person then re-enrols.
- **A card mapping set in the console does not count.** Only a mapping the operator's tooling set
  (`user-create-cac`, `invite --edipi`) is a strong path for promotion. A mapping set any other way makes `grant` refuse
  unless it is run with `--clear-bindings`, which removes the mapping.
- **Refused** for a service account, and for an account that already holds an admin right nobody vetted
  (`revoke` it first).
- **Out of the application groups.** `grant` moves a new administrator out of every application group and maps those
  app roles directly. app-a's Admin screen and user managers can no longer see them. That is the point.
- **To invite a brand-new administrator:** `invite <first.last> --email <address> --groups idp-auditor` creates the
  account with no group and leaves the promotion pending. After the person enrols TOTP, run `promote <first.last>`.
- **After a Keycloak upgrade** that adds an admin role, administrators are refused (`STIG-ADMIN-NEEDS-REGRANT`) until
  you run `grant <first.last> <role>` again. `sudo idp-admin.py guard` must report no `NEEDS-REGRANT`.
- **To take the right away:** `sudo idp-admin.py revoke <first.last>`.

### h. Onboard a new application

1. The app team follows `keycloak-rp-integration` (in this repository) and sends a validated
   `client-request.json` (`validate-client-request.py --emit-client` turns it into a client file).
2. Save it in your operations repository's clients directory (the config's `repoClientsDir`), with `"owner"` and `"owner_contact"` filled in.
3. From the operator's workstation, in that repository's root:
   ```
   H=<path to>/idp-admin.py; F=<clients dir>/<client_id>.json
   $H add-client $F --owner <team> --owner-contact <their address> --host idp-host --dry-run
   $H add-client $F --owner <team> --owner-contact <their address> --host idp-host --repo . --secret-to <file>
   ```
   Use `--secret-to-keyvault <vault>/<name>` instead of `--secret-to` if you prefer, or nothing for a `client-jwt`
   app. Change an existing client with `--update <client_id>`.
4. Commit the client file through a reviewed change. `$H check-clients --host idp-host --repo .` must say `no drift`.
5. If the app's people should be managed through role groups, add it to the config's `applications` (with its
   user-manager role and any delegations), install the config on the VM, and run `sudo idp-admin.py roles-setup`.
6. The app uses the issuer `https://idp.example.mil/realms/example` and reads roles from
   `resource_access.<client_id>.roles`.

**Never change a client in the console.** Every Keycloak start re-applies the client files and silently undoes it.
A console edit that a restart reverts can take an application's sign-in down.

---

## 4. Who do I ask?

| Task | Operator (VM) | IdP admin (console) | User manager | app-a Admin screen | Auditor |
|---|---|---|---|---|---|
| Add a CAC holder (card mapping) | **yes** | set EDIPI on an existing account | no | no | no |
| Link an Entra account | **yes** | yes (attribute) | no | no | no |
| Invite a password + TOTP user | **yes** | yes | yes (`stig-accounts`) | no | no |
| Give or move an app role (group) | yes | yes | **yes** | app-a roles only | no |
| Give or remove a direct-mapped role | **yes** | yes | no | no | no |
| Disable | yes | yes | yes (`stig-accounts`) | no | no |
| Re-enable | **yes** | yes, except an account the guard disabled: `reset-user` first | no | no | no |
| Unlock, reset factors, force logout | **yes** | yes | no | no | no |
| Delete | **yes** | yes | no | no | no |
| Make someone an admin, user manager (all apps, or one app's) or auditor | **only here** | no | no | no | no |
| Register an application | **only here** | no | no | no | no |
| Read sign-in and admin events | yes (`idp-events`) | yes | no | no | **yes** |

---

## 5. Gotchas

- **The card picker never appears.** Chrome remembered a certificate choice for this site. Open
  `chrome://settings/content/all?searchSubpage=idp.example.mil`, delete the site's data, quit Chrome with ⌘Q, and try
  again. On macOS, also check Keychain Access for an "identity preference" entry for that host.
- **"EDIPI already mapped to another account".** One card, one account. Use the existing account, or have an IdP
  admin remove the mapping from the wrong one. Never create a second account for the same card.
- **An administrator in an application group.** It is not allowed. `grant` and the guard move administrators out of
  application groups and map the roles directly. That is why app-a's Admin screen does not list administrators, and
  why a user manager cannot change their roles.
- **An administrator whose password is "wrong".** An administrator with a password but no TOTP is refused exactly
  like a wrong password. Sign in by card.
- **Someone was made an admin in the console.** It does not work. They are refused at once, and the guard disables
  them and mails an alert. Use `grant`. To release them afterwards: `reset-user <first.last>`, then `grant`.
- **A card is refused for everyone at once.** DISA OCSP may be down (OCSP fails closed). Password + TOTP and Entra
  still work.
- **Locked out after three wrong passwords.** The lock is temporary (15 minutes, growing to 24 hours). The card still
  works. `user-unlock` clears it.
- **An account went disabled by itself.** 35 days without a sign-in, or a 72-hour temporary account. Re-enable it.
- **A role change "did nothing".** Roles reach the app at the next sign-in. Use `user-logout`.
- **The set-up mail never came.** It comes from `noreply@notify.example.mil`; check spam. The link works once and
  expires (12 hours by default). Re-send with `send-setup`. A user manager's re-send is refused within 15 minutes of
  the last one, and once the account is set up.
- **`reset-user` cleared the e-mail.** That is deliberate. Set it again before `send-setup`:
  `sudo idp-admin.py rename <first.last> <first.last> --email <address>` (the same name twice only updates the e-mail
  and names). Or an IdP admin uses the console: Users → the person → Details → Email → Save. Then
  `sudo idp-admin.py send-setup <first.last>`.
- **`user-create-cac --existing` refused.** The account has a password or TOTP (`--accept-credentials` after
  checking), an Entra link, or is in an application group (use `grant`).
- **The application sends the person to an access-proxy login.** An access proxy sits in front of that host. Add
  the person there.
- **Usernames.** `invite` and `stig-accounts` accept only `first.last` in lower case. Keep to that everywhere: a
  username cannot be changed in the console (`rename` keeps the same user id).
