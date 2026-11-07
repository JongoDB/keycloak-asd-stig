# Migrating an app from the v1 toolkit to the keycloak-cac image (prompt)

Paste this into a session that paused its Keycloak work with a `NOTES-keycloak-v2.md` note:

```
Migrate this app's CAC login to the v2 keycloak-cac image from JongoDB/keycloak-asd-stig (add the repo to this
session if needed; read keycloak-cac/README.md and keycloak-asd-stig/SKILL.md step 0).

1. Read NOTES-keycloak-v2.md in this repo: it lists the client ID, redirect/logout URIs, the pattern (native OIDC
   or oauth2-proxy gateway), the files touched and the Keycloak settings the app relied on.
2. Replace the v1 deployment pieces (keycloak-stig + kcstig-tools images, pki-init / pki-refresh / apply job
   containers, profile.json, runtime.env) with the single keycloak-cac service:
   - the same realm name -> CAC_REALM, public URL -> CAC_PUBLIC_URL
   - users/admins from the old profile -> CAC_USERS / CAC_ADMINS (or *_JSON / *_DIR for full records)
   - the app's client -> one JSON file in CAC_CLIENTS_DIR (same client_id, URIs, roles)
   - other profile fields that differ from the STIG defaults -> CAC_PROFILE_JSON
   - secrets as *_FILE; CAC_AUTOMATION_SECRET reuses the old stig-automation secret if the database is kept
3. If the existing database is kept, set CAC_AUTOMATION_SECRET to the old automation secret so the container
   can log in after the bootstrap admin is gone. Otherwise start on a fresh database.
4. Keep the app side unchanged unless the issuer URL changes (it is <CAC_PUBLIC_URL>/realms/<CAC_REALM>).
5. Test in lab mode (compose.lab.yaml pattern, CAC_LAB_MODE=true, mock cards) with the skill's e2e_check.py,
   then run kcstig.py verify. Report what changed, what was removed, and the test results.
Do not merge to the main branch until I review.
```
