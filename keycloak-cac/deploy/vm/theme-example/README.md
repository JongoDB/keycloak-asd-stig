# `dod-stig-x509`: an opt-in child theme that relabels the X.509 confirm page

**Optional, and not in the image.** `dod-stig` (baked into keycloak-cac) is unchanged. This child theme fixes one
label on one page, and it is the place to add your own branding (CSS, logo) if you want a branded login.

## What it fixes
After a card is picked, Keycloak's identity confirmation page (`login-x509-info.ftl`, from `base`) shows a row
labelled **Username** whose value is the EDIPI. That row is not in `login-x509-info.ftl`: it is the attempted-username
box from the `username` macro in keycloak.v2's `template.ftl`, labelled `msg("username")`. The X.509 authenticator sets
the attempted username to the identity it extracts from the certificate (the `cac_edipi` value), not to the username.
`username` is shared with the password form and every other page that shows an attempted username, so it cannot be
overridden as a message.

The fix is scoped to that one page:
- `login/login-x509-info.ftl`: a copy of Keycloak 26.8.2 `theme/base/login/login-x509-info.ftl`; one change, it
  imports `template-x509.ftl` instead of `template.ftl`.
- `login/template-x509.ftl`: a copy of Keycloak 26.8.2 `theme/keycloak.v2/login/template.ftl`; one change, the
  `username` macro's label is `msg("x509AttemptedIdentity")`. Nothing else imports it, so every other page keeps the
  stock `template.ftl` and the stock "Username".
- `login/messages/messages_en.properties`: only `x509AttemptedIdentity=EDIPI (from your CAC)`.
- `login/theme.properties`: `parent=dod-stig`, `import=common/keycloak`; nothing else restated.

The certificate row and "You will be logged in as:" (`first.last`) are unchanged, and the confirmation page stays on.

**Removable once the image carries the authenticator fix** tracked in this repository's issue #9 (attempted username
set to the mapped user's username): then the stock row reads a correct "Username: first.last".

## Install
1. Copy this directory to `/opt/keycloak/themes/dod-stig-x509` beside `/opt/keycloak/themes/dod-stig`, either by a
   read-only bind mount (Compose: `- ./theme-example:/opt/keycloak/themes/dod-stig-x509:ro`) or a `COPY` in a derived
   image. Restart Keycloak (production mode caches themes).
2. In the realm: Realm settings > Themes > Login theme = `dod-stig-x509` (or
   `kcadm.sh update realms/<realm> -s loginTheme=dod-stig-x509`).

## Inheritance
Properties are inherited from the parent chain in Keycloak 26: `styles`, `stylesCommon`, `darkMode`,
`scripts=js/dod-banner.js` and every `kc*Class` entry resolve without being restated, so the DoD banner (CSS + JS,
which gates the login form) and its messages come from `dod-stig` unchanged. **If you add a stylesheet, restate
`styles`** (a child's value replaces the parent's rather than appending) and keep `css/styles.css css/dod-banner.css`
first: `styles=css/styles.css css/dod-banner.css css/<yours>-YYYY-MM-DD.css`.

## Recheck on every Keycloak upgrade
Diff each copy against the new version's file (`theme/base/login/login-x509-info.ftl` and
`theme/keycloak.v2/login/template.ftl` in `lib/lib/main/org.keycloak.keycloak-themes-<version>.jar`) and carry the
upstream changes across, keeping the one changed line in each. A stale copy affects only the X.509 confirm page, but
it can still break that page.

## Tested (Keycloak 26.8.2)
On a throwaway Keycloak 26.8.2 (upstream image, whose themes jar is byte-identical to the one in keycloak-cac
26.8.2) with keycloak-cac's `stig-extensions.jar` and `dod-stig` theme, the `stig-x509-client-username-form`
authenticator, the Custom Attribute Mapper on `cac_edipi`, and a test certificate `CN=DOE.JOHN.Q.1234567890`: under
`dod-stig` the confirm page shows "Username / 1234567890" (the defect reproduced); with the two templates and the
message in place it shows "EDIPI (from your CAC) / 1234567890", the certificate row, and "You will be logged in as:
john.doe". The password form (no card, and after "Ignore") still shows "Username".

## If you add CSS: restart, and give every change a new filename
Measured on Keycloak 26.8.2 with `start --optimized`, production theme cache defaults and `/opt/keycloak/data` on
tmpfs (as the VM compose file runs it):
- **A restart is required.** Keycloak gzips each resource on first request into `data/tmp/kc-gzip-cache/<tag>/` and
  serves that copy to every client that sends `Accept-Encoding: gzip` (every browser), without checking the source
  file's mtime. A restart empties the tmpfs and the next request re-encodes the new file.
- **Never replace the theme directory itself while Keycloak runs.** A bind mount holds the directory, not the path:
  `rm -rf` plus `mv` leaves the container on the deleted directory until restart. Sync into the existing directory
  (`rsync -a --delete`).
- **The `/resources/<tag>/` segment does not change** on a theme change or a restart (it changes only on a Keycloak
  version upgrade), and CSS is served with `Cache-Control: max-age=2592000` (30 days) and no `ETag` /
  `Last-Modified`. So give every CSS change a new dated filename (`css/<yours>-YYYY-MM-DD.css` plus the `styles=`
  entry): a new filename is a new URL, which no browser has cached.
- **Do not touch the banner gate** (`html.dod-banner-pending ... {visibility:hidden}`) or the banner JS: the login
  card must stay hidden until the DoD notice is acknowledged (V-222434).
