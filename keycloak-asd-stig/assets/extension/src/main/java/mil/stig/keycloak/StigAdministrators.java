package mil.stig.keycloak;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/** Who counts as an administrator, and whether an administrator already holds a second factor. */
final class StigAdministrators {
    private StigAdministrators() { }
    private static final org.jboss.logging.Logger LOG = org.jboss.logging.Logger.getLogger("mil.stig.audit");

    /** An administrator holds ANY role of the realm's realm-management client, effectively: directly, through a
     *  composite, or through a group. Fine-grained (FGAP v2) delegation alone does not make an administrator. */
    static boolean isAdministrator(RealmModel realm, UserModel user) {
        if (user == null) return false;
        ClientModel rm = realm.getClientByClientId("realm-management");
        return rm != null && rm.getRolesStream().anyMatch(user::hasRole);
    }

    /** A group (with its parents) carrying any realm-management role. */
    static boolean groupCarriesAdmin(RealmModel realm, org.keycloak.models.GroupModel g) {
        ClientModel rm = realm.getClientByClientId("realm-management");
        return g != null && rm != null && rm.getRolesStream().anyMatch(g::hasRole);
    }

    /** Master-realm attribute holding the realm's VETTED administrators (comma-separated user ids). Only the master
     *  realm (the operator's tooling, break-glass) can write it. */
    static final String ALLOWLIST_ATTR_PREFIX = "stig.admin-allowlist.";

    /** Realms that ENFORCE an allowlist whatever the master realm holds (deployment configuration, comma-separated):
     *  for these a missing allowlist refuses every administrator instead of switching the check off. */
    static final java.util.Set<String> ENFORCED_REALMS = enforcedRealms(System.getenv("STIG_ALLOWLIST_ENFORCED_REALMS"));

    static java.util.Set<String> enforcedRealms(String v) {
        java.util.Set<String> out = new java.util.HashSet<>();
        if (v != null) for (String r : v.split(",")) if (!r.isBlank()) out.add(r.trim());
        return out;
    }

    /** The realm's allowlisted administrator ids; an EMPTY set (nobody vetted) when the realm is enforced by
     *  configuration but its allowlist is missing; null when the realm does not enforce an allowlist at all. */
    static java.util.Set<String> allowlist(org.keycloak.models.KeycloakSession session, RealmModel realm) {
        RealmModel master = session.realms().getRealmByName(org.keycloak.Config.getAdminRealm());
        if (master == null || master.getId().equals(realm.getId())) return null;
        String v = master.getAttribute(ALLOWLIST_ATTR_PREFIX + realm.getName());
        if (v == null) return ENFORCED_REALMS.contains(realm.getName()) ? new java.util.HashSet<>() : null;
        java.util.Set<String> out = new java.util.HashSet<>();
        for (String id : v.split(",")) if (!id.isBlank()) out.add(id.trim());
        return out;
    }

    /** Master-realm attribute holding, for each vetted administrator, WHAT WAS GRANTED: {@code <user id>=<item>,<item>;...}
     *  where an item is {@code group:<group id>@<role>+<role>...} - the granted group, by id, with a snapshot of the
     *  realm-management roles it carried when it was granted - or, from the older format, a bare realm-management role
     *  name. Written with the id list, by the same tooling (grant / promote), never by the realm itself, so what an
     *  administrator may hold stays under the master realm's control. */
    static final String ALLOWLIST_ROLES_ATTR_PREFIX = "stig.admin-allowlist-roles.";

    /** Parse the entries; null when the value is absent or malformed in any part (callers fail closed). */
    static java.util.Map<String, java.util.Set<String>> parseEntries(String v) {
        if (v == null || v.isBlank()) return null;
        java.util.Map<String, java.util.Set<String>> out = new java.util.HashMap<>();
        for (String e : v.split(";", -1)) {
            int i = e.indexOf('=');
            if (i <= 0 || e.indexOf('=', i + 1) >= 0) return null;
            String id = e.substring(0, i).trim();
            if (id.isEmpty() || out.containsKey(id)) return null;
            java.util.Set<String> roles = new java.util.HashSet<>();
            for (String r : e.substring(i + 1).split(",", -1)) {
                if (r.isBlank()) return null;
                roles.add(r.trim());
            }
            out.put(id, roles);
        }
        return out;
    }

    /** Where an administrator stands against its entry. */
    enum Standing { VETTED, NOT_LISTED, OVER_ENTRY, NEEDS_REGRANT }

    /**
     * Classify an administrator's EFFECTIVE realm-management roles against its entry's items:
     *  - within the snapshots of what was granted: VETTED (unless a granted group no longer exists: NEEDS_REGRANT);
     *  - beyond the snapshots, but only by roles its granted groups carry NOW (a composite or a group changed after the
     *    grant, e.g. by an upgrade): NEEDS_REGRANT - refused, and the operator re-runs grant to accept the change;
     *  - beyond what its granted groups carry even now (a role reached outside the grant): OVER_ENTRY;
     *  - no entry, or an item that cannot be read: NOT_LISTED (fail closed).
     * {@code live} gives a granted group's realm-management roles now, or null when the group id no longer exists.
     */
    static Standing classify(java.util.Set<String> effective, java.util.Collection<String> items,
                             java.util.function.Function<String, java.util.Set<String>> live) {
        if (items == null || items.isEmpty()) return Standing.NOT_LISTED;
        java.util.Set<String> snap = new java.util.HashSet<>(), now = new java.util.HashSet<>();
        boolean missing = false;
        for (String it : items) {
            if (it.startsWith("group:")) {
                String rest = it.substring(6);
                int at = rest.indexOf('@');
                if (at <= 0 || rest.indexOf('@', at + 1) >= 0) return Standing.NOT_LISTED;
                for (String r : rest.substring(at + 1).split("\\+")) if (!r.isBlank()) snap.add(r.trim());
                java.util.Set<String> l = live.apply(rest.substring(0, at));
                if (l == null) missing = true; else now.addAll(l);
            } else if (it.indexOf(':') >= 0 || it.indexOf('@') >= 0 || it.indexOf('+') >= 0) {
                return Standing.NOT_LISTED;                      // an item this gate does not know: fail closed
            } else {
                snap.add(it); now.add(it);                        // the older format: an expanded role name
            }
        }
        java.util.Set<String> extra = new java.util.HashSet<>(effective);
        extra.removeAll(snap);
        if (extra.isEmpty()) return missing ? Standing.NEEDS_REGRANT : Standing.VETTED;
        return now.containsAll(extra) ? Standing.NEEDS_REGRANT : Standing.OVER_ENTRY;
    }

    /** A granted group's realm-management roles now (its own, its parents', composites expanded); null if the id is gone. */
    static java.util.Set<String> groupRoles(org.keycloak.models.KeycloakSession session, RealmModel realm, String groupId) {
        ClientModel rm = realm.getClientByClientId("realm-management");
        org.keycloak.models.GroupModel g = session.groups().getGroupById(realm, groupId);
        if (g == null || rm == null) return null;
        java.util.Set<String> out = new java.util.HashSet<>();
        rm.getRolesStream().filter(g::hasRole).forEach(r -> out.add(r.getName()));
        return out;
    }

    static Standing standing(org.keycloak.models.KeycloakSession session, RealmModel realm, UserModel user) {
        if (user == null || !isAdministrator(realm, user)) return Standing.VETTED;
        java.util.Set<String> al = allowlist(session, realm);
        if (al == null) return Standing.VETTED;                  // this realm does not enforce an allowlist
        if (!al.contains(user.getId())) return Standing.NOT_LISTED;
        RealmModel master = session.realms().getRealmByName(org.keycloak.Config.getAdminRealm());
        java.util.Map<String, java.util.Set<String>> entries = master == null ? null
                : parseEntries(master.getAttribute(ALLOWLIST_ROLES_ATTR_PREFIX + realm.getName()));
        java.util.Set<String> items = entries == null ? null : entries.get(user.getId());
        return classify(effectiveAdminRoles(realm, user), items, gid -> groupRoles(session, realm, gid));
    }

    /** The realm-management roles the user holds EFFECTIVELY: directly, through a composite, or through a group
     *  (and its parents) - the same set the operator's guard computes. */
    static java.util.Set<String> effectiveAdminRoles(RealmModel realm, UserModel user) {
        ClientModel rm = realm.getClientByClientId("realm-management");
        java.util.Set<String> out = new java.util.HashSet<>();
        if (rm != null && user != null) rm.getRolesStream().filter(user::hasRole).forEach(r -> out.add(r.getName()));
        return out;
    }

    /** An administrator (any realm-management role, by any route) who is NOT vetted for what it holds: not on the
     *  realm's allowlist, holding a realm-management role beyond its entry, or needing a re-grant (see classify). Where
     *  the realm enforces an allowlist, an entry or a list that cannot be read counts as no entry (fail closed). */
    static boolean unvettedAdministrator(org.keycloak.models.KeycloakSession session, RealmModel realm, UserModel user) {
        Standing s = standing(session, realm, user);
        if (s == Standing.NEEDS_REGRANT) {
            LOG.errorf("STIG-ADMIN-NEEDS-REGRANT realm=%s user=%s: its granted groups now carry realm-management roles beyond what "
                    + "was vetted (a composite or group changed after the grant), or a granted group is gone - refused until the "
                    + "operator re-runs grant", realm.getName(), user.getUsername());
        }
        return s != Standing.VETTED;
    }

    /** An enrolled OTP or two-factor WebAuthn credential. */
    static boolean hasSecondFactor(UserModel user) {
        return user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)
                || user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_TWOFACTOR);
    }
}
