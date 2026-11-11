package mil.stig.keycloak;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/** Who counts as an administrator, and whether an administrator already holds a second factor. */
final class StigAdministrators {
    private StigAdministrators() { }

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
     *  where an item is {@code group:<group path>} (e.g. group:/roles/idp-admin) or {@code role:<realm-management role>}
     *  (a bare name is read as a role). What an item permits is expanded when the check runs - the group's roles (with
     *  its parents) or the role's composites, recursively - so a role added to realm-admin, or to a granted /roles group,
     *  never makes a vetted administrator "over its entry"; only a role reached outside the grant does. Written with
     *  the id list, by the same tooling (grant / promote), never by the realm itself. */
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

    /** The realm-management role names an entry's granted items permit NOW; null if any item cannot be resolved
     *  (an unknown group or role: fail closed). */
    static java.util.Set<String> permitted(org.keycloak.models.KeycloakSession session, RealmModel realm, java.util.Set<String> items) {
        ClientModel rm = realm.getClientByClientId("realm-management");
        if (rm == null || items == null) return null;
        java.util.Set<String> out = new java.util.HashSet<>();
        for (String it : items) {
            if (it.startsWith("group:")) {
                org.keycloak.models.GroupModel g = org.keycloak.models.utils.KeycloakModelUtils.findGroupByPath(session, realm, it.substring(6));
                if (g == null) return null;
                rm.getRolesStream().filter(g::hasRole).forEach(r -> out.add(r.getName()));
            } else {
                org.keycloak.models.RoleModel granted = rm.getRole(it.startsWith("role:") ? it.substring(5) : it);
                if (granted == null) return null;
                rm.getRolesStream().filter(granted::hasRole).forEach(r -> out.add(r.getName()));
            }
        }
        return out;
    }

    /** True when the user holds an effective realm-management role its entry does not permit, or there is no entry. */
    static boolean exceedsEntry(java.util.Set<String> effective, java.util.Set<String> entry) {
        return entry == null || !entry.containsAll(effective);
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
     *  realm's allowlist, or holding a realm-management role beyond what its entry's grants permit now. Where the realm
     *  enforces an allowlist, an entry, a grant or a list that cannot be read counts as no entry (fail closed). */
    static boolean unvettedAdministrator(org.keycloak.models.KeycloakSession session, RealmModel realm, UserModel user) {
        if (user == null || !isAdministrator(realm, user)) return false;
        java.util.Set<String> al = allowlist(session, realm);
        if (al == null) return false;
        if (!al.contains(user.getId())) return true;
        RealmModel master = session.realms().getRealmByName(org.keycloak.Config.getAdminRealm());
        java.util.Map<String, java.util.Set<String>> entries = master == null ? null
                : parseEntries(master.getAttribute(ALLOWLIST_ROLES_ATTR_PREFIX + realm.getName()));
        java.util.Set<String> items = entries == null ? null : entries.get(user.getId());
        return exceedsEntry(effectiveAdminRoles(realm, user), items == null ? null : permitted(session, realm, items));
    }

    /** An enrolled OTP or two-factor WebAuthn credential. */
    static boolean hasSecondFactor(UserModel user) {
        return user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)
                || user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_TWOFACTOR);
    }
}
