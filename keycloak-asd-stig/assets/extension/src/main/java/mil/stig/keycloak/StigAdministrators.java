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
     *  realm (the operator's tooling, break-glass) can write it; absent = not enforced for that realm. */
    static final String ALLOWLIST_ATTR_PREFIX = "stig.admin-allowlist.";

    /** The realm's allowlisted administrator ids, or null when the realm does not enforce an allowlist. */
    static java.util.Set<String> allowlist(org.keycloak.models.KeycloakSession session, RealmModel realm) {
        RealmModel master = session.realms().getRealmByName(org.keycloak.Config.getAdminRealm());
        if (master == null || master.getId().equals(realm.getId())) return null;
        String v = master.getAttribute(ALLOWLIST_ATTR_PREFIX + realm.getName());
        if (v == null) return null;
        java.util.Set<String> out = new java.util.HashSet<>();
        for (String id : v.split(",")) if (!id.isBlank()) out.add(id.trim());
        return out;
    }

    /** An administrator (any realm-management role, by any route) who is NOT on the realm's allowlist. */
    static boolean unvettedAdministrator(org.keycloak.models.KeycloakSession session, RealmModel realm, UserModel user) {
        if (user == null || !isAdministrator(realm, user)) return false;
        java.util.Set<String> al = allowlist(session, realm);
        return al != null && !al.contains(user.getId());
    }

    /** An enrolled OTP or two-factor WebAuthn credential. */
    static boolean hasSecondFactor(UserModel user) {
        return user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)
                || user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_TWOFACTOR);
    }
}
