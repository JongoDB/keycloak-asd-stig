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

    /** An enrolled OTP or two-factor WebAuthn credential. */
    static boolean hasSecondFactor(UserModel user) {
        return user.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)
                || user.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_TWOFACTOR);
    }
}
