package mil.stig.keycloak;

import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;

/**
 * ASD STIG V-222544 (APSC-DV-001760): enforce a 24 hour minimum password lifetime.
 *
 * Policy id: minimumPasswordAge, value = hours (default 24).
 *
 * The rule only applies to a user changing their own password. It deliberately does not
 * block:
 *  - administrator resets through the Admin REST API / console (no authentication session),
 *    which is the approved unlock / recovery path (V-222433);
 *  - a user completing a forced UPDATE_PASSWORD required action, e.g. after an admin-issued
 *    temporary password (V-222547 requires an immediate change to a permanent password).
 */
public class MinimumPasswordAgePolicyProviderFactory implements PasswordPolicyProviderFactory {

    public static final String ID = "minimumPasswordAge";

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new Provider(session);
    }

    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayName() { return "Minimum Password Age (hours) [STIG]"; }
    @Override public String getConfigType() { return PasswordPolicyProvider.INT_CONFIG_TYPE; }
    @Override public String getDefaultConfigValue() { return "24"; }
    @Override public boolean isMultiplSupported() { return false; }

    static final class Provider implements PasswordPolicyProvider {
        private final KeycloakSession session;

        Provider(KeycloakSession session) { this.session = session; }

        @Override
        public PolicyError validate(RealmModel realm, UserModel user, String password) {
            Integer hours = realm.getPasswordPolicy().getPolicyConfig(ID);
            if (hours == null || hours <= 0 || user == null) return null;

            // Admin REST / console reset: no authentication session in context.
            if (session.getContext() == null || session.getContext().getAuthenticationSession() == null) return null;

            // Forced change (temporary password, admin-required update): must be allowed.
            if (user.getRequiredActionsStream().anyMatch(a -> UserModel.RequiredAction.UPDATE_PASSWORD.name().equals(a))) return null;
            if (session.getContext().getAuthenticationSession().getRequiredActions().contains(UserModel.RequiredAction.UPDATE_PASSWORD.name())) {
                // Required action added for this login only (e.g. password expired). Expired => older than min age anyway,
                // but an admin-forced action also lands here; allow it.
                return null;
            }

            Long created = user.credentialManager()
                    .getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                    .map(CredentialModel::getCreatedDate)
                    .filter(d -> d != null)
                    .max(Long::compare)
                    .orElse(null);
            if (created == null) return null; // first password

            long ageMs = System.currentTimeMillis() - created;
            if (ageMs < hours * 3600_000L) {
                return new PolicyError("invalidPasswordMinAgeMessage", hours);
            }
            return null;
        }

        @Override
        public PolicyError validate(String user, String password) { return null; }

        @Override
        public Object parseConfig(String value) {
            return parseInteger(value, 24);
        }

        @Override public void close() { }
    }
}
