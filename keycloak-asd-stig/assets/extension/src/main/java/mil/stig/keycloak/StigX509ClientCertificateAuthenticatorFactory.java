package mil.stig.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

/** "X509/Validate Username Form" with the same configuration, except that password lockout never refuses a card. */
public class StigX509ClientCertificateAuthenticatorFactory extends X509ClientCertificateAuthenticatorFactory {
    public static final String PROVIDER_ID = "stig-x509-client-username-form";
    @Override public Authenticator create(KeycloakSession session) { return new StigX509ClientCertificateAuthenticator(isLegacyCriticalBehavior()); }
    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "X509/Validate Username Form (card not locked by password failures)"; }
    @Override public String getHelpText() {
        return "Keycloak's X509/Validate Username Form, except that password-failure lockout does not refuse a valid, unrevoked card.";
    }
}
