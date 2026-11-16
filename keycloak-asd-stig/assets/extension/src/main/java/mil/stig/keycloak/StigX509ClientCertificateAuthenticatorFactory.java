package mil.stig.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** "X509/Validate Username Form" with the same configuration, except that password lockout never refuses a card. */
public class StigX509ClientCertificateAuthenticatorFactory extends X509ClientCertificateAuthenticatorFactory {
    public static final String PROVIDER_ID = "stig-x509-client-username-form";
    @Override public Authenticator create(KeycloakSession session) { return new StigX509ClientCertificateAuthenticator(isLegacyCriticalBehavior()); }
    @Override public String getId() { return PROVIDER_ID; }
    /** Re-reads and verifies changed CRL files off the request path (IssuerCrlCheck). */
    @Override public void postInit(KeycloakSessionFactory factory) { super.postInit(factory); IssuerCrlCheck.startPrewarm(factory); }
    @Override public void close() { IssuerCrlCheck.stopPrewarm(); super.close(); }
    @Override public String getDisplayType() { return "X509/Validate Username Form (card not locked by password failures)"; }
    @Override public String getHelpText() {
        return "Keycloak's X509/Validate Username Form, except that password-failure lockout does not refuse a valid, unrevoked card.";
    }
}
