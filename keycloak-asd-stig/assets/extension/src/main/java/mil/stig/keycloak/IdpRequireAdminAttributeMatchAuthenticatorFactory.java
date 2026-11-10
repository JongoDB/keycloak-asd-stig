package mil.stig.keycloak;

import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Post-broker-login step: EVERY sign-in through an identity provider - including through an identity-provider link
 * that already exists - must carry the identity the account's administrator-set attribute names (default "entra_oid",
 * compared with the attribute an IdP mapper copies from the token's "oid" claim, or with that claim directly). A link
 * that someone else made (a delegate through the admin API, the user through the account console - Keycloak lets
 * manage-account link accounts even without manage-account-links) therefore never signs anyone in: the sign-in is
 * refused unless the identity provider vouches for the identity an administrator recorded. Fails closed: no
 * attribute on the account, or nothing vouched, is a refusal.
 */
public class IdpRequireAdminAttributeMatchAuthenticatorFactory implements Authenticator, AuthenticatorFactory {

    public static final String ID = "idp-require-admin-attribute-match";
    static final String ATTR = IdpLinkByAdminAttributeAuthenticatorFactory.ATTR;   // entra_oid
    static final String CLAIM = "oid";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        AuthenticationSessionModel as = context.getAuthenticationSession();
        SerializedBrokeredIdentityContext s = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                as, AdminSecondFactorRequiredAuthenticatorFactory.BROKERED);
        String held = user == null ? null : user.getFirstAttribute(ATTR);
        String vouched = null, idp = "?";
        if (s != null) {
            BrokeredIdentityContext b = s.deserialize(context.getSession(), as);
            idp = b.getIdpConfig() != null ? b.getIdpConfig().getAlias() : "?";
            vouched = b.getUserAttribute(ATTR);
            if (vouched == null || vouched.isBlank()) {
                Object tok = b.getContextData().get("VALIDATED_ID_TOKEN");
                if (tok instanceof JsonWebToken jwt) {
                    Map<String, Object> other = jwt.getOtherClaims();
                    Object v = other == null ? null : other.get(CLAIM);
                    vouched = v == null ? null : String.valueOf(v);
                }
            }
        }
        if (held != null && !held.isBlank() && held.equals(vouched)) {
            context.success();
            return;
        }
        LOG.warnf("STIG-IDP-LINK-MISMATCH realm=%s user=%s idp=%s: the identity provider vouched for %s, the account's "
                + "administrator-set %s is %s - sign-in refused (a link nobody authorised)", context.getRealm().getName(),
                user == null ? "?" : user.getUsername(), idp, vouched == null ? "nothing" : "another identity", ATTR,
                held == null ? "unset" : "set");
        context.getEvent().user(user).error(Errors.ACCESS_DENIED);
        Response page = context.form().setError(Messages.ACCESS_DENIED).createErrorPage(Response.Status.FORBIDDEN);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, page);
    }

    @Override public void action(AuthenticationFlowContext context) { authenticate(context); }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }

    @Override public Authenticator create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Identity provider must vouch for the admin-set entra_oid"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Post broker login: refuses a brokered sign-in (even through an existing link) unless the IdP vouches for the account's admin-set entra_oid.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
