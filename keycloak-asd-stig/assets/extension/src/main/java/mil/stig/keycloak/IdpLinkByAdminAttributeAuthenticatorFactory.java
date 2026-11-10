package mil.stig.keycloak;

import java.util.List;
import java.util.stream.Collectors;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * First-broker-login step: link the brokered identity ONLY to the one existing account whose admin-set attribute
 * (default "entra_oid") equals the value the identity provider vouches for (an IdP attribute mapper copies, e.g.,
 * Entra's immutable object id claim "oid" into the same attribute name on the brokered identity). No match - or more
 * than one - and the sign-in is refused. Nothing is ever created and nothing is matched by username or e-mail, so a
 * crafted UPN or a reused address cannot land on someone else's account. The attribute itself should be protected
 * with cac-identity-guard (unique, realm administrators only).
 */
public class IdpLinkByAdminAttributeAuthenticatorFactory extends AbstractIdpAuthenticator implements AuthenticatorFactory {

    public static final String ID = "idp-link-by-admin-attribute";
    static final String ATTR = "entra_oid";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serialized,
                                    BrokeredIdentityContext broker) {
        String attr = ATTR;
        String vouched = broker.getUserAttribute(attr);
        if (vouched == null || vouched.isBlank()) {
            refuse(context, broker, "the identity provider sent no " + attr);
            return;
        }
        List<UserModel> found = context.getSession().users()
                .searchForUserByUserAttributeStream(context.getRealm(), attr, vouched).limit(2).collect(Collectors.toList());
        if (found.size() != 1) {
            refuse(context, broker, found.isEmpty() ? "no account carries this " + attr : "more than one account carries this " + attr);
            return;
        }
        UserModel user = found.get(0);
        context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO,
                new ExistingUserInfo(user.getId(), attr, vouched).serialize());
        LOG.infof("STIG-IDP-LINK idp=%s user=%s via %s", broker.getIdpConfig().getAlias(), user.getUsername(), attr);
        context.setUser(user);
        context.success();
    }

    private void refuse(AuthenticationFlowContext context, BrokeredIdentityContext broker, String why) {
        LOG.warnf("STIG-IDP-LINK-REFUSED idp=%s username=%s reason=%s", broker.getIdpConfig().getAlias(), broker.getUsername(), why);
        sendFailureChallenge(context, Response.Status.UNAUTHORIZED, "idpLinkNotAuthorized", why,
                AuthenticationFlowError.UNKNOWN_USER);
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serialized,
                              BrokeredIdentityContext broker) {
        authenticateImpl(context, serialized, broker);
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }

    // ---- factory
    @Override public Authenticator create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Link only by admin-set attribute (entra_oid)"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Links the brokered identity only to the existing account whose admin-set entra_oid equals the IdP's; never creates or matches by name/e-mail.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
