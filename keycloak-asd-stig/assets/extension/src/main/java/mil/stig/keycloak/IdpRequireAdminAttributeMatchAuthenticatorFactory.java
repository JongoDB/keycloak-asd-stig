package mil.stig.keycloak;

import java.util.List;

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
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Post-broker-login step: EVERY sign-in through an identity provider - through a new or an existing link - must come
 * from the configured provider alias and tenant and vouch for the identity the account's administrator-set attribute
 * names (AdminBoundIdentity). A link someone else made (a delegate through the admin API; the user through the account
 * console - Keycloak lets manage-account link accounts even without manage-account-links) signs nobody in. Fails
 * closed: unconfigured, a mapper writing the administrator-set attribute, another provider or tenant, nothing
 * vouched, or no administrator-set value - each is a refusal.
 */
public class IdpRequireAdminAttributeMatchAuthenticatorFactory implements Authenticator, AuthenticatorFactory {

    public static final String ID = "idp-require-admin-attribute-match";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        AuthenticationSessionModel as = context.getAuthenticationSession();
        SerializedBrokeredIdentityContext s = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                as, AdminSecondFactorRequiredAuthenticatorFactory.BROKERED);
        AdminBoundIdentity id = AdminBoundIdentity.of(context);
        String why, idp = "?";
        if (s == null || user == null) {
            why = "not a brokered sign-in";
        } else if (StigAdministrators.unvettedAdministrator(context.getSession(), context.getRealm(), user)) {
            why = "holds administrator rights it is not vetted for (not on the allowlist, or beyond its entry) (STIG-ADMIN-NOT-ALLOWLISTED)";
        } else {
            BrokeredIdentityContext b = s.deserialize(context.getSession(), as);
            idp = b.getIdpConfig() == null ? null : b.getIdpConfig().getAlias();
            why = AdminBoundIdentity.refusal(id.cfg(), idp, AdminBoundIdentity.first(b, id.oidAttr), AdminBoundIdentity.first(b, id.tidAttr),
                    user.getFirstAttribute(id.adminAttr), AdminBoundIdentity.mapperTargets(context));
        }
        if (why == null) {
            context.success();
            return;
        }
        LOG.warnf("STIG-IDP-LINK-MISMATCH realm=%s user=%s idp=%s: %s - sign-in refused", context.getRealm().getName(),
                user == null ? "?" : user.getUsername(), idp, why);
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
    @Override public boolean isConfigurable() { return true; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Post broker login: refuses a brokered sign-in (even through an existing link) unless the IdP vouches for the account's admin-set entra_oid.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return AdminBoundIdentity.properties(); }
}
