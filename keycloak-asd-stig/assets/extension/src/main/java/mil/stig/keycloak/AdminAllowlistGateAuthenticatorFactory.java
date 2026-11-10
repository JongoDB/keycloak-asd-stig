package mil.stig.keycloak;

import java.util.List;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

/**
 * After ANY way of signing in to the browser flow - an existing SSO cookie included - refuse an account that holds
 * administrator rights (any realm-management role, by any route) but is not on the realm's allowlist (a master-realm
 * attribute only the operator's tooling writes). An administrator made in the console, not by the tooling, therefore
 * cannot sign in as one at all - not even with a session it already had.
 */
public class AdminAllowlistGateAuthenticatorFactory implements Authenticator, AuthenticatorFactory {
    public static final String ID = "stig-admin-allowlist-gate";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel u = context.getUser();
        if (!StigAdministrators.unvettedAdministrator(context.getSession(), context.getRealm(), u)) {
            context.success();
            return;
        }
        LOG.errorf("STIG-ADMIN-NOT-ALLOWLISTED realm=%s user=%s path=browser: holds administrator rights but is not on the allowlist",
                context.getRealm().getName(), u.getUsername());
        context.getEvent().user(u).error(Errors.ACCESS_DENIED);
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
    @Override public String getDisplayType() { return "Administrators must be on the allowlist"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Refuses an administrator who is not on the realm's allowlist (master realm attribute)."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
