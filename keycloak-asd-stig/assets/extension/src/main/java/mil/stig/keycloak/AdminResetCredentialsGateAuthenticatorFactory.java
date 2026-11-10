package mil.stig.keycloak;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

/**
 * Reset-credentials flow, between "choose user" and "send e-mail": an administrator with no enrolled second factor
 * gets NO reset e-mail, and the same "you should receive an e-mail" page anyone else gets (no enumeration). An
 * administrator never sets a password through an e-mailed link and then enrols a second factor on its strength.
 * Logged as STIG-ADMIN-RESET-REFUSED.
 */
public class AdminResetCredentialsGateAuthenticatorFactory implements Authenticator, AuthenticatorFactory {
    public static final String ID = "stig-admin-reset-credentials-gate";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user != null && StigAdministrators.isAdministrator(context.getRealm(), user) && !StigAdministrators.hasSecondFactor(user)) {
            LOG.warnf("STIG-ADMIN-RESET-REFUSED realm=%s user=%s: no reset e-mail for an administrator without an enrolled second factor",
                    context.getRealm().getName(), user.getUsername());
            context.forkWithSuccessMessage(new FormMessage(Messages.EMAIL_SENT));
            return;
        }
        context.success();
    }

    @Override public void action(AuthenticationFlowContext context) { authenticate(context); }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }
    @Override public Authenticator create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Reset: no e-mail for an administrator without a second factor"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Between choose-user and send-email in the reset-credentials flow."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
