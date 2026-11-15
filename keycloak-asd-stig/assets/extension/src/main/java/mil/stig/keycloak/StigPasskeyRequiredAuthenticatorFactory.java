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
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

/**
 * Passkey realms (kcstig auth_mode=passkey), right after the username form: an account that holds NO passwordless
 * passkey is refused here, in the sign-in flow. It is never enrolled during sign-in - a passkey is registered only
 * through the e-mailed set-up or recovery link (execute-actions), which proves control of the mailbox on record.
 * Without this step an unclaimed account (invited, not yet set up) would be protected only by whether Keycloak's own
 * passkey authenticator allows set-up during sign-in, a property of the Keycloak release rather than of this realm.
 * Logged as STIG-PASSKEY-NOT-ENROLLED.
 */
public class StigPasskeyRequiredAuthenticatorFactory implements Authenticator, AuthenticatorFactory {
    public static final String ID = "stig-passkey-required";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel u = context.getUser();
        if (u != null && u.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_PASSWORDLESS)) {
            context.success();
            return;
        }
        LOG.warnf("STIG-PASSKEY-NOT-ENROLLED realm=%s user=%s: no passkey; refused (set-up only through the e-mailed link)",
                context.getRealm().getName(), u == null ? "?" : u.getUsername());
        if (u != null) context.getEvent().user(u);
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        Response page = context.form().setError(Messages.ACCESS_DENIED).createErrorPage(Response.Status.UNAUTHORIZED);
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, page);
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
    @Override public String getDisplayType() { return "Passkey realm: refuse an account without a passkey"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "After the username form: an account with no passwordless passkey is refused, never enrolled."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
