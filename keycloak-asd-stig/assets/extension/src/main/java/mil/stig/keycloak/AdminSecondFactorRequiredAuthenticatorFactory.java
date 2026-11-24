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
 * An administrator never enrols a second factor on the strength of one factor. Placed after the password (browser
 * flow) or inside the post-broker step that demands MFA: an administrator who holds no enrolled OTP / WebAuthn
 * credential is refused here, BEFORE the OTP step could offer enrolment ("Configure OTP" after a password alone is
 * how whoever knows an administrator's password would become that administrator). Everyone else, and an
 * administrator who already holds a second factor, passes untouched. An administrator enrols or replaces a second
 * factor only after signing in with the card, or with the second factor already held.
 *
 * The refusal looks like a wrong password in the browser flow (so it does not confirm that the password was right).
 * After a brokered sign-in it is a policy page (stig-admin-second-factor.ftl: sign in with the CAC, or enrol an
 * authenticator app first), shown as a challenge - never a failure, so it never counts toward brute-force lockout. The reason is in the audit log: STIG-ADMIN-SECOND-FACTOR-REQUIRED.
 */
public class AdminSecondFactorRequiredAuthenticatorFactory implements Authenticator, AuthenticatorFactory {

    public static final String ID = "stig-admin-second-factor-required";
    static final String BROKERED = "PBL_BROKERED_IDENTITY_CONTEXT";   // PostBrokerLoginConstants
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        if (user == null || !StigAdministrators.isAdministrator(realm, user) || StigAdministrators.hasSecondFactor(user)) {
            context.success();
            return;
        }
        boolean brokered = context.getAuthenticationSession().getAuthNote(BROKERED) != null;
        String idpMfa = context.getAuthenticationSession().getAuthNote(ConditionalIdpMfaUnprovenAuthenticatorFactory.NOTE);
        LOG.warnf("STIG-ADMIN-SECOND-FACTOR-REQUIRED realm=%s user=%s path=%s%s: an administrator with no enrolled second "
                + "factor was refused (no enrolment after one factor; sign in with the card)", realm.getName(), user.getUsername(),
                brokered ? "identity-provider" : "password", brokered && idpMfa != null ? " idp-mfa=" + idpMfa : "");
        context.getEvent().user(user);
        if (brokered) {
            // a POLICY refusal after a successful identity-provider sign-in - not a wrong credential: a challenge, not a
            // failure, so the brute-force protector never counts it (a failure would, and three of them lock the
            // administrator out). The page says what to do instead, with the way back to the CAC sign-in.
            context.getEvent().error(Errors.ACCESS_DENIED);
            Response page = context.form().setAttribute("cacSignIn", restartUrl(context))
                    .createForm("stig-admin-second-factor.ftl");
            context.challenge(page);
        } else {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response page = context.form().setError(Messages.INVALID_USER).createLoginUsernamePassword();
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, page);
        }
    }

    /** The sign-in from the start (the login page, where the CAC sign-in is offered), for this client and tab. */
    static String restartUrl(AuthenticationFlowContext context) {
        return org.keycloak.services.resources.LoginActionsService.loginActionsBaseUrl(context.getUriInfo())
                .path(org.keycloak.services.resources.LoginActionsService.RESTART_PATH)
                .queryParam(org.keycloak.models.Constants.CLIENT_ID, context.getAuthenticationSession().getClient().getClientId())
                .queryParam(org.keycloak.models.Constants.TAB_ID, context.getAuthenticationSession().getTabId())
                .build(context.getRealm().getName()).toString();
    }

    @Override public void action(AuthenticationFlowContext context) { authenticate(context); }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }

    // ---- factory
    @Override public Authenticator create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Administrators: second factor already enrolled"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Refuses an administrator (any realm-management role) who has no enrolled OTP/WebAuthn credential, so a second factor is never enrolled after one factor.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
