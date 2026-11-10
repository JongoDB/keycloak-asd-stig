package mil.stig.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import static org.keycloak.services.validation.Validation.FIELD_PASSWORD;

/**
 * Keycloak's username + password form, except that an ADMINISTRATOR (any realm-management role) with no enrolled
 * second factor is refused exactly as a wrong password is: the same execution, the same page, the same event and
 * the same lockout accounting. So the refusal neither offers TOTP set-up after a password alone nor tells whoever
 * typed the password that it was right (a separate gate execution after the form did, through the form's
 * execution id). Logged as STIG-ADMIN-SECOND-FACTOR-REQUIRED.
 */
public class StigUsernamePasswordFormFactory extends UsernamePasswordFormFactory {
    public static final String PROVIDER_ID = "stig-username-password-form";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override public Authenticator create(KeycloakSession session) { return new Form(session); }
    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "Username Password Form (administrators need an enrolled second factor)"; }
    @Override public String getHelpText() {
        return "Username and password; an administrator without an enrolled OTP/WebAuthn is refused like a wrong password.";
    }

    static final class Form extends UsernamePasswordForm {
        Form(KeycloakSession session) { super(session); }

        @Override
        protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
            boolean userWasSet = isUserAlreadySetBeforeUsernamePasswordAuth(context);
            if (!super.validateForm(context, formData)) return false;
            UserModel user = context.getUser();
            if (user == null || !StigAdministrators.isAdministrator(context.getRealm(), user)) return true;
            if (StigAdministrators.unvettedAdministrator(context.getSession(), context.getRealm(), user)) {
                LOG.errorf("STIG-ADMIN-NOT-ALLOWLISTED realm=%s user=%s path=password: holds administrator rights but is not on the "
                        + "allowlist - refused as if the password were wrong", context.getRealm().getName(), user.getUsername());
            } else if (StigAdministrators.hasSecondFactor(user)) {
                return true;
            } else {
                LOG.warnf("STIG-ADMIN-SECOND-FACTOR-REQUIRED realm=%s user=%s path=password: an administrator with no enrolled second "
                        + "factor was refused as if the password were wrong (sign in with the card)", context.getRealm().getName(), user.getUsername());
            }
            context.getAuthenticationSession().removeAuthNote(AuthenticationManager.PASSWORD_VALIDATED);
            context.getEvent().user(user);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            AuthenticatorUtils.setupReauthenticationInUsernamePasswordFormError(context);
            Response challenge = challenge(context, getDefaultChallengeMessage(context), FIELD_PASSWORD);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            if (!userWasSet) context.clearUser();
            return false;
        }
    }
}
