package mil.stig.keycloak;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.UsernameForm;
import org.keycloak.authentication.authenticators.browser.UsernameFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Passkey realms (kcstig auth_mode=passkey, sign_in=username): Keycloak's own username form (passkeys, conditional UI,
 * "Sign in with passkey"), except that an account holding NO passwordless passkey is answered EXACTLY as an unknown
 * username - Keycloak's own invalid-user path (testInvalidUser with no user), the same page, status and event - so
 * the response does not tell whether such an account exists. A disabled or locked-out account is answered the same way
 * (Keycloak's own "Account is disabled" would tell it apart),, and it is never taken on to a passkey step where it
 * could be offered a set-up. A passkey is registered only through the e-mailed set-up or recovery link.
 * UsernameForm is final, so this wraps it and intercepts the flow context's success().
 * Logged as STIG-PASSKEY-NOT-ENROLLED.
 */
public class StigPasskeyUsernameFormFactory implements AuthenticatorFactory {
    public static final String ID = "stig-passkey-username-form";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    static boolean hasPasskey(UserModel u) {
        return u != null && u.credentialManager().isConfiguredFor(WebAuthnCredentialModel.TYPE_PASSWORDLESS);
    }

    static final class Form implements Authenticator {
        private final UsernameForm inner;
        Form(KeycloakSession session) { this.inner = new UsernameForm(session); }

        /** The context, with success() checked: an identified account without a passkey becomes an unknown user. */
        private AuthenticationFlowContext guarded(AuthenticationFlowContext ctx) {
            InvocationHandler h = (proxy, m, args) -> {
                if (m.getName().equals("success") && !hasPasskey(ctx.getUser())) {
                    asUnknown(ctx, "no passkey");
                    return null;
                }
                // Keycloak answers a DISABLED account with "Account is disabled" (enabledUser -> forceChallenge) before
                // success() is ever reached: that, too, would tell an existing account from an unknown username
                boolean disabledAnswer = false;
                if (m.getName().equals("forceChallenge")) {
                    // enabledUser runs BEFORE the account is put in the context: find it by the attempted username
                    UserModel cu = ctx.getUser();
                    if (cu == null) {
                        String tried = ctx.getAuthenticationSession().getAuthNote(
                                org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
                        cu = tried == null ? null : org.keycloak.models.utils.KeycloakModelUtils.findUserByNameOrEmail(
                                ctx.getSession(), ctx.getRealm(), tried);
                    }
                    // disabled, or locked by brute-force protection (unreachable in a passkey realm today - Keycloak
                    // 26.8.2 counts no failed passkey assertion, with or without a user in context - but answered the
                    // same way, so a later release that counts them cannot turn the lock into an account oracle)
                    disabledAnswer = cu != null && (!cu.isEnabled() || lockedOut(ctx, cu));
                }
                boolean disabledFailure = (m.getName().equals("failureChallenge") || m.getName().equals("failure")) && args != null
                        && args.length > 0 && (args[0] == AuthenticationFlowError.USER_DISABLED || args[0] == AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
                if (disabledAnswer || disabledFailure) {
                    asUnknown(ctx, "disabled");
                    return null;
                }
                try {
                    return m.invoke(ctx, args);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            };
            return (AuthenticationFlowContext) Proxy.newProxyInstance(AuthenticationFlowContext.class.getClassLoader(),
                    new Class<?>[] {AuthenticationFlowContext.class}, h);
        }

        private static boolean lockedOut(AuthenticationFlowContext ctx, UserModel u) {
            org.keycloak.services.managers.BruteForceProtector p = ctx.getProtector();
            return p != null && ctx.getRealm().isBruteForceProtected()
                    && (p.isTemporarilyDisabled(ctx.getSession(), ctx.getRealm(), u) || p.isPermanentlyLockedOut(ctx.getSession(), ctx.getRealm(), u));
        }

        /** Answer exactly as Keycloak answers an unknown username: no user in the context, the event or the auth
         *  session (Keycloak's failure logging would otherwise find the account by the attempted-username note and
         *  count the attempt against it - a lockout that answers differently and lets anyone lock the account). */
        private void asUnknown(AuthenticationFlowContext ctx, String why) {
            UserModel u = ctx.getUser();
            LOG.warnf("STIG-PASSKEY-NOT-ENROLLED realm=%s user=%s: %s; answered as an unknown username",
                    ctx.getRealm().getName(), u == null ? "?" : u.getUsername(), why);
            ctx.clearUser();
            ctx.getEvent().user((String) null);
            ctx.getAuthenticationSession().removeAuthNote(
                    org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
            inner.testInvalidUser(ctx, null);                         // Keycloak's own unknown-user response
        }

        @Override public void authenticate(AuthenticationFlowContext context) { inner.authenticate(guarded(context)); }
        @Override public void action(AuthenticationFlowContext context) { inner.action(guarded(context)); }
        @Override public boolean requiresUser() { return inner.requiresUser(); }
        @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return inner.configuredFor(s, r, u); }
        @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { }
        @Override public void close() { inner.close(); }
    }

    private final UsernameFormFactory base = new UsernameFormFactory();
    @Override public Authenticator create(KeycloakSession session) { return new Form(session); }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }
    @Override public String getReferenceCategory() { return base.getReferenceCategory(); }
    @Override public Set<String> getOptionalReferenceCategories(KeycloakSession s) { return base.getOptionalReferenceCategories(s); }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return base.getRequirementChoices(); }
    @Override public String getDisplayType() { return "Passkey realm: username form (no passkey = unknown user)"; }
    @Override public String getHelpText() { return "Keycloak's username form; an account without a passkey is answered exactly as an unknown username."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
    @Override public boolean isUserSetupAllowed() { return false; }
}
