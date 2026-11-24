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
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.messages.Messages;

/**
 * After ANY way of signing in to the browser flow - an existing SSO cookie included - refuse an account that holds
 * administrator rights (any realm-management role, by any route) but is not on the realm's allowlist, or holds a
 * realm-management role beyond its entry (master-realm attributes only the operator's tooling writes). An administrator made in the console, not by the tooling, therefore
 * cannot sign in as one at all - not even with a session it already had.
 */
public class AdminAllowlistGateAuthenticatorFactory implements Authenticator, AuthenticatorFactory, ServerInfoAwareProviderFactory {
    /** Capability marker, published in the server info (providers.authenticator.stig-admin-allowlist-gate
     *  .operationalInfo): 1 = every allowlist check also refuses an administrator holding a realm-management role
     *  beyond its entry (stig.admin-allowlist-roles.<realm>); 2 = entries name the granted groups BY ID with a
     *  snapshot of what they carried at grant (group:<id>@<role>+...); a group that carries more now -> refused until
     *  re-granted (STIG-ADMIN-NEEDS-REGRANT), never treated as over-entry. The operator's guard reads it, and while it is missing
     *  or older it contains what an over-entitled account changed. */
    public static final String ROLE_EXTENT_KEY = "allowlist-role-extent";
    public static final String ROLE_EXTENT_VERSION = "2";      // 2: granted groups by id + snapshot (see StigAdministrators)

    /** Capability marker for the admin-API client profile (AdminApiStepUp, enforced by AdminApiGuardFilter): 1 = a
     *  client with stig.admin-api.profile=account-onboarding reaches only that profile's calls, and its writes need an
     *  authentication no older than stig.admin-api.max-auth-age; 2 = also stig.admin-api.operations; 3 = also the portal
     *  operations (stig-accounts reset-otp, reset-password, unlock, logout, link-cac, status: off unless listed). Tooling
     *  that creates such a client reads it first: on an older extension the attribute would be ignored. */
    public static final String ADMIN_API_PROFILE_KEY = "admin-api-profile";
    public static final String ADMIN_API_PROFILE_VERSION = "3";      // 3: the portal operations, each allow-listed

    /** Runtime state of the sanitised Referer audit (V-222447, StigRefererAuditFilter): "sanitised" or "off". The
     *  operator's verify and guard read it - a deployment variable can switch the audit off, so config alone is not proof. */
    public static final String REFERER_AUDIT_KEY = "referer-audit";

    @Override
    public java.util.Map<String, String> getOperationalInfo() {
        return java.util.Map.of(ROLE_EXTENT_KEY, ROLE_EXTENT_VERSION, ADMIN_API_PROFILE_KEY, ADMIN_API_PROFILE_VERSION,
                REFERER_AUDIT_KEY, StigRefererAuditFilter.ON ? "sanitised" : "off");
    }

    public static final String ID = "stig-admin-allowlist-gate";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel u = context.getUser();
        if (!StigAdministrators.unvettedAdministrator(context.getSession(), context.getRealm(), u)) {
            context.success();
            return;
        }
        LOG.errorf("STIG-ADMIN-NOT-ALLOWLISTED realm=%s user=%s path=browser: holds administrator rights it is not vetted for (not on the allowlist, or beyond its entry)",
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
    @Override public void postInit(KeycloakSessionFactory factory) {
        // once at start-up: whether the Referer is audited (V-222447); OFF is a finding, so it is a warning
        if (StigRefererAuditFilter.ON) LOG.infof("STIG-REFERER-AUDIT on: the Referer is recorded sanitised (STIG-REFERER lines)");
        else LOG.warnf("STIG-REFERER-AUDIT OFF: STIG_REFERER_AUDIT=off - the Referer is NOT recorded (V-222447 not met)");
    }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Administrators must be on the allowlist"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Refuses an administrator who is not on the realm's allowlist, or holds a realm-management role beyond its entry (master realm attributes)."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
