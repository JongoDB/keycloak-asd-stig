package mil.stig.keycloak;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/**
 * Condition for the post-broker "administrators prove MFA" sub-flow: matches (the sub-flow runs: an enrolled second
 * factor is required, and an administrator without one is refused) UNLESS this sign-in's validated ID token from a
 * trusted tenant reports the tenant's own MFA (IdpMfaEvidence). Placed after conditional-stig-administrator, so it is
 * evaluated for administrators only.
 *
 * Fails toward today's behaviour: no configuration, a malformed one, another provider or tenant, a guest, a missing or
 * malformed claim, no token, or any error reading it - each MATCHES, and the second factor is still required.
 *
 * The evidence lives only in this sign-in's authentication session (notes stig.idp-mfa.*) and in the audit log and
 * event details; nothing is stored on the user and no token is kept beyond what Keycloak's own broker keeps for the
 * sign-in. Audit line: STIG-ADMIN-SECOND-FACTOR-IDP-MFA accepted|refused ... reason=... amr=[method names].
 */
public class ConditionalIdpMfaUnprovenAuthenticatorFactory implements ConditionalAuthenticator, ConditionalAuthenticatorFactory {

    public static final String ID = "conditional-stig-idp-mfa-unproven";
    static final String VALIDATED_ID_TOKEN = "VALIDATED_ID_TOKEN";        // OIDCIdentityProvider.VALIDATED_ID_TOKEN
    static final String NOTE = "stig.idp-mfa", NOTE_AMR = "stig.idp-mfa.amr", NOTE_ACR = "stig.idp-mfa.acr";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticationSessionModel as = context.getAuthenticationSession();
        UserModel user = context.getUser();
        AuthenticatorConfigModel cm = context.getAuthenticatorConfig();
        IdpMfaEvidence.Cfg cfg = IdpMfaEvidence.cfg(cm == null ? null : cm.getConfig());
        IdpMfaEvidence.Decision d;
        String alias = null;
        try {
            SerializedBrokeredIdentityContext s = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                    as, AdminSecondFactorRequiredAuthenticatorFactory.BROKERED);
            Map<String, Object> claims = null;
            if (s != null) {
                alias = s.getIdentityProviderId();
                if (cfg.usable() && cfg.alias().equals(alias)) {          // deserialize only for the trusted provider
                    BrokeredIdentityContext b = s.deserialize(context.getSession(), as);
                    claims = claims(b.getContextData().get(VALIDATED_ID_TOKEN));
                }
            }
            d = IdpMfaEvidence.decide(cfg, alias, claims);
        } catch (RuntimeException e) {
            d = new IdpMfaEvidence.Decision(false, "error reading the sign-in's evidence (" + e.getClass().getSimpleName() + ")", null, null);
        }
        record(context, as, user, alias, d);
        return !d.accepted();
    }

    /** The validated token as a JSON object (Keycloak keeps it in the broker context as a JsonWebToken). */
    @SuppressWarnings("unchecked")
    static Map<String, Object> claims(Object token) {
        if (token == null) return null;
        if (token instanceof Map<?, ?> m) return (Map<String, Object>) m;
        return JsonSerialization.mapper.convertValue(token, Map.class);
    }

    private static void record(AuthenticationFlowContext context, AuthenticationSessionModel as, UserModel user, String alias,
                               IdpMfaEvidence.Decision d) {
        String verdict = d.accepted() ? "accepted" : "refused";
        String line = verdict + " reason=" + d.reason() + " amr=[" + d.amrText() + "]" + (d.acr() == null ? "" : " acr=" + d.acr());
        // conditions may be evaluated more than once in a flow: one audit line per distinct decision of this sign-in
        if (!Objects.equals(as.getAuthNote(NOTE), line)) {
            as.setAuthNote(NOTE, line);
            as.setAuthNote(NOTE_AMR, d.amrText());
            if (d.acr() != null) as.setAuthNote(NOTE_ACR, d.acr()); else as.removeAuthNote(NOTE_ACR);
            LOG.infof("STIG-ADMIN-SECOND-FACTOR-IDP-MFA %s realm=%s user=%s idp=%s reason=%s amr=[%s]%s", verdict,
                    context.getRealm().getName(), user == null ? "?" : user.getUsername(), alias == null ? "-" : alias, d.reason(),
                    d.amrText(), d.acr() == null ? "" : " acr=" + d.acr());
        }
        context.getEvent().detail("stig_idp_mfa", verdict).detail("stig_idp_mfa_reason", d.reason())
                .detail("stig_idp_mfa_amr", d.amrText());
    }

    @Override public void action(AuthenticationFlowContext context) { }
    @Override public boolean requiresUser() { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }

    @Override public ConditionalAuthenticator getSingleton() { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Condition - identity provider did not vouch for MFA (trusted tenant)"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return true; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Post broker login: matches unless this sign-in's validated ID token, from the configured provider and a trusted tenant, "
                + "reports MFA (amr contains an accepted method, or an accepted acr). Fails closed: no config, any doubt = matches.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return IdpMfaEvidence.properties(); }
}
