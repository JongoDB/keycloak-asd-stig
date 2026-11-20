package mil.stig.keycloak;

import java.security.cert.X509Certificate;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.x509.X509ClientCertificateLookup;

/**
 * "Present your card": binds the card a delegate's create left PENDING (`<card attribute>_pending`, e.g.
 * cac_edipi_pending: stig-accounts' "signIn": ["entra", "cac"]) - and only when the person, already signed in through
 * the identity provider, presents a card whose identity (validated exactly as a card sign-in validates it, and extracted
 * by the realm's own X.509 mapping) EQUALS the pending value. That proves the same human holds both: a delegate who
 * put their OWN card in the slot cannot get it bound to someone else's account, because the account holder cannot
 * present that card.
 *
 *   match, and no account holds that card          bind it, clear the pending value (audited)
 *   another card, or the card already bound elsewhere   refuse, clear the pending value (audited): Entra-only
 *   no card / an invalid card                       ask again (the person may Skip: the pending value stays until the
 *                                                   invite's 7 days are over, then it is ignored and the guard reports it)
 * Triggered while the account has a pending card, a provider binding, and is within the 7 days.
 */
public class PresentCardRequiredAction implements RequiredActionProvider, RequiredActionFactory {

    public static final String ID = "stig-present-card";
    static final String SKIPPED = "stig-present-card-skipped";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    // ---- factory
    @Override public RequiredActionProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayText() { return "Present your CAC (bind the card an invite named)"; }

    static String cardAttr(RealmModel realm) {
        return AccountsPolicy.cardAttribute(realm.getAttribute(AccountsPolicy.CARD_ATTRIBUTE));
    }

    /** The account's pending card value, or null (none, card accounts off, or the invite is past its 7 days). */
    static String livePending(RealmModel realm, UserModel u, long nowMs) {
        String ca = cardAttr(realm);
        if (ca == null) return null;
        String p = u.getFirstAttribute(ca + AccountsPolicy.PENDING_SUFFIX);
        if (p == null || p.isBlank()) return null;
        return AccountsPolicy.pendingExpired(u.getCreatedTimestamp(), PendingInviteLink.markerTime(u.getFirstAttribute(StigAccountsResourceProviderFactory.CREATED_BY)), nowMs)
                ? null : p.trim();
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        UserModel u = context.getUser();
        // not again in the sign-in where the person just skipped it (Keycloak re-evaluates triggers after each action)
        if (context.getAuthenticationSession() != null && context.getAuthenticationSession().getAuthNote(SKIPPED) != null) return;
        if (u.getFirstAttribute(IdpLinkByAdminAttributeAuthenticatorFactory.ATTR) != null && livePending(context.getRealm(), u, Time.currentTimeMillis()) != null)
            u.addRequiredAction(ID);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (livePending(context.getRealm(), context.getUser(), Time.currentTimeMillis()) == null) {
            context.success();                       // nothing (left) to bind
            return;
        }
        context.challenge(page(context, null));
    }

    private jakarta.ws.rs.core.Response page(RequiredActionContext context, String error) {
        X509Certificate[] certs = chain(context);
        MultivaluedMap<String, String> f = new MultivaluedHashMap<>();
        f.add("username", context.getUser().getUsername());
        f.add("subjectDN", certs == null || certs.length == 0
                ? "No card presented yet: insert your CAC and choose Sign in (or Ignore to do it at a later sign-in)"
                : certs[0].getSubjectX500Principal().getName());
        f.add("isUserEnabled", "true");
        org.keycloak.forms.login.LoginFormsProvider form = context.form().setFormData(f);
        if (error != null) form.setError(error);
        return form.createX509ConfirmPage();
    }

    private static X509Certificate[] chain(RequiredActionContext context) {
        try {
            X509ClientCertificateLookup lookup = context.getSession().getProvider(X509ClientCertificateLookup.class);
            return lookup == null ? null : lookup.getCertificateChain(context.getHttpRequest());
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        RealmModel realm = context.getRealm(); UserModel u = context.getUser(); KeycloakSession session = context.getSession();
        String pending = livePending(realm, u, Time.currentTimeMillis()), ca = cardAttr(realm);
        if (pending == null || ca == null) { context.success(); return; }
        if (context.getHttpRequest().getDecodedFormParameters().containsKey("cancel")) {
            LOG.infof("STIG-CARD-PRESENT-SKIPPED realm=%s user=%s card=%s: asked again at the next sign-in, until the invite expires",
                    realm.getName(), u.getUsername(), AccountsPolicy.maskEdipi(pending));
            context.getAuthenticationSession().setAuthNote(SKIPPED, "1");
            context.success();                      // re-added by evaluateTriggers at the next sign-in while live
            return;
        }
        X509Certificate[] certs = chain(context);
        if (certs == null || certs.length == 0) { context.challenge(page(context, "No card was presented.")); return; }
        String identity;
        try {
            AuthenticatorConfigModel cfg = x509Config(realm);
            if (cfg == null) throw new IllegalStateException("the realm's browser flow has no configured X.509 step");
            Authenticator a = ((AuthenticatorFactory) session.getKeycloakSessionFactory()
                    .getProviderFactory(Authenticator.class, StigX509ClientCertificateAuthenticatorFactory.PROVIDER_ID)).create(session);
            identity = ((StigX509ClientCertificateAuthenticator) a).validatedIdentity(session, cfg, certs);
        } catch (Exception e) {
            LOG.warnf("STIG-CARD-PRESENT-INVALID realm=%s user=%s: %s", realm.getName(), u.getUsername(), e.getMessage());
            context.challenge(page(context, "That card could not be validated."));
            return;
        }
        String why = null;
        if (identity == null || !identity.trim().equals(pending)) why = "the card presented is not the one the invite named";
        else if (session.users().searchForUserByUserAttributeStream(realm, ca, pending).anyMatch(x -> !x.getId().equals(u.getId())))
            why = "that card is already bound to another account";
        u.removeAttribute(ca + AccountsPolicy.PENDING_SUFFIX);       // either way the invite's card is settled now
        if (why != null) {
            LOG.warnf("STIG-CARD-PRESENT-REFUSED realm=%s user=%s pending=%s presented=%s: %s - the account stays without a card",
                    realm.getName(), u.getUsername(), AccountsPolicy.maskEdipi(pending), AccountsPolicy.maskEdipi(identity), why);
            audit(context, "{\"stig\":\"card refused: " + why + "\",\"card\":\"" + AccountsPolicy.maskEdipi(pending) + "\"}");
            context.success();
            return;
        }
        u.setSingleAttribute(ca, pending);
        LOG.infof("STIG-CARD-PRESENT-BOUND realm=%s user=%s card=%s: the invite's card, presented by the account holder",
                realm.getName(), u.getUsername(), AccountsPolicy.maskEdipi(pending));
        audit(context, "{\"stig\":\"card bound: presented by the account holder\",\"card\":\"" + AccountsPolicy.maskEdipi(pending) + "\"}");
        context.success();
    }

    /** The X.509 step's configuration in the realm's browser flow (its sub-flows included). */
    static AuthenticatorConfigModel x509Config(RealmModel realm) {
        return realm.getBrowserFlow() == null ? null : find(realm, realm.getBrowserFlow().getId(), 0);
    }

    private static AuthenticatorConfigModel find(RealmModel realm, String flowId, int depth) {
        if (depth > 8) return null;
        for (AuthenticationExecutionModel e : (Iterable<AuthenticationExecutionModel>) realm.getAuthenticationExecutionsStream(flowId)::iterator) {
            if (e.isAuthenticatorFlow()) {
                AuthenticatorConfigModel c = find(realm, e.getFlowId(), depth + 1);
                if (c != null) return c;
            } else if (List.of(StigX509ClientCertificateAuthenticatorFactory.PROVIDER_ID, "auth-x509-client-username-form").contains(e.getAuthenticator())
                    && e.getAuthenticatorConfig() != null) {
                return realm.getAuthenticatorConfigById(e.getAuthenticatorConfig());
            }
        }
        return null;
    }

    private static void audit(RequiredActionContext context, String representation) {
        RealmModel realm = context.getRealm();
        if (!realm.isAdminEventsEnabled()) return;
        AdminEvent ev = new AdminEvent();
        ev.setId(KeycloakModelUtils.generateId()); ev.setTime(Time.currentTimeMillis()); ev.setRealmId(realm.getId());
        AuthDetails ad = new AuthDetails();
        ad.setRealmId(realm.getId()); ad.setUserId(context.getUser().getId());
        ad.setClientId(context.getAuthenticationSession().getClient() == null ? null : context.getAuthenticationSession().getClient().getId());
        ad.setIpAddress(context.getConnection() == null ? null : context.getConnection().getRemoteAddr());
        ev.setAuthDetails(ad);
        ev.setOperationType(OperationType.UPDATE); ev.setResourceTypeAsString(ResourceType.USER.name());
        ev.setResourcePath("users/" + context.getUser().getId());
        if (realm.isAdminEventsDetailsEnabled()) ev.setRepresentation(representation);
        EventStoreProvider store = context.getSession().getProvider(EventStoreProvider.class);
        if (store != null) store.onEvent(ev, realm.isAdminEventsDetailsEnabled());
        realm.getEventsListenersStream().forEach(l -> {
            EventListenerProvider p = context.getSession().getProvider(EventListenerProvider.class, l);
            if (p != null) p.onEvent(ev, realm.isAdminEventsDetailsEnabled());
        });
    }
}
