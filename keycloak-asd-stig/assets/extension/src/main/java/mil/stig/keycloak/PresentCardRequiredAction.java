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
 *
 * An administrator's LINK REQUEST (idp-admin.py link-cac; AccountsPolicy.LINK_ATTRIBUTE "stig_card_link" = the request's
 * epoch-ms) asks the holder of an EXISTING account - however they sign in (password + OTP, or the provider) - to present
 * a card at their next sign-in: live for 7 days from the request. The card attribute is the one the browser flow's X.509
 * step maps cards by. With `<card attribute>_pending` also set, only that card binds (as an invite's); without, the card
 * the holder presents - never one bound to, or reserved for, another account, and never over a card the account already
 * holds. Either way the request is settled (cleared) by a bind or a refusal, and audited.
 */
public class PresentCardRequiredAction implements RequiredActionProvider, RequiredActionFactory {

    public static final String ID = "stig-present-card";
    static final String SKIPPED = "stig-present-card-skipped";

    /**
     * STIG_CARD_PORT: a second public port of the SAME Keycloak listener (the host maps it to the same container port).
     * The card is presented by a POST to that port. Why: a browser asks for a client certificate only during a TLS
     * handshake, and it reuses the connection (HTTP/2) and the TLS session it already has with host:443 - typically one
     * made without a certificate (the person signed in with Entra, or declined the prompt). A request on that connection
     * can never carry a certificate. A different port is a different connection, TLS session and client-certificate
     * decision in the browser (they are keyed by host:port), while cookies are not port-scoped: the same authentication
     * session, so the bind stays in the same session. Unset: the form posts to the page's own origin (as before).
     */
    static final int CARD_PORT = cardPort(System.getenv("STIG_CARD_PORT"));

    static int cardPort(String v) {
        try {
            int p = Integer.parseInt(String.valueOf(v).trim());
            return p > 0 && p < 65536 ? p : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** The form's action, moved to the card port when one is configured. */
    static java.net.URI onCardPort(java.net.URI action, int port) {
        if (port <= 0 || action == null) return action;
        String host = action.getRawAuthority() == null ? null : action.getHost();
        if (host == null) return action;
        if (host.indexOf(':') >= 0 && !host.startsWith("[")) host = "[" + host + "]";        // IPv6 literal
        return java.net.URI.create(action.getScheme() + "://" + host + ":" + port + (action.getRawPath() == null ? "" : action.getRawPath())
                + (action.getRawQuery() == null ? "" : "?" + action.getRawQuery()));
    }
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    // ---- factory
    @Override public RequiredActionProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayText() { return "Present your CAC (bind the card an invite or an administrator's link request names)"; }

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

    /** What this account's step would bind: the card attribute (null: the realm's X.509 step is missing or ambiguous - a
     *  link request then binds nothing), the card it must be (null: the card the holder presents - a link request only),
     *  and whether it is an administrator's link request rather than an invite. */
    record Request(String attr, String expected, boolean link) { }

    /** The account's live request, or null. An account carrying a link request is judged by it alone (live or not). */
    static Request request(RealmModel realm, UserModel u, long nowMs) {
        String marker = u.getFirstAttribute(AccountsPolicy.LINK_ATTRIBUTE);
        if (marker != null && !marker.isBlank()) {
            if (!AccountsPolicy.linkLive(AccountsPolicy.linkTime(marker), nowMs)) return null;
            AuthenticatorConfigModel cfg = x509Config(realm);
            String ca = cfg == null || cfg.getConfig() == null ? null : AccountsPolicy.cardAttribute(cfg.getConfig().get(USER_ATTR_KEY));
            String p = ca == null ? null : u.getFirstAttribute(ca + AccountsPolicy.PENDING_SUFFIX);
            return new Request(ca, p == null || p.isBlank() ? null : p.trim(), true);
        }
        String p = livePending(realm, u, nowMs);
        return p == null ? null : new Request(cardAttr(realm), p, false);
    }

    static String shown(Request r) {
        return r.expected() == null ? "any" : AccountsPolicy.maskEdipi(r.expected());
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        UserModel u = context.getUser();
        // not again in the sign-in where the person just skipped it (Keycloak re-evaluates triggers after each action)
        if (context.getAuthenticationSession() != null && context.getAuthenticationSession().getAuthNote(SKIPPED) != null) return;
        Request r = request(context.getRealm(), u, Time.currentTimeMillis());
        if (r != null && (r.link() || u.getFirstAttribute(IdpLinkByAdminAttributeAuthenticatorFactory.ATTR) != null))
            u.addRequiredAction(ID);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (request(context.getRealm(), context.getUser(), Time.currentTimeMillis()) == null) {
            context.success();                       // nothing (left) to bind
            return;
        }
        context.challenge(page(context, null));
    }

    private jakarta.ws.rs.core.Response page(RequiredActionContext context, String error) {
        X509Certificate[] certs = chain(context);
        MultivaluedMap<String, String> f = new MultivaluedHashMap<>();
        f.add("username", context.getUser().getUsername());
        f.add("subjectDN", CARD_PORT > 0
                ? "Insert your CAC and choose Sign in: your browser will ask for your certificate (or Ignore to do it at a later sign-in)"
                : certs == null || certs.length == 0
                ? "No card presented yet: insert your CAC and choose Sign in (or Ignore to do it at a later sign-in)"
                : certs[0].getSubjectX500Principal().getName());
        f.add("isUserEnabled", "true");
        org.keycloak.forms.login.LoginFormsProvider form = context.form().setFormData(f);
        Request r = request(context.getRealm(), context.getUser(), Time.currentTimeMillis());
        form.setAttribute("cardIntro", r != null && r.link() ? "stigPresentCardIntroLink" : "stigPresentCardIntro");
        // with a card port: our own page - "Sign in with CAC/PIV" posts to the card port (a new connection and TLS handshake,
        // which asks for the certificate), "Continue without the card" posts to this page's OWN origin (the form's
        // unmodified action), so a network that blocks the card port can always go on
        if (CARD_PORT > 0) {
            java.net.URI card = onCardPort(context.getActionUrl(), CARD_PORT);
            if (error != null) form.setAttribute("cardError", error);         // shown by the template itself
            return form.setAttribute("cardAction", card.toString())
                    .setAttribute("cardProbe", card.getScheme() + "://" + card.getRawAuthority() + "/realms/" + context.getRealm().getName()
                            + "/.well-known/openid-configuration")
                    .createForm("stig-present-card.ftl");
        }
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
        Request req = request(realm, u, Time.currentTimeMillis());
        if (req == null || (!req.link() && req.attr() == null)) { context.success(); return; }
        String pending = req.expected(), ca = req.attr(), kind = req.link() ? "link" : "invite";
        if (context.getHttpRequest().getDecodedFormParameters().containsKey("cancel")) {
            LOG.infof("STIG-CARD-PRESENT-SKIPPED realm=%s user=%s request=%s card=%s: asked again at the next sign-in, until the %s expires",
                    realm.getName(), u.getUsername(), kind, shown(req), req.link() ? "link request" : "invite");
            context.getAuthenticationSession().setAuthNote(SKIPPED, "1");
            context.success();                      // re-added by evaluateTriggers at the next sign-in while live
            return;
        }
        X509Certificate[] certs = chain(context);
        if (certs == null || certs.length == 0) {
            LOG.infof("STIG-CARD-PRESENT-NO-CERT realm=%s user=%s port=%s: the request carried no client certificate",
                    realm.getName(), u.getUsername(), context.getUriInfo() == null ? "?" : String.valueOf(context.getUriInfo().getRequestUri().getPort()));
            context.challenge(page(context, "No card was presented: insert your CAC, choose Sign in, and pick your certificate when the browser asks."));
            return;
        }
        // the card must be bound to the attribute the realm's X.509 step maps cards by - else a bound card would open nothing
        // (or another account): refuse to bind on any mismatch or ambiguity, and leave the pending value for the operator
        AuthenticatorConfigModel cfg = x509Config(realm);
        if (cfg == null || cfg.getConfig() == null || ca == null || !ca.equals(cfg.getConfig().get(USER_ATTR_KEY))) {
            LOG.errorf("STIG-CARD-PRESENT-MISCONFIGURED realm=%s user=%s: %s - nothing bound", realm.getName(), u.getUsername(),
                    cfg == null ? "the browser flow has no X.509 step, or several that differ"
                                : "stig.accounts.card-attribute " + ca + " is not the X.509 step's user attribute " + cfg.getConfig().get(USER_ATTR_KEY));
            context.success();
            return;
        }
        String identity;
        try {
            Authenticator a = ((AuthenticatorFactory) session.getKeycloakSessionFactory()
                    .getProviderFactory(Authenticator.class, StigX509ClientCertificateAuthenticatorFactory.PROVIDER_ID)).create(session);
            identity = ((StigX509ClientCertificateAuthenticator) a).validatedIdentity(session, cfg, certs);
        } catch (Exception e) {
            LOG.warnf("STIG-CARD-PRESENT-INVALID realm=%s user=%s reason=card not valid (%s) subject=%s", realm.getName(), u.getUsername(),
                    e.getClass().getSimpleName(), AccountsPolicy.redactEdipis(certs[0].getSubjectX500Principal().getName()));
            context.challenge(page(context, "That card could not be validated."));
            return;
        }
        String id = identity == null ? null : identity.trim();
        boolean elsewhere = id != null && !id.isEmpty()
                && session.users().searchForUserByUserAttributeStream(realm, ca, id).anyMatch(x -> !x.getId().equals(u.getId()));
        boolean reserved = id != null && !id.isEmpty()
                && session.users().searchForUserByUserAttributeStream(realm, ca + AccountsPolicy.PENDING_SUFFIX, id).anyMatch(x -> !x.getId().equals(u.getId()));
        String why = AccountsPolicy.presentRefusal(pending, id, u.getFirstAttribute(ca), elsewhere, reserved, req.link());
        u.removeAttribute(ca + AccountsPolicy.PENDING_SUFFIX);       // either way the request is settled now
        u.removeAttribute(AccountsPolicy.LINK_ATTRIBUTE);
        if (why != null) {
            LOG.warnf("STIG-CARD-PRESENT-REFUSED realm=%s user=%s request=%s pending=%s presented=%s: %s - the account's card is unchanged",
                    realm.getName(), u.getUsername(), kind, shown(req), AccountsPolicy.maskEdipi(id), why);
            audit(context, "{\"stig\":\"card refused: " + why + "\",\"request\":\"" + kind + "\",\"card\":\"" + AccountsPolicy.maskEdipi(id) + "\"}");
            context.success();
            return;
        }
        u.setSingleAttribute(ca, id);
        LOG.infof("STIG-CARD-PRESENT-BOUND realm=%s user=%s request=%s card=%s: %s, presented by the account holder",
                realm.getName(), u.getUsername(), kind, AccountsPolicy.maskEdipi(id),
                req.link() ? (pending == null ? "the card of an administrator's link request" : "the card an administrator's link request named") : "the invite's card");
        audit(context, "{\"stig\":\"card bound: presented by the account holder\",\"request\":\"" + kind + "\",\"card\":\"" + AccountsPolicy.maskEdipi(id) + "\"}");
        context.success();
    }

    static final String USER_ATTR_KEY = "x509-cert-auth.mapper-selection.user-attribute-name";

    /** The X.509 step's configuration in the realm's browser flow (its sub-flows included). Pinned: when the flow holds
     *  several X.509 steps, they must all carry the SAME configuration (else null: refuse rather than pick one). */
    static AuthenticatorConfigModel x509Config(RealmModel realm) {
        if (realm.getBrowserFlow() == null) return null;
        List<AuthenticatorConfigModel> all = new java.util.ArrayList<>();
        find(realm, realm.getBrowserFlow().getId(), 0, all);
        return pinned(all.stream().map(c -> c == null ? null : c.getConfig()).toList()) == null ? null : all.get(0);
    }

    /** The one configuration all X.509 steps share, or null (none, one without a configuration, or two that differ). */
    static java.util.Map<String, String> pinned(List<java.util.Map<String, String>> cfgs) {
        if (cfgs.isEmpty() || cfgs.stream().anyMatch(java.util.Objects::isNull)) return null;
        return cfgs.stream().allMatch(c -> c.equals(cfgs.get(0))) ? cfgs.get(0) : null;
    }

    private static void find(RealmModel realm, String flowId, int depth, List<AuthenticatorConfigModel> out) {
        if (depth > 8) return;
        for (AuthenticationExecutionModel e : (Iterable<AuthenticationExecutionModel>) realm.getAuthenticationExecutionsStream(flowId)::iterator) {
            if (e.isAuthenticatorFlow()) {
                find(realm, e.getFlowId(), depth + 1, out);
            } else if (List.of(StigX509ClientCertificateAuthenticatorFactory.PROVIDER_ID, "auth-x509-client-username-form").contains(e.getAuthenticator())) {
                out.add(e.getAuthenticatorConfig() == null ? null : realm.getAuthenticatorConfigById(e.getAuthenticatorConfig()));
            }
        }
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
