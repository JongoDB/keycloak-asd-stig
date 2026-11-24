package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * /admin/realms/{realm}/stig-accounts - the ONLY account operations a fine-grained delegate needs, for delegates that
 * hold no `manage-members`, and only for callers that also hold realm-management query-users - the IdP's user managers,
 * not an application's fine-grained-only delegate (so they can never set or reset a password, touch credentials or identity-provider links,
 * change an e-mail address, send mail to an address of their choosing, or re-enable an account):
 *
 *   POST /users                      {username first.last, email, firstName, lastName, group "/app/ROLE"[, lifespan]}
 *                                    create into a group the caller may manage the membership of, e-mail the set-up link
 *                                    (password, TOTP, terms; at most 24 h). 201 {id, username, setupEmail}
 *   POST /users/{id}/setup-email     re-send the set-up link to the address ON RECORD, only while the account is still
 *                                    being set up (no credential, set-up actions pending; else 409); once per 15 min. 204
 *   POST /users/{id}/disable         disable a member and end its sessions (back-channel). 204. There is NO enable:
 *                                    re-enabling is for realm administrators only. At most 20 per caller in any 60 minutes.
 *                                    "signIn": "entra" - an account for the realm's external identity provider (no
 *                                    set-up, no mail; its first provider sign-in binds it: PendingInviteLink).
 *                                    "signIn": "cac", "edipi": "<10 digits>" - a card account: the card attribute is
 *                                    bound here, server-side, to a brand-new account (never an existing one); no
 *                                    password/OTP set-up, no mail; 409 when that card is bound to any account.
 *   An optional `reference` (body field of POST /users, or ?reference= on the others; 1-64 of [A-Za-z0-9._:-], e.g.
 *   the request the call fulfils) is recorded in the admin event and the audit log line. Invalid: 400.
 *
 * The PORTAL operations - for an application page's onboarding client only (a token of a client carrying the admin-API
 * profile account-onboarding whose stig.admin-api.operations lists the operation; any other token: 403), each a write
 * needing an authentication no older than the client's max-auth-age (else 401 + the RFC 9470 challenge), each limited
 * to 20 per caller in any 60 minutes (429), each answered without any identifier beyond the account's id and username:
 *   POST /users/{id}/reset-otp       remove the account's OTP authenticators, require CONFIGURE_TOTP at the next sign-in.
 *                                    200 {"removed": n}. Only for an account that signs in with a password (409).
 *   POST /users/{id}/reset-password  e-mail the account's address ON RECORD a link to set a new password (UPDATE_PASSWORD;
 *                                    ?lifespan= as setup-email). Nobody sets a password here. Only for an account that has
 *                                    one (409: setup-email is for accounts still being set up); once per 15 min (429).
 *                                    200 {"email": "sent"}; 502 when the mail could not be sent.
 *   POST /users/{id}/unlock          clear the account's brute-force lockout (its login failures). 200 {"wasLocked": b};
 *                                    an account NOT locked: a no-op (its failure count is never reset, no admin event).
 *                                    A DISABLED account (an administrator's disable, or a permanent lockout): 409 -
 *                                    re-enabling is for realm administrators only.
 *   POST /users/{id}/logout          end every session of the account (back-channel). 200 {"sessionsEnded": n}
 *   POST /users/{id}/link-cac        none, {} or {"edipi": "<10 digits>"}: a LINK REQUEST, as idp-admin.py link-cac's default
 *                                    and --edipi modes: the holder presents a card at their next sign-in (the present-card
 *                                    step's own rules: never a card bound to or reserved for another account, an any-card
 *                                    request never satisfied by an SSO-reused sign-in); with edipi only that card binds.
 *                                    Never a direct bind, never over a card the account holds nor over a live request
 *                                    (409; replacing or cancelling stays with the IdP's operators); an expired one is replaced. 200 {"requested": true, "card": "any" | "named", "days": 7}
 *   GET  /users/{id}/status          {id, username, enabled, locked, passwordSet, otpEnrolled, cardBound, cardPending,
 *                                     entraLinked, activeSessions}: booleans and a count only (no step-up: a read)
 *   GET  /users/status?id=..&id=..   up to 50 at once: {"accounts": [status...], "refused": [ids not in scope]}
 *                                    Status: at most 60 calls per caller in any minute (a page counts once): 429.
 *   Every portal write records one admin event (ACTION users/{id}/<op>, {"stig": "portal <op>", ...}; a card masked to
 *   its last four digits) and a STIG-ACCOUNTS <op> audit line.
 *   anything else                    403
 *
 * Authorisation is Keycloak's own: the admin API's token checks (audience, admin scope) and the realm's fine-grained
 * evaluator - Groups `manage-membership` on the target group, and on EVERY group of an existing target. Never an
 * administrator (any realm-management role, or a group carrying one) as a target or a group. Refused: a username or
 * e-mail address already in use (409), a malformed one (400). Every call writes an admin event attributed to the caller.
 */
public class StigAccountsResourceProviderFactory implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    public static final String ID = "stig-accounts";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");
    static final List<String> SETUP_ACTIONS = List.of("UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS");
    /** Recorded on every account this endpoint creates: such an account is never made an administrator without a
     *  credential reset and an operator-set e-mail address (the operator's tooling enforces it). */
    static final String CREATED_BY = "stig_created_by";
    /** Client (for a service-account caller) or realm attribute: comma list of e-mail domains a caller may create
     *  accounts for (".mil" = any domain ending in .mil; "example.org" = exactly that domain). The client attribute
     *  wins over the realm attribute. Unset on both: ".mil" only. Set but blank or malformed: no domain (fail closed). */
    static final String EMAIL_DOMAINS = "stig.accounts.email-domains";

    @Override public AdminRealmResourceProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    /** Only callers holding this realm-management role (the IdP's user managers) may use the endpoint at all; an
     *  application's fine-grained-only delegate is refused everything, whatever its group scopes. */
    static final String REQUIRED_ROLE = "query-users";

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        UserModel caller = auth.adminAuth().getUser();
        ClientModel rm = realm.getClientByClientId("realm-management");
        org.keycloak.models.RoleModel need = rm == null ? null : rm.getRole(REQUIRED_ROLE);
        if (caller == null || need == null || !caller.hasRole(need)) {
            LOG.warnf("STIG-ACCOUNTS-REFUSED realm=%s caller=%s: not an IdP user manager (no realm-management %s)", realm.getName(),
                    caller == null ? "?" : caller.getUsername(), REQUIRED_ROLE);
            return new Refused();
        }
        return new Accounts(session, realm, auth, adminEvent);
    }

    /** Every method and path: 403. */
    @Produces(MediaType.APPLICATION_JSON)
    public static final class Refused {
        private static Response no() {
            return Response.status(Response.Status.FORBIDDEN).entity(Map.of("error", "not allowed")).type(MediaType.APPLICATION_JSON).build();
        }
        @GET @Path("{any: .*}") public Response g() { return no(); }
        @GET public Response g0() { return no(); }
        @POST @Path("{any: .*}") public Response p() { return no(); }
        @POST public Response p0() { return no(); }
        @PUT @Path("{any: .*}") public Response u() { return no(); }
        @DELETE @Path("{any: .*}") public Response d() { return no(); }
        @PATCH @Path("{any: .*}") public Response pa() { return no(); }
    }

    @Produces(MediaType.APPLICATION_JSON)
    public static final class Accounts {
        private final KeycloakSession session; private final RealmModel realm; private final AdminPermissionEvaluator auth;
        private final AdminEventBuilder adminEvent;

        Accounts(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
            this.session = session; this.realm = realm; this.auth = auth; this.adminEvent = adminEvent;
        }

        private static Response err(Response.Status st, String msg) {
            return Response.status(st).entity(Map.of("error", msg)).type(MediaType.APPLICATION_JSON).build();
        }
        private static String str(Map<String, Object> b, String k) {
            Object v = b == null ? null : b.get(k);
            return v instanceof String s ? s.trim() : null;
        }
        private String caller() {
            UserModel u = auth.adminAuth().getUser();
            return u == null ? "?" : u.getUsername();
        }
        private void refused(String op, String why) {
            LOG.warnf("STIG-ACCOUNTS-REFUSED realm=%s caller=%s op=%s: %s", realm.getName(), caller(), op, why);
        }

        /** The existing target, when the caller may manage it: in at least one group, every one of them a group whose
         *  membership the caller manages, none carrying administrator rights nor in the /roles tree, and not an
         *  administrator itself (any effective realm-management role). */
        private UserModel target(String id, String op) {
            UserModel u = id == null || !AdminApiStepUp.id(id) ? null : session.users().getUserById(realm, id);
            if (u == null || u.getServiceAccountClientLink() != null) { refused(op, "no such account " + AccountsPolicy.maskDigitRuns(String.valueOf(id))); return null; }
            List<GroupModel> gs = u.getGroupsStream().collect(Collectors.toList());
            if (gs.isEmpty() || StigAdministrators.isAdministrator(realm, u)
                    || gs.stream().anyMatch(g -> StigAdministrators.groupCarriesAdmin(realm, g) || inRolesTree(g) || !auth.groups().canManageMembership(g))) {
                refused(op, "account " + u.getUsername() + " is an administrator or outside the caller's groups");
                return null;
            }
            return u;
        }

        /** A group in the /roles tree (the IdP's own role groups), at any depth. */
        private static boolean inRolesTree(GroupModel g) {
            java.util.LinkedList<String> path = new java.util.LinkedList<>();
            for (GroupModel x = g; x != null; x = x.getParent()) path.addFirst(x.getName());
            return AccountsPolicy.inRolesTree(path);
        }

        private boolean profileNameValid(String value, String field) {
            org.keycloak.validate.Validator v = org.keycloak.validate.Validators.validator(session, "person-name-prohibited-characters");
            if (v == null) return true;     // the user-profile validator is not available: AccountsPolicy.validName still applies
            return v.validate(value, field, new org.keycloak.validate.ValidationContext(session), org.keycloak.validate.ValidatorConfig.EMPTY).isValid();
        }

        private String emailDomains() {
            UserModel cu = auth.adminAuth().getUser();
            String link = cu == null ? null : cu.getServiceAccountClientLink();
            ClientModel c = link == null ? null : realm.getClientById(link);
            // A set attribute is authoritative even when blank (then nothing is allowed); only an unset one falls
            // through, client -> realm -> the default.
            String v = c == null ? null : c.getAttribute(EMAIL_DOMAINS);
            if (v == null) v = realm.getAttribute(EMAIL_DOMAINS);
            return v == null ? AccountsPolicy.DEFAULT_EMAIL_DOMAINS : v;
        }

        /** At most `limit` operations of one kind per caller in ANY 60 minutes (a sliding window), atomically: each one
         *  claims one of `limit` numbered slots with putIfAbsent (atomic in the cluster cache), and a slot frees itself
         *  exactly one hour after it was claimed; with every slot taken it is refused. */
        private boolean underRate(String kind, int limit) {
            return underRate(kind, limit, AccountsPolicy.RATE_WINDOW);
        }

        /** The same, over a window of `window` seconds. */
        private boolean underRate(String kind, int limit, int window) {
            UserModel cu = auth.adminAuth().getUser();
            String base = "stig-accounts-" + kind + ":" + (cu == null ? "?" : cu.getId()) + ":";
            org.keycloak.models.SingleUseObjectProvider so = session.singleUseObjects();
            for (int i = 0; i < limit; i++) {
                if (so.putIfAbsent(base + i, window)) return true;
            }
            return false;
        }

        /** One status call's rate slot (STATUS_PER_MINUTE per caller in any 60 s; a page of up to 50 counts once). */
        private boolean statusRate() {
            if (underRate("portal-status", AccountsPolicy.STATUS_PER_MINUTE, 60)) return true;
            refused("status", "more than " + AccountsPolicy.STATUS_PER_MINUTE + " status calls in a minute");
            return false;
        }

        private static String refSuffix(String ref) { return ref == null ? "" : " reference=" + ref; }

        /** E-mail the account's address on record a link that runs `actions` (Keycloak's execute-actions mail, the
         *  token valid `lifespan` seconds, landing on the account console). No event: the caller records its own. */
        private boolean sendActions(UserModel u, List<String> actions, int lifespan) {
            ClientModel console = realm.getClientByClientId(Constants.ACCOUNT_CONSOLE_CLIENT_ID);
            String redirect = UriBuilder.fromUri(session.getContext().getUri().getBaseUri()).path("realms").path(realm.getName())
                    .path("account").path("/").build().toString();
            int expiration = Time.currentTime() + lifespan;
            ExecuteActionsActionToken token = new ExecuteActionsActionToken(u.getId(), u.getEmail(), expiration, actions,
                    console == null ? null : redirect, console == null ? null : console.getClientId());
            UriBuilder b = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            b.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));
            try {
                session.getProvider(EmailTemplateProvider.class)
                        .setAttribute(Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS, token.getRequiredActions())
                        .setAttribute(Constants.IGNORE_ACCEPT_LANGUAGE_HEADER, true)
                        .setRealm(realm).setUser(u).sendExecuteActions(b.build(realm.getName()).toString(), TimeUnit.SECONDS.toMinutes(lifespan));
                return true;
            } catch (EmailException e) {
                LOG.warnf("STIG-ACCOUNTS e-mail (%s) to %s failed: %s", String.join(",", actions), u.getUsername(), e.getMessage());
                return false;
            }
        }

        private boolean sendSetup(UserModel u, int lifespan, String ref) {
            if (!sendActions(u, SETUP_ACTIONS, lifespan)) return false;
            session.singleUseObjects().put("stig-accounts-setup:" + u.getId(), AccountsPolicy.RESEND_INTERVAL, Map.of("t", "1"));
            adminEvent.operation(OperationType.ACTION).resource(ResourceType.USER)
                    .resourcePath("users", u.getId(), "execute-actions-email");
            if (ref != null) adminEvent.representation(Map.of("reference", ref));
            adminEvent.success();
            return true;
        }

        @POST @Path("users") @Consumes(MediaType.APPLICATION_JSON)
        public Response create(Map<String, Object> body, @QueryParam("lifespan") Integer lifespanQ,
                               @QueryParam("reference") String refQ) {
            String username = str(body, "username"), email = str(body, "email"), first = str(body, "firstName"),
                   last = str(body, "lastName"), groupPath = str(body, "group");
            Object refB = body == null ? null : body.get("reference");
            if (refB != null && !(refB instanceof String)) return err(Response.Status.BAD_REQUEST, "reference must be a string");
            String ref = AccountsPolicy.reference(refB != null ? (String) refB : refQ);
            if ("".equals(ref)) return err(Response.Status.BAD_REQUEST, "reference must be 1-64 of A-Z a-z 0-9 . _ : -");
            Integer lifespanB = body != null && body.get("lifespan") instanceof Number n ? n.intValue() : lifespanQ;
            if (!AccountsPolicy.validUsername(username)) return err(Response.Status.BAD_REQUEST, "username must be first.last in lower case");
            if (!AccountsPolicy.validEmail(email)) return err(Response.Status.BAD_REQUEST, "invalid e-mail address");
            if (!AccountsPolicy.validName(first) || !AccountsPolicy.validName(last) || !profileNameValid(first, "firstName") || !profileNameValid(last, "lastName")) {
                return err(Response.Status.BAD_REQUEST, "firstName and lastName are required: a person's name, no links or markup");
            }
            // "signIn": "entra" - an account that will sign in only through the realm's external identity provider:
            // no password or OTP set-up, no set-up mail; the provider's FIRST sign-in binds it (PendingInviteLink).
            // Allowed only when the realm names the provider's domain (stig.accounts.entra-domain) and the address is in it.
            // "signIn": "password" (default) | "entra" | "cac" | ["entra", "cac"] (both on one account: the card is bound
            // here, the provider's first sign-in binds the rest)
            Object signInB = body == null ? null : body.get("signIn");
            List<String> methods = AccountsPolicy.signInMethods(signInB);
            if (methods == null) {
                return err(Response.Status.BAD_REQUEST, "signIn must be password, " + AccountsPolicy.SIGN_IN_PROVIDER + ", "
                        + AccountsPolicy.SIGN_IN_CARD + " or [" + AccountsPolicy.SIGN_IN_PROVIDER + ", " + AccountsPolicy.SIGN_IN_CARD + "]");
            }
            String signIn = String.join(",", methods);
            // a set-up link's lifetime means nothing without a set-up mail: refused rather than silently ignored
            if (!methods.equals(List.of("password")) && (lifespanB != null))
                return err(Response.Status.BAD_REQUEST, "lifespan is only for a password account's set-up mail");
            boolean viaProvider = methods.contains(AccountsPolicy.SIGN_IN_PROVIDER);
            boolean viaCard = methods.contains(AccountsPolicy.SIGN_IN_CARD);
            // "signIn": "cac": the card is bound HERE, at creation only, to a brand-new account - stig-accounts never
            // binds a card to an existing account, and the plain admin API still refuses a delegate (cac-identity-guard)
            Object edipiB = body == null ? null : body.get("edipi");
            if (edipiB != null && !viaCard) return err(Response.Status.BAD_REQUEST, "edipi is only for signIn " + AccountsPolicy.SIGN_IN_CARD);
            String edipi = edipiB instanceof String es ? es.trim() : null;
            String cardAttr = viaCard ? AccountsPolicy.cardAttribute(realm.getAttribute(AccountsPolicy.CARD_ATTRIBUTE)) : null;
            if (viaCard && !AccountsPolicy.validEdipi(edipi)) return err(Response.Status.BAD_REQUEST, "edipi must be exactly 10 digits");
            if (viaCard && cardAttr == null) {
                refused("create", "signIn cac: the realm's " + AccountsPolicy.CARD_ATTRIBUTE + " is unset or malformed");
                return err(Response.Status.FORBIDDEN, "this realm does not create card accounts");
            }
            if (viaProvider && !AccountsPolicy.providerDomainMatches(email, realm.getAttribute(AccountsPolicy.PROVIDER_DOMAIN))) {
                refused("create", "signIn " + signIn + " for " + email + ": the realm's " + AccountsPolicy.PROVIDER_DOMAIN + " is "
                        + realm.getAttribute(AccountsPolicy.PROVIDER_DOMAIN));
                return err(Response.Status.FORBIDDEN, "this address cannot sign in through the identity provider");
            }
            String domains = emailDomains();
            if (!AccountsPolicy.emailDomainAllowed(email, domains)) {
                refused("create", "e-mail domain of " + email + " not in " + domains);
                return err(Response.Status.FORBIDDEN, "e-mail domain not allowed for this caller");
            }
            int lifespan = AccountsPolicy.lifespan(lifespanB);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..86400 seconds");
            GroupModel g = groupPath == null ? null : KeycloakModelUtils.findGroupByPath(session, realm, groupPath);
            if (g == null || StigAdministrators.groupCarriesAdmin(realm, g) || !auth.groups().canManageMembership(g)) {
                refused("create", "group " + groupPath + " is not one whose membership the caller manages");
                return err(Response.Status.FORBIDDEN, "not allowed");
            }
            // The rate slot is claimed HERE: after the caller's own mistakes (malformed input, domain, lifespan, a group it
            // cannot manage), which spend none, and BEFORE the existence check, so every 409 costs a slot and probing
            // whether a username or e-mail exists anywhere in the realm stays limited to 20 an hour. The 409 never says
            // which of the two is taken, nor echoes either. The claim is atomic, so concurrency cannot exceed the limit.
            if (!underRate("create", AccountsPolicy.CREATE_PER_HOUR)) {
                refused("create", "more than " + AccountsPolicy.CREATE_PER_HOUR + " accounts in an hour");
                return err(Response.Status.TOO_MANY_REQUESTS, "too many accounts created this hour");
            }
            String conflict = viaCard ? AccountsPolicy.CARD_CONFLICT : "username or e-mail address already in use";
            if (session.users().getUserByUsername(realm, username) != null || session.users().getUserByEmail(realm, email) != null) {
                refused("create", "username or e-mail address already in use: " + username);
                return err(Response.Status.CONFLICT, conflict);
            }
            if (viaCard) {
                // one card, one account (cac-identity-guard's rule: no account in the realm may hold the value), and
                // two concurrent creates with the same card cannot both pass: the card is claimed atomically first
                String lock = "stig-accounts-card:" + realm.getId() + ":" + edipi;
                if (!session.singleUseObjects().putIfAbsent(lock, 60)) {
                    refused("create", "card " + AccountsPolicy.maskEdipi(edipi) + " is being bound by another create: " + username);
                    return err(Response.Status.CONFLICT, conflict);
                }
                // the claim is held until this transaction ends (committed: the card is on the account, which the search
                // below finds from then on; rolled back: free again) - never longer than its 60 s
                session.getTransactionManager().enlistAfterCompletion(new org.keycloak.models.AbstractKeycloakTransaction() {
                    @Override protected void commitImpl() { session.singleUseObjects().remove(lock); }
                    @Override protected void rollbackImpl() { session.singleUseObjects().remove(lock); }
                });
                // bound anywhere, or RESERVED by a live pending invite (an expired one is free)
                long now = Time.currentTimeMillis();
                if (session.users().searchForUserByUserAttributeStream(realm, cardAttr, edipi).findAny().isPresent()
                        || session.users().searchForUserByUserAttributeStream(realm, cardAttr + AccountsPolicy.PENDING_SUFFIX, edipi)
                               .anyMatch(x -> !AccountsPolicy.pendingExpired(x.getCreatedTimestamp(),
                                       PendingInviteLink.markerTime(x.getFirstAttribute(CREATED_BY)), now))) {
                    refused("create", "card " + AccountsPolicy.maskEdipi(edipi) + " already bound or reserved by a pending invite: " + username);
                    return err(Response.Status.CONFLICT, conflict);
                }
            }
            UserModel u = session.users().addUser(realm, username);
            u.setEnabled(true); u.setEmail(email); u.setEmailVerified(false); u.setFirstName(first); u.setLastName(last);
            if (viaProvider || viaCard) {
                u.addRequiredAction("TERMS_AND_CONDITIONS");          // no password, no OTP: the provider / the card signs in
            } else {
                SETUP_ACTIONS.forEach(u::addRequiredAction);
            }
            if (viaProvider) u.setSingleAttribute(PendingInviteLink.PENDING_MARKER, PendingInviteLink.PENDING_VALUE);
            // a card account: the card is bound here, server-side (the delegate never writes the attribute). Accepted
            // risk: a delegate may name their OWN card for a new account - it reaches nothing beyond the delegation they
            // already hold, and stig_created_by attributes the account to them.
            // Entra + card: the card is NOT bound here. It is only NAMED (pending), and bound when the account holder,
            // after their first Entra sign-in, presents that very card (PresentCardRequiredAction) - so a delegate who
            // names their own card for someone else's account gets nothing.
            if (viaCard && !viaProvider) u.setSingleAttribute(cardAttr, edipi);
            if (viaCard && viaProvider) u.setSingleAttribute(cardAttr + AccountsPolicy.PENDING_SUFFIX, edipi);
            u.setSingleAttribute(AccountsPolicy.SIGNIN_METHODS, signIn);
            u.joinGroup(g);
            u.setSingleAttribute(CREATED_BY, caller() + " " + Time.currentTimeMillis());   // read by the operator's tooling
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("id", u.getId()); rep.put("username", username); rep.put("email", email); rep.put("group", g.getId());
            if (viaProvider || viaCard) rep.put("signIn", methods.size() == 1 ? methods.get(0) : methods);
            if (viaCard) rep.put("card", AccountsPolicy.maskEdipi(edipi));
            if (ref != null) rep.put("reference", ref);
            adminEvent.operation(OperationType.CREATE).resource(ResourceType.USER).resourcePath("users", u.getId()).representation(rep).success();
            LOG.infof("STIG-ACCOUNTS created realm=%s caller=%s user=%s group=%s%s%s", realm.getName(), caller(), username, groupPath,
                    (viaCard || viaProvider ? " signIn=" + signIn : "") + (viaCard ? " card=" + AccountsPolicy.maskEdipi(edipi) : ""), refSuffix(ref));
            Map<String, Object> out = new LinkedHashMap<>(rep);
            if (viaProvider || viaCard) {
                out.put("setupEmail", "none");                       // nothing to set up: the provider / the card signs in
            } else {
                out.put("setupEmail", sendSetup(u, lifespan, ref) ? "sent" : "failed");
            }
            return Response.status(Response.Status.CREATED).entity(out).type(MediaType.APPLICATION_JSON).build();
        }

        @POST @Path("users/{id}/setup-email")
        public Response resend(@PathParam("id") String id, @QueryParam("lifespan") Integer lifespanQ,
                               @QueryParam("reference") String refQ) {
            String ref = AccountsPolicy.reference(refQ);
            if ("".equals(ref)) return err(Response.Status.BAD_REQUEST, "reference must be 1-64 of A-Z a-z 0-9 . _ : -");
            UserModel u = target(id, "setup-email");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            int lifespan = AccountsPolicy.lifespan(lifespanQ);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..86400 seconds");
            if (u.getEmail() == null || u.getEmail().isBlank()) return err(Response.Status.BAD_REQUEST, "the account has no e-mail address");
            // only while the account is still being set up: no password, OTP or WebAuthn yet, set-up actions pending
            if (u.getFirstAttribute(PendingInviteLink.PENDING_MARKER) != null) {
                return err(Response.Status.CONFLICT, "the account signs in through the identity provider: there is no set-up mail");
            }
            String ca = AccountsPolicy.cardAttribute(realm.getAttribute(AccountsPolicy.CARD_ATTRIBUTE));
            if (ca != null && u.getFirstAttribute(ca) != null) {
                return err(Response.Status.CONFLICT, "the account signs in with a card: there is no set-up mail");
            }
            boolean hasCredential = u.credentialManager().getStoredCredentialsStream().findAny().isPresent();
            List<String> pending = u.getRequiredActionsStream().collect(Collectors.toList());
            if (hasCredential || !pending.contains("UPDATE_PASSWORD") || !pending.contains("CONFIGURE_TOTP")) {
                refused("setup-email", "account " + u.getUsername() + " is already set up");
                return err(Response.Status.CONFLICT, "the account is already set up");
            }
            if (session.singleUseObjects().contains("stig-accounts-setup:" + u.getId())) {
                return err(Response.Status.TOO_MANY_REQUESTS, "a set-up e-mail went to this account less than 15 minutes ago");
            }
            if (!sendSetup(u, lifespan, ref)) return err(Response.Status.BAD_GATEWAY, "the e-mail could not be sent");
            LOG.infof("STIG-ACCOUNTS setup-email realm=%s caller=%s user=%s%s", realm.getName(), caller(), u.getUsername(), refSuffix(ref));
            return Response.noContent().build();
        }

        @POST @Path("users/{id}/disable")
        public Response disable(@PathParam("id") String id, @QueryParam("reference") String refQ) {
            String ref = AccountsPolicy.reference(refQ);
            if ("".equals(ref)) return err(Response.Status.BAD_REQUEST, "reference must be 1-64 of A-Z a-z 0-9 . _ : -");
            UserModel u = target(id, "disable");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            if (!u.isEnabled()) return Response.noContent().build();          // already disabled: nothing to do
            if (!underRate("disable", AccountsPolicy.DISABLE_PER_HOUR)) {
                refused("disable", "more than " + AccountsPolicy.DISABLE_PER_HOUR + " accounts disabled in an hour");
                return err(Response.Status.TOO_MANY_REQUESTS, "too many accounts disabled this hour");
            }
            u.setEnabled(false);
            session.users().setNotBeforeForUser(realm, u, Time.currentTime());
            session.sessions().getUserSessionsStream(realm, u).collect(Collectors.toList())
                   .forEach(s -> AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(),
                           session.getContext().getConnection(), session.getContext().getRequestHeaders(), true));
            Map<String, Object> drep = new LinkedHashMap<>(); drep.put("enabled", false);
            if (ref != null) drep.put("reference", ref);
            adminEvent.operation(OperationType.UPDATE).resource(ResourceType.USER).resourcePath("users", u.getId())
                    .representation(drep).success();
            LOG.infof("STIG-ACCOUNTS disabled realm=%s caller=%s user=%s%s", realm.getName(), caller(), u.getUsername(), refSuffix(ref));
            return Response.noContent().build();
        }

        // ---------------------------------------------------------------- the portal operations (see the class doc)

        /** A checked portal request: a refusal to answer with, or the target account and the caller's reference. */
        private record Pre(Response refused, UserModel user, String ref) { }

        private ClientModel client() { return auth.adminAuth().getClient(); }

        /** The 401 a write with a stale authentication gets (the same challenge AdminApiGuardFilter sends). */
        private Response stepUp() {
            ClientModel c = client();
            int max = Math.max(AdminApiStepUp.maxAge(c == null ? null : c.getAttribute(AdminApiStepUp.MAX_AGE_ATTR)), AdminApiStepUp.MIN_MAX_AGE);
            return Response.status(Response.Status.UNAUTHORIZED).header("WWW-Authenticate", AdminApiStepUp.challenge(max))
                    .header("Access-Control-Expose-Headers", AdminApiStepUp.EXPOSE_HEADERS)
                    .entity(Map.of("error", "insufficient_user_authentication")).type(MediaType.APPLICATION_JSON).build();
        }

        /** Every portal operation starts here: the caller's client is an onboarding client listing `op` (else 403), a
         *  write's authentication is recent enough (else 401 - checked here as well as in AdminApiGuardFilter, so a path
         *  the filter classified differently still cannot skip it), the reference is valid (else 400), and the target is
         *  an account the caller manages that is no administrator (else 403, the same answer as for no such account). */
        private Pre pre(String op, String id, String refQ, boolean write) {
            ClientModel c = client();
            String why = AccountsPolicy.portalRefusal(c == null ? null : c.getAttribute(AdminApiStepUp.PROFILE_ATTR),
                    c == null ? null : c.getAttribute(AdminApiStepUp.OPS_ATTR), op);
            if (why != null) { refused(op, why); return new Pre(err(Response.Status.FORBIDDEN, "not allowed"), null, null); }
            if (write) {
                Long at = auth.adminAuth().getToken() == null ? null : auth.adminAuth().getToken().getAuth_time();
                if (!AdminApiStepUp.fresh(at, AdminApiStepUp.maxAge(c.getAttribute(AdminApiStepUp.MAX_AGE_ATTR)), Time.currentTime())) {
                    refused(op, "the authentication behind the token is older than the client's max-auth-age");
                    return new Pre(stepUp(), null, null);
                }
            }
            String ref = AccountsPolicy.reference(refQ);
            if ("".equals(ref)) return new Pre(err(Response.Status.BAD_REQUEST, "reference must be 1-64 of A-Z a-z 0-9 . _ : -"), null, null);
            UserModel u = target(id, op);
            if (u == null) return new Pre(err(Response.Status.FORBIDDEN, "not allowed"), null, null);
            return new Pre(null, u, ref);
        }

        /** One portal write's rate slot (20 per caller and operation in any 60 minutes); false: refused (logged). */
        private boolean portalRate(String op) {
            if (underRate("portal-" + op, AccountsPolicy.PORTAL_OPS_PER_HOUR)) return true;
            refused(op, "more than " + AccountsPolicy.PORTAL_OPS_PER_HOUR + " in an hour");
            return false;
        }

        /** The admin event (ACTION users/{id}/<op>) and the audit line of a portal write; `details` never holds an
         *  unmasked card number. */
        private void audited(String op, UserModel u, Map<String, Object> details, String ref) {
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("stig", "portal " + op);
            rep.putAll(details);
            if (ref != null) rep.put("reference", ref);
            adminEvent.operation(OperationType.ACTION).resource(ResourceType.USER).resourcePath("users", u.getId(), op)
                    .representation(rep).success();
            StringBuilder d = new StringBuilder();
            details.forEach((k, v) -> d.append(' ').append(k).append('=').append(v));
            LOG.infof("STIG-ACCOUNTS %s realm=%s caller=%s user=%s%s%s", op, realm.getName(), caller(), u.getUsername(), d, refSuffix(ref));
        }

        private static Response ok(Map<String, Object> body) {
            return Response.ok(body).type(MediaType.APPLICATION_JSON).build();
        }

        private static boolean hasCredential(UserModel u, String type) {
            return u.credentialManager().getStoredCredentialsByTypeStream(type).findAny().isPresent();
        }

        @POST @Path("users/{id}/reset-otp")
        public Response resetOtp(@PathParam("id") String id, @QueryParam("reference") String refQ) {
            Pre p = pre("reset-otp", id, refQ, true);
            if (p.refused() != null) return p.refused();
            UserModel u = p.user();
            if (!u.isEnabled()) return err(Response.Status.CONFLICT, "the account is disabled");
            if (!hasCredential(u, PasswordCredentialModel.TYPE)) {
                refused("reset-otp", "account " + u.getUsername() + " does not sign in with a password and an authenticator");
                return err(Response.Status.CONFLICT, "the account does not sign in with a password and an authenticator");
            }
            if (!portalRate("reset-otp")) return err(Response.Status.TOO_MANY_REQUESTS, "too many authenticator resets this hour");
            List<String> ids = u.credentialManager().getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .map(org.keycloak.credential.CredentialModel::getId).collect(Collectors.toList());
            ids.forEach(u.credentialManager()::removeStoredCredentialById);
            u.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            audited("reset-otp", u, new LinkedHashMap<>(Map.of("removed", ids.size(), "requiredAction", "CONFIGURE_TOTP")), p.ref());
            return ok(Map.of("removed", ids.size()));
        }

        @POST @Path("users/{id}/reset-password")
        public Response resetPassword(@PathParam("id") String id, @QueryParam("lifespan") Integer lifespanQ,
                                      @QueryParam("reference") String refQ) {
            Pre p = pre("reset-password", id, refQ, true);
            if (p.refused() != null) return p.refused();
            UserModel u = p.user();
            int lifespan = AccountsPolicy.lifespan(lifespanQ);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..86400 seconds");
            if (!u.isEnabled()) return err(Response.Status.CONFLICT, "the account is disabled");
            if (u.getEmail() == null || u.getEmail().isBlank()) return err(Response.Status.CONFLICT, "the account has no e-mail address");
            if (!hasCredential(u, PasswordCredentialModel.TYPE)) {
                refused("reset-password", "account " + u.getUsername() + " has no password");
                return err(Response.Status.CONFLICT, "the account has no password (an account still being set up: setup-email)");
            }
            String once = "stig-accounts-reset-password:" + u.getId();
            if (session.singleUseObjects().contains(once)) {
                return err(Response.Status.TOO_MANY_REQUESTS, "a password reset e-mail went to this account less than 15 minutes ago");
            }
            if (!portalRate("reset-password")) return err(Response.Status.TOO_MANY_REQUESTS, "too many password resets this hour");
            // claimed atomically before the mail: two concurrent requests cannot both send one
            if (!session.singleUseObjects().putIfAbsent(once, AccountsPolicy.RESEND_INTERVAL)) {
                return err(Response.Status.TOO_MANY_REQUESTS, "a password reset e-mail went to this account less than 15 minutes ago");
            }
            if (!sendActions(u, List.of(UserModel.RequiredAction.UPDATE_PASSWORD.name()), lifespan)) {
                session.singleUseObjects().remove(once);             // nothing was sent: the person may be sent one again
                return err(Response.Status.BAD_GATEWAY, "the e-mail could not be sent");
            }
            audited("reset-password", u, new LinkedHashMap<>(Map.of("actions", List.of("UPDATE_PASSWORD"), "email", "sent")), p.ref());
            return ok(Map.of("email", "sent"));
        }

        @POST @Path("users/{id}/unlock")
        public Response unlock(@PathParam("id") String id, @QueryParam("reference") String refQ) {
            Pre p = pre("unlock", id, refQ, true);
            if (p.refused() != null) return p.refused();
            UserModel u = p.user();
            if (!u.isEnabled()) {
                refused("unlock", "account " + u.getUsername() + " is disabled");
                return err(Response.Status.CONFLICT, "the account is disabled (by an administrator, or a permanent lockout): re-enabling is for IdP administrators");
            }
            if (!portalRate("unlock")) return err(Response.Status.TOO_MANY_REQUESTS, "too many unlocks this hour");
            BruteForceProtector bp = session.getProvider(BruteForceProtector.class);
            boolean locked = bp != null && bp.isTemporarilyDisabled(session, realm, u);
            if (!locked) {
                // not locked: a no-op. The failure count is NOT cleared - clearing it would hand a password guesser a
                // fresh set of attempts before the lockout - and no admin event is written for a change that did not happen
                LOG.infof("STIG-ACCOUNTS unlock realm=%s caller=%s user=%s wasLocked=false (nothing changed)%s", realm.getName(),
                        caller(), u.getUsername(), refSuffix(p.ref()));
                return ok(Map.of("wasLocked", false));
            }
            session.loginFailures().removeUserLoginFailure(realm, u.getId());
            audited("unlock", u, new LinkedHashMap<>(Map.of("wasLocked", true)), p.ref());
            return ok(Map.of("wasLocked", true));
        }

        @POST @Path("users/{id}/logout")
        public Response logout(@PathParam("id") String id, @QueryParam("reference") String refQ) {
            Pre p = pre("logout", id, refQ, true);
            if (p.refused() != null) return p.refused();
            UserModel u = p.user();
            if (!portalRate("logout")) return err(Response.Status.TOO_MANY_REQUESTS, "too many sign-outs this hour");
            // as Keycloak's own POST users/{id}/logout: tokens issued before now are refused, and every session ends
            session.users().setNotBeforeForUser(realm, u, Time.currentTime());
            List<org.keycloak.models.UserSessionModel> ss = session.sessions().getUserSessionsStream(realm, u).collect(Collectors.toList());
            ss.forEach(s -> AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(),
                    session.getContext().getConnection(), session.getContext().getRequestHeaders(), true));
            audited("logout", u, new LinkedHashMap<>(Map.of("sessionsEnded", ss.size())), p.ref());
            return ok(Map.of("sessionsEnded", ss.size()));
        }

        /** The attribute the realm's X.509 step maps cards by (what the present-card step binds), or null. */
        private String x509CardAttribute() {
            org.keycloak.models.AuthenticatorConfigModel cfg = PresentCardRequiredAction.x509Config(realm);
            return cfg == null || cfg.getConfig() == null ? null
                    : AccountsPolicy.cardAttribute(cfg.getConfig().get(PresentCardRequiredAction.USER_ATTR_KEY));
        }

        /** A link-cac body: none or blank (= {}), else a JSON object; null when it is anything else. */
        @SuppressWarnings("unchecked")
        static Map<String, Object> linkBody(String raw) {
            if (raw == null || raw.isBlank()) return Map.of();
            try {
                Object o = org.keycloak.util.JsonSerialization.readValue(raw, Object.class);
                return o instanceof Map ? (Map<String, Object>) o : null;
            } catch (java.io.IOException | RuntimeException e) {
                return null;
            }
        }

        @POST @Path("users/{id}/link-cac") @Consumes(MediaType.WILDCARD)
        public Response linkCac(@PathParam("id") String id, @QueryParam("reference") String refQ, String rawBody) {
            Pre p = pre("link-cac", id, refQ, true);
            if (p.refused() != null) return p.refused();
            UserModel u = p.user();
            Map<String, Object> body = linkBody(rawBody);
            if (body == null) return err(Response.Status.BAD_REQUEST, "the body is {} or {\"edipi\": \"<10 digits>\"}");
            if (body != null && !java.util.Set.of("edipi").containsAll(body.keySet())) {
                return err(Response.Status.BAD_REQUEST, "the only field is edipi");
            }
            Object eb = body == null ? null : body.get("edipi");
            if (eb != null && !(eb instanceof String)) return err(Response.Status.BAD_REQUEST, "edipi must be exactly 10 digits");
            String edipi = eb == null ? null : ((String) eb).trim();
            if (edipi != null && !AccountsPolicy.validEdipi(edipi)) return err(Response.Status.BAD_REQUEST, "edipi must be exactly 10 digits");
            String ca = x509CardAttribute();
            org.keycloak.models.RequiredActionProviderModel ra = realm.getRequiredActionProviderByAlias(PresentCardRequiredAction.ID);
            if (ca == null || !PresentCardRequiredAction.linkGuarded(session) || ra == null || !ra.isEnabled()) {
                refused("link-cac", "the realm is not set up for link requests (X.509 step's card attribute "
                        + ca + ", link attribute guarded " + PresentCardRequiredAction.linkGuarded(session) + ", present-card step "
                        + (ra == null ? "absent" : ra.isEnabled() ? "enabled" : "disabled") + ")");
                return err(Response.Status.FORBIDDEN, "this realm does not take card link requests");
            }
            String pendingAttr = ca + AccountsPolicy.PENDING_SUFFIX;
            String link = u.getFirstAttribute(AccountsPolicy.LINK_ATTRIBUTE);
            boolean canSignIn = hasCredential(u, PasswordCredentialModel.TYPE) || u.getFirstAttribute(StigBindingsResourceProviderFactory.ENTRA) != null
                    || session.users().getFederatedIdentitiesStream(realm, u).findAny().isPresent();
            long nowMs = Time.currentTimeMillis();
            boolean hasLink = link != null && !link.isBlank();
            boolean liveLink = hasLink && AccountsPolicy.linkLive(AccountsPolicy.linkTime(link), nowMs);
            String pending = u.getFirstAttribute(pendingAttr);
            boolean liveInvite = !hasLink && pending != null && !pending.isBlank() && !AccountsPolicy.pendingExpired(u.getCreatedTimestamp(),
                    PendingInviteLink.markerTime(u.getFirstAttribute(CREATED_BY)), nowMs);
            String why = AccountsPolicy.portalLinkRefusal(u.isEnabled(), u.getFirstAttribute(ca), liveLink, liveInvite, canSignIn);
            if (why != null) {
                refused("link-cac", "account " + u.getUsername() + ": " + why);
                return err(Response.Status.CONFLICT, why);
            }
            if (!portalRate("link-cac")) return err(Response.Status.TOO_MANY_REQUESTS, "too many card link requests this hour");
            if (edipi != null) {
                // the same claim stig-accounts' card creates, stig-bindings and the present-card step take: one card, one account
                String key = "stig-accounts-card:" + realm.getId() + ":" + edipi;
                if (!session.singleUseObjects().putIfAbsent(key, 60)) {
                    refused("link-cac", "card " + AccountsPolicy.maskEdipi(edipi) + " is being bound elsewhere right now: " + u.getUsername());
                    return err(Response.Status.CONFLICT, "that card is already bound to or reserved for another account");
                }
                AccountsPolicy.releaseAfterCompletion(session, key);
                for (String a : List.of(ca, pendingAttr)) {
                    if (session.users().searchForUserByUserAttributeStream(realm, a, edipi).anyMatch(x -> !x.getId().equals(u.getId()))) {
                        refused("link-cac", "card " + AccountsPolicy.maskEdipi(edipi) + " is bound to or reserved for another account: " + u.getUsername());
                        return err(Response.Status.CONFLICT, "that card is already bound to or reserved for another account");
                    }
                }
            }
            // a link request as the operator's tool writes it ("<epoch-ms>"; the account is never an administrator here,
            // so never "<epoch-ms> admin"), replacing an earlier request of the account; the present-card step does the rest
            u.setSingleAttribute(AccountsPolicy.LINK_ATTRIBUTE, String.valueOf(Time.currentTimeMillis()));
            if (edipi != null) u.setSingleAttribute(pendingAttr, edipi); else u.removeAttribute(pendingAttr);
            u.addRequiredAction(PresentCardRequiredAction.ID);
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("card", edipi == null ? "any" : AccountsPolicy.maskEdipi(edipi));
            d.put("replacesExpired", hasLink || (pending != null && !pending.isBlank()));
            audited("link-cac", u, d, p.ref());
            return ok(Map.of("requested", true, "card", edipi == null ? "any" : "named", "days", AccountsPolicy.LINK_DAYS));
        }

        /** One account's status (AccountsPolicy.statusView): booleans and a count, nothing else. */
        private Map<String, Object> status(UserModel u) {
            BruteForceProtector bp = session.getProvider(BruteForceProtector.class);
            boolean locked = bp != null && (bp.isTemporarilyDisabled(session, realm, u) || bp.isPermanentlyLockedOut(session, realm, u));
            String ca = x509CardAttribute();
            if (ca == null) ca = AccountsPolicy.cardAttribute(realm.getAttribute(AccountsPolicy.CARD_ATTRIBUTE));
            String card = ca == null ? null : u.getFirstAttribute(ca);
            return AccountsPolicy.statusView(u.getId(), u.getUsername(), u.isEnabled(), locked,
                    hasCredential(u, PasswordCredentialModel.TYPE), hasCredential(u, OTPCredentialModel.TYPE),
                    card != null && !card.isBlank(), PresentCardRequiredAction.request(session, realm, u, Time.currentTimeMillis()) != null,
                    session.users().getFederatedIdentitiesStream(realm, u).findAny().isPresent(),
                    session.sessions().getUserSessionsStream(realm, u).count());
        }

        @GET @Path("users/{id}/status")
        public Response statusOne(@PathParam("id") String id) {
            Pre p = pre("status", id, null, false);
            if (p.refused() != null) return p.refused();
            if (!statusRate()) return err(Response.Status.TOO_MANY_REQUESTS, "too many status calls this minute");
            LOG.infof("STIG-ACCOUNTS status realm=%s caller=%s user=%s", realm.getName(), caller(), p.user().getUsername());
            return ok(status(p.user()));
        }

        @GET @Path("users/status")
        public Response statusMany(@QueryParam("id") List<String> ids) {
            ClientModel c = client();
            String why = AccountsPolicy.portalRefusal(c == null ? null : c.getAttribute(AdminApiStepUp.PROFILE_ATTR),
                    c == null ? null : c.getAttribute(AdminApiStepUp.OPS_ATTR), "status");
            if (why != null) { refused("status", why); return err(Response.Status.FORBIDDEN, "not allowed"); }
            List<String> want = AccountsPolicy.statusIds(ids);
            if (want == null) return err(Response.Status.BAD_REQUEST, "id: 1.." + AccountsPolicy.STATUS_MAX + " account ids");
            if (!statusRate()) return err(Response.Status.TOO_MANY_REQUESTS, "too many status calls this minute");
            List<Map<String, Object>> out = new ArrayList<>(); List<String> no = new ArrayList<>();
            for (String i : want) {
                UserModel u = target(i, "status");
                if (u == null) no.add(i); else out.add(status(u));
            }
            LOG.infof("STIG-ACCOUNTS status realm=%s caller=%s accounts=%d refused=%d", realm.getName(), caller(), out.size(), no.size());
            return ok(Map.of("accounts", out, "refused", no));
        }

        // Nothing else: every other method or path is refused, not merely absent.
        @GET @Path("{any: .*}") public Response g() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @GET public Response g0() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @POST @Path("{any: .*}") public Response p() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @PUT @Path("{any: .*}") public Response u() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @DELETE @Path("{any: .*}") public Response d() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @PATCH @Path("{any: .*}") public Response pa() { return err(Response.Status.FORBIDDEN, "not allowed"); }
    }
}
