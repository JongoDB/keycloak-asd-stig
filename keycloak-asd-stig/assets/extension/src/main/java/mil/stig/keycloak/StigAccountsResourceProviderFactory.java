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
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;
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
 *   POST /users                      {username first.last, email, firstName, lastName, group "/app/ROLE"[, lifespan]
 *                                     [, organization <id>][, onBehalfOf "<sub> <username>"]}
 *                                    create into a group the caller may manage the membership of, e-mail the set-up link
 *                                    (the realm's set-up actions - default password, TOTP, terms; at most 24 h).
 *                                    201 {id, username, setupEmail}
 *   POST /users/{id}/setup-email     re-send the set-up link to the address ON RECORD, only while the account is still
 *                                    being set up (no credential, credential set-up actions pending; else 409); once per
 *                                    15 min. 204
 *   POST /users/{id}/disable         disable a member and end its sessions (back-channel). 204. There is NO enable:
 *                                    re-enabling is for realm administrators only (console, idp-admin.py user-enable),
 *                                    except reactivate below.
 *   POST /users/{id}/recover         (only where the operator enabled it) remove the member's passkeys, end its sessions
 *                                    and mail a fresh set-up link to the address ON RECORD (1 h; once per 24 h). 204
 *   POST /users/{id}/reactivate      (only where the operator enabled it) re-enable a member the INACTIVITY WORKFLOW
 *                                    disabled (stig_disabled_by=inactivity), and restart that workflow for it. 204
 *   anything else                    403
 * Every call takes an optional onBehalfOf (body on create, query parameter elsewhere): who the calling application says
 * asked. It is recorded in the admin event and in stig_created_by, marked as asserted by the caller - never trusted.
 *
 * Per-realm switches live in MASTER-realm attributes (the operator's tooling writes them; a realm's own administrators
 * cannot): stig.accounts.setup-actions.<realm> (U1), stig.accounts.recover.<realm>=true (U3),
 * stig.accounts.reactivate.<realm>=true (U4). E-mail domains: the caller client's stig.accounts.email-domains, else the
 * realm's, else .mil and defconai.com ("*" = any), minus the realm's stig.accounts.email-domains-deny (U2); with an
 * organization, the address must be in THAT organization's domains, and the organization must be listed in the caller
 * client's stig.accounts.organizations (U7).
 *
 * Authorisation is Keycloak's own: the admin API's token checks (audience, admin scope) and the realm's fine-grained
 * evaluator - Groups `manage-membership` on the target group, and on EVERY group of an existing target. Never an
 * administrator (any realm-management role, or a group carrying one) as a target or a group. Refused: a username or
 * e-mail address already in use (409), a malformed one (400). Every call writes an admin event attributed to the caller.
 */
public class StigAccountsResourceProviderFactory implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    public static final String ID = "stig-accounts";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");
    static final List<String> SETUP_ACTIONS = AccountsPolicy.DEFAULT_SETUP_ACTIONS;
    static final String SETUP_ACTIONS_ATTR = "stig.accounts.setup-actions.", RECOVER_ATTR = "stig.accounts.recover.",
            REACTIVATE_ATTR = "stig.accounts.reactivate.";
    static final String EMAIL_DOMAINS_DENY = "stig.accounts.email-domains-deny", ORGANIZATIONS = "stig.accounts.organizations";
    /** Set by the inactivity workflow (kcstig accounts.disabled_marker) just before it disables an account. */
    static final String DISABLED_MARKER = "stig_disabled_by", INACTIVITY = "inactivity";
    static final String INACTIVITY_WORKFLOW_PREFIX = "stig-disable-inactive-";
    /** Recorded on every account this endpoint creates: such an account is never made an administrator without a
     *  credential reset and an operator-set e-mail address (the operator's tooling enforces it). */
    static final String CREATED_BY = "stig_created_by";
    /** Client (for a service-account caller) or realm attribute: comma list of e-mail domains; default .mil,defconai.com. */
    static final String EMAIL_DOMAINS = "stig.accounts.email-domains";

    @Override public AdminRealmResourceProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    /** Only callers holding this realm-management role (the IdP's user managers) may use the endpoint at all; an
     *  application's fine-grained-only delegate (e.g. LogC2's) is refused everything, whatever its group scopes. */
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
         *  membership the caller manages, none carrying administrator rights, and not an administrator itself. */
        private UserModel target(String id, String op) {
            UserModel u = id == null ? null : session.users().getUserById(realm, id);
            if (u == null || u.getServiceAccountClientLink() != null) { refused(op, "no such account " + id); return null; }
            List<GroupModel> gs = u.getGroupsStream().collect(Collectors.toList());
            if (gs.isEmpty() || StigAdministrators.isAdministrator(realm, u)
                    || gs.stream().anyMatch(g -> StigAdministrators.groupCarriesAdmin(realm, g) || !auth.groups().canManageMembership(g))) {
                refused(op, "account " + u.getUsername() + " is an administrator or outside the caller's groups");
                return null;
            }
            return u;
        }

        private boolean profileNameValid(String value, String field) {
            org.keycloak.validate.Validator v = org.keycloak.validate.Validators.validator(session, "person-name-prohibited-characters");
            if (v == null) return true;     // the user-profile validator is not available: AccountsPolicy.validName still applies
            return v.validate(value, field, new org.keycloak.validate.ValidationContext(session), org.keycloak.validate.ValidatorConfig.EMPTY).isValid();
        }

        private ClientModel callerClient() {
            UserModel cu = auth.adminAuth().getUser();
            String link = cu == null ? null : cu.getServiceAccountClientLink();
            return link == null ? null : realm.getClientById(link);
        }

        /** A master-realm attribute keyed by this realm: only the operator's tooling can write it. */
        private String masterAttr(String prefix) {
            RealmModel master = session.realms().getRealmByName(Config.getAdminRealm());
            return master == null ? null : master.getAttribute(prefix + realm.getName());
        }
        private boolean enabledByOperator(String prefix) { return "true".equals(masterAttr(prefix)); }

        /** The realm's set-up actions; null when the operator's value cannot be read (callers refuse). */
        private List<String> setupActions() { return AccountsPolicy.parseSetupActions(masterAttr(SETUP_ACTIONS_ATTR)); }

        private static String asserted(String onBehalfOf) { return onBehalfOf + " (asserted by caller)"; }

        private void endSessions(UserModel u) {
            session.users().setNotBeforeForUser(realm, u, Time.currentTime());
            session.sessions().getUserSessionsStream(realm, u).collect(Collectors.toList())
                   .forEach(s -> AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(),
                           session.getContext().getConnection(), session.getContext().getRequestHeaders(), true));
        }

        private org.keycloak.organization.OrganizationProvider organizations() {
            if (session.getContext().getRealm() == null || !realm.getId().equals(session.getContext().getRealm().getId())) {
                session.getContext().setRealm(realm);
            }
            return session.getProvider(org.keycloak.organization.OrganizationProvider.class);
        }

        private String emailDomains() {
            ClientModel c = callerClient();
            String v = c == null ? null : c.getAttribute(EMAIL_DOMAINS);
            if (v == null || v.isBlank()) v = realm.getAttribute(EMAIL_DOMAINS);
            return v == null || v.isBlank() ? AccountsPolicy.DEFAULT_EMAIL_DOMAINS : v;
        }

        /** At most CREATE_PER_HOUR creations per caller per clock hour, atomically: each creation claims one of the
         *  hour's numbered slots with putIfAbsent (atomic in the cluster cache); with every slot taken it is refused. */
        private boolean underRate() {
            UserModel cu = auth.adminAuth().getUser();
            String base = "stig-accounts-create:" + (cu == null ? "?" : cu.getId()) + ":" + (Time.currentTime() / 3600) + ":";
            org.keycloak.models.SingleUseObjectProvider so = session.singleUseObjects();
            for (int i = 0; i < AccountsPolicy.CREATE_PER_HOUR; i++) {
                if (so.putIfAbsent(base + i, 3700)) return true;
            }
            return false;
        }

        private boolean sendSetup(UserModel u, int lifespan, List<String> actions) {
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
                session.singleUseObjects().put("stig-accounts-setup:" + u.getId(), AccountsPolicy.RESEND_INTERVAL, Map.of("t", "1"));
                adminEvent.operation(OperationType.ACTION).resource(ResourceType.USER)
                        .resourcePath("users", u.getId(), "execute-actions-email").success();
                return true;
            } catch (EmailException e) {
                LOG.warnf("STIG-ACCOUNTS set-up e-mail to %s failed: %s", u.getUsername(), e.getMessage());
                return false;
            }
        }

        @POST @Path("users") @Consumes(MediaType.APPLICATION_JSON)
        public Response create(Map<String, Object> body, @QueryParam("lifespan") Integer lifespanQ, @QueryParam("onBehalfOf") String onBehalfOfQ) {
            String username = str(body, "username"), email = str(body, "email"), first = str(body, "firstName"),
                   last = str(body, "lastName"), groupPath = str(body, "group"), orgId = str(body, "organization"),
                   onBehalfOf = str(body, "onBehalfOf");
            Integer lifespanB = body != null && body.get("lifespan") instanceof Number n ? n.intValue() : lifespanQ;
            if (!AccountsPolicy.validUsername(username)) return err(Response.Status.BAD_REQUEST, "username must be first.last in lower case");
            if (!AccountsPolicy.validEmail(email)) return err(Response.Status.BAD_REQUEST, "invalid e-mail address");
            if (!AccountsPolicy.validName(first) || !AccountsPolicy.validName(last) || !profileNameValid(first, "firstName") || !profileNameValid(last, "lastName")) {
                return err(Response.Status.BAD_REQUEST, "firstName and lastName are required: a person's name, no links or markup");
            }
            if (onBehalfOf == null) onBehalfOf = onBehalfOfQ == null ? null : onBehalfOfQ.trim();
            if (!AccountsPolicy.validOnBehalfOf(onBehalfOf)) return err(Response.Status.BAD_REQUEST, "onBehalfOf: 1-200 characters, letters, digits, . _ @ : + / = - and single spaces");
            List<String> actions = setupActions();
            if (actions == null) {
                refused("create", "the operator's set-up actions for this realm cannot be read");
                return err(Response.Status.SERVICE_UNAVAILABLE, "account set-up is not configured correctly for this realm");
            }
            org.keycloak.models.OrganizationModel vendorOrg = null;
            if (orgId != null) {
                // U7: only an organization the operator listed for this caller client, and the address in ITS domains
                ClientModel cc = callerClient();
                org.keycloak.organization.OrganizationProvider orgs = organizations();
                vendorOrg = orgs == null || !orgs.isEnabled() ? null : orgs.getById(orgId);
                if (cc == null || vendorOrg == null || !vendorOrg.isEnabled() || !AccountsPolicy.idList(cc.getAttribute(ORGANIZATIONS)).contains(orgId)) {
                    refused("create", "organization " + orgId + " is not one this caller may add members to");
                    return err(Response.Status.FORBIDDEN, "not allowed");
                }
                List<String> od = vendorOrg.getDomains().map(org.keycloak.models.OrganizationDomainModel::getName).collect(Collectors.toList());
                if (!AccountsPolicy.emailInDomains(email, od)) {
                    refused("create", "e-mail domain of " + email + " not one of organization " + vendorOrg.getAlias() + "'s domains");
                    return err(Response.Status.FORBIDDEN, "e-mail domain not allowed for this organization");
                }
            } else {
                String domains = emailDomains();
                if (!AccountsPolicy.emailDomainAllowed(email, domains)) {
                    refused("create", "e-mail domain of " + email + " not in " + domains);
                    return err(Response.Status.FORBIDDEN, "e-mail domain not allowed for this caller");
                }
            }
            if (AccountsPolicy.emailDomainDenied(email, realm.getAttribute(EMAIL_DOMAINS_DENY))) {
                refused("create", "e-mail domain of " + email + " is on the realm's denylist");
                return err(Response.Status.FORBIDDEN, "e-mail domain not allowed for this caller");
            }
            if (!underRate()) {
                refused("create", "more than " + AccountsPolicy.CREATE_PER_HOUR + " accounts in an hour");
                return err(Response.Status.TOO_MANY_REQUESTS, "too many accounts created this hour");
            }
            int lifespan = AccountsPolicy.lifespan(lifespanB);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..86400 seconds");
            GroupModel g = groupPath == null ? null : KeycloakModelUtils.findGroupByPath(session, realm, groupPath);
            if (g == null || StigAdministrators.groupCarriesAdmin(realm, g) || !auth.groups().canManageMembership(g)) {
                refused("create", "group " + groupPath + " is not one whose membership the caller manages");
                return err(Response.Status.FORBIDDEN, "not allowed");
            }
            if (session.users().getUserByUsername(realm, username) != null || session.users().getUserByEmail(realm, email) != null) {
                refused("create", "username or e-mail address already in use: " + username);
                return err(Response.Status.CONFLICT, "username or e-mail address already in use");
            }
            UserModel u = session.users().addUser(realm, username);
            u.setEnabled(true); u.setEmail(email); u.setEmailVerified(false); u.setFirstName(first); u.setLastName(last);
            actions.forEach(u::addRequiredAction);
            u.joinGroup(g);
            if (vendorOrg != null) organizations().addMember(vendorOrg, u);
            u.setSingleAttribute(CREATED_BY, caller() + " " + Time.currentTimeMillis()
                    + (onBehalfOf == null ? "" : " onBehalfOf=" + asserted(onBehalfOf)));   // read by the operator's tooling
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("id", u.getId()); rep.put("username", username); rep.put("email", email); rep.put("group", g.getId());
            if (vendorOrg != null) rep.put("organization", vendorOrg.getId());
            if (onBehalfOf != null) rep.put("onBehalfOf", asserted(onBehalfOf));
            adminEvent.operation(OperationType.CREATE).resource(ResourceType.USER).resourcePath("users", u.getId()).representation(rep).success();
            LOG.infof("STIG-ACCOUNTS created realm=%s caller=%s user=%s group=%s organization=%s onBehalfOf=%s", realm.getName(), caller(),
                    username, groupPath, vendorOrg == null ? "-" : vendorOrg.getAlias(), onBehalfOf == null ? "-" : asserted(onBehalfOf));
            boolean sent = sendSetup(u, lifespan, actions);
            Map<String, Object> out = new LinkedHashMap<>(rep); out.put("setupEmail", sent ? "sent" : "failed");
            return Response.status(Response.Status.CREATED).entity(out).type(MediaType.APPLICATION_JSON).build();
        }

        @POST @Path("users/{id}/setup-email")
        public Response resend(@PathParam("id") String id, @QueryParam("lifespan") Integer lifespanQ, @QueryParam("onBehalfOf") String onBehalfOf) {
            if (!AccountsPolicy.validOnBehalfOf(onBehalfOf)) return err(Response.Status.BAD_REQUEST, "invalid onBehalfOf");
            List<String> actions = setupActions();
            if (actions == null) return err(Response.Status.SERVICE_UNAVAILABLE, "account set-up is not configured correctly for this realm");
            UserModel u = target(id, "setup-email");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            int lifespan = AccountsPolicy.lifespan(lifespanQ);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..86400 seconds");
            if (u.getEmail() == null || u.getEmail().isBlank()) return err(Response.Status.BAD_REQUEST, "the account has no e-mail address");
            // only while the account is still being set up: no credential yet, its credential set-up actions pending
            boolean hasCredential = u.credentialManager().getStoredCredentialsStream().findAny().isPresent();
            List<String> pending = u.getRequiredActionsStream().collect(Collectors.toList());
            if (!AccountsPolicy.stillSettingUp(hasCredential, pending, actions)) {
                refused("setup-email", "account " + u.getUsername() + " is already set up");
                return err(Response.Status.CONFLICT, "the account is already set up");
            }
            if (session.singleUseObjects().contains("stig-accounts-setup:" + u.getId())) {
                return err(Response.Status.TOO_MANY_REQUESTS, "a set-up e-mail went to this account less than 15 minutes ago");
            }
            LOG.infof("STIG-ACCOUNTS setup-email realm=%s caller=%s user=%s onBehalfOf=%s", realm.getName(), caller(), u.getUsername(),
                    onBehalfOf == null ? "-" : asserted(onBehalfOf));
            return sendSetup(u, lifespan, actions) ? Response.noContent().build() : err(Response.Status.BAD_GATEWAY, "the e-mail could not be sent");
        }

        /** U3: a member who lost its passkey. Only where the operator enabled recovery for this realm; only an account
         *  whose credentials are all WebAuthn (a passkey account); once per 24 h; the link (1 h) goes to the address ON
         *  RECORD. Its passkeys are removed and its sessions end first, so the old device signs in nowhere, and until the
         *  link is used the account is refused at sign-in (stig-passkey-required). */
        @POST @Path("users/{id}/recover")
        public Response recover(@PathParam("id") String id, @QueryParam("lifespan") Integer lifespanQ, @QueryParam("onBehalfOf") String onBehalfOf) {
            if (!enabledByOperator(RECOVER_ATTR)) { refused("recover", "recovery is not enabled for this realm"); return err(Response.Status.FORBIDDEN, "not allowed"); }
            if (!AccountsPolicy.validOnBehalfOf(onBehalfOf)) return err(Response.Status.BAD_REQUEST, "invalid onBehalfOf");
            List<String> actions = setupActions();
            if (actions == null) return err(Response.Status.SERVICE_UNAVAILABLE, "account set-up is not configured correctly for this realm");
            UserModel u = target(id, "recover");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            int lifespan = AccountsPolicy.recoverLifespan(lifespanQ);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..3600 seconds");
            if (!u.isEnabled()) return err(Response.Status.CONFLICT, "the account is disabled");
            if (u.getEmail() == null || u.getEmail().isBlank()) return err(Response.Status.BAD_REQUEST, "the account has no e-mail address");
            List<org.keycloak.credential.CredentialModel> creds = u.credentialManager().getStoredCredentialsStream().collect(Collectors.toList());
            if (creds.stream().anyMatch(c -> !org.keycloak.models.credential.WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(c.getType())
                    && !org.keycloak.models.credential.WebAuthnCredentialModel.TYPE_TWOFACTOR.equals(c.getType()))) {
                refused("recover", "account " + u.getUsername() + " holds a credential that is not a passkey");
                return err(Response.Status.CONFLICT, "only a passkey account can be recovered here");
            }
            if (!session.singleUseObjects().putIfAbsent("stig-accounts-recover:" + u.getId(), AccountsPolicy.RECOVER_INTERVAL)) {
                return err(Response.Status.TOO_MANY_REQUESTS, "this account was recovered less than 24 hours ago");
            }
            creds.forEach(c -> u.credentialManager().removeStoredCredentialById(c.getId()));
            endSessions(u);
            u.setEmailVerified(false);
            actions.forEach(u::addRequiredAction);
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("recovered", true); rep.put("passkeysRemoved", creds.size());
            if (onBehalfOf != null) rep.put("onBehalfOf", asserted(onBehalfOf));
            adminEvent.operation(OperationType.ACTION).resource(ResourceType.USER).resourcePath("users", u.getId(), "recover")
                    .representation(rep).success();
            LOG.warnf("STIG-ACCOUNTS recovered realm=%s caller=%s user=%s passkeysRemoved=%d onBehalfOf=%s", realm.getName(), caller(),
                    u.getUsername(), creds.size(), onBehalfOf == null ? "-" : asserted(onBehalfOf));
            return sendSetup(u, lifespan, actions) ? Response.noContent().build() : err(Response.Status.BAD_GATEWAY, "the e-mail could not be sent");
        }

        /** U4: re-enable an account the INACTIVITY WORKFLOW disabled - never one disabled by disable, the guard or an
         *  administrator (no marker: the marker is set only by that workflow, and cleared at every sign-in and by disable).
         *  Only where the operator enabled it. The inactivity workflow is started again for the account, so a
         *  reactivated account that is not used is disabled again (V-222411); without that workflow it is refused. */
        @POST @Path("users/{id}/reactivate")
        public Response reactivate(@PathParam("id") String id, @QueryParam("onBehalfOf") String onBehalfOf) {
            if (!enabledByOperator(REACTIVATE_ATTR)) { refused("reactivate", "reactivation is not enabled for this realm"); return err(Response.Status.FORBIDDEN, "not allowed"); }
            if (!AccountsPolicy.validOnBehalfOf(onBehalfOf)) return err(Response.Status.BAD_REQUEST, "invalid onBehalfOf");
            UserModel u = target(id, "reactivate");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            if (u.isEnabled()) return err(Response.Status.CONFLICT, "the account is not disabled");
            if (!INACTIVITY.equals(u.getFirstAttribute(DISABLED_MARKER))) {
                refused("reactivate", "account " + u.getUsername() + " was not disabled by the inactivity workflow");
                return err(Response.Status.CONFLICT, "only an account disabled for inactivity can be reactivated here");
            }
            org.keycloak.models.workflow.WorkflowProvider wp = session.getProvider(org.keycloak.models.workflow.WorkflowProvider.class);
            List<org.keycloak.models.workflow.Workflow> wfs = wp == null ? List.of() : wp.getWorkflows()
                    .filter(w -> w.isEnabled() && w.getName() != null && w.getName().startsWith(INACTIVITY_WORKFLOW_PREFIX))
                    .collect(Collectors.toList());
            if (wfs.isEmpty()) {
                refused("reactivate", "no inactivity workflow in the realm: a reactivated account would never be disabled again");
                return err(Response.Status.CONFLICT, "the realm has no inactivity workflow");
            }
            u.setEnabled(true);
            u.removeAttribute(DISABLED_MARKER);
            wfs.forEach(w -> wp.activate(w, org.keycloak.models.workflow.ResourceType.USERS, u.getId()));
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("enabled", true); rep.put("reactivated", "inactivity");
            if (onBehalfOf != null) rep.put("onBehalfOf", asserted(onBehalfOf));
            adminEvent.operation(OperationType.UPDATE).resource(ResourceType.USER).resourcePath("users", u.getId())
                    .representation(rep).success();
            LOG.warnf("STIG-ACCOUNTS reactivated realm=%s caller=%s user=%s workflows=%s onBehalfOf=%s", realm.getName(), caller(), u.getUsername(),
                    wfs.stream().map(org.keycloak.models.workflow.Workflow::getName).collect(Collectors.toList()), onBehalfOf == null ? "-" : asserted(onBehalfOf));
            return Response.noContent().build();
        }

        @POST @Path("users/{id}/disable")
        public Response disable(@PathParam("id") String id, @QueryParam("onBehalfOf") String onBehalfOf) {
            if (!AccountsPolicy.validOnBehalfOf(onBehalfOf)) return err(Response.Status.BAD_REQUEST, "invalid onBehalfOf");
            UserModel u = target(id, "disable");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            u.removeAttribute(DISABLED_MARKER);       // disabled by a person now: never "for inactivity", even if it was
            if (!u.isEnabled()) return Response.noContent().build();          // already disabled: nothing more to do
            u.setEnabled(false);
            endSessions(u);
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("enabled", false);
            if (onBehalfOf != null) rep.put("onBehalfOf", asserted(onBehalfOf));
            adminEvent.operation(OperationType.UPDATE).resource(ResourceType.USER).resourcePath("users", u.getId())
                    .representation(rep).success();
            LOG.infof("STIG-ACCOUNTS disabled realm=%s caller=%s user=%s onBehalfOf=%s", realm.getName(), caller(), u.getUsername(),
                    onBehalfOf == null ? "-" : asserted(onBehalfOf));
            return Response.noContent().build();
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
