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
 * hold no `manage-members` (so they can never set or reset a password, touch credentials or identity-provider links,
 * change an e-mail address, send mail to an address of their choosing, or re-enable an account):
 *
 *   POST /users                      {username first.last, email, firstName, lastName, group "/app/ROLE"[, lifespan]}
 *                                    create into a group the caller may manage the membership of, e-mail the set-up link
 *                                    (password, TOTP, terms; at most 24 h). 201 {id, username, setupEmail}
 *   POST /users/{id}/setup-email     re-send the set-up link to the address ON RECORD, only while the account is still
 *                                    being set up (no credential, set-up actions pending; else 409); once per 15 min. 204
 *   POST /users/{id}/disable         disable a member and end its sessions (back-channel). 204. There is NO enable:
 *                                    re-enabling is for realm administrators only (console, idp-admin.py user-enable).
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

    @Override public AdminRealmResourceProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new Accounts(session, realm, auth, adminEvent);
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

        private boolean sendSetup(UserModel u, int lifespan) {
            ClientModel console = realm.getClientByClientId(Constants.ACCOUNT_CONSOLE_CLIENT_ID);
            String redirect = UriBuilder.fromUri(session.getContext().getUri().getBaseUri()).path("realms").path(realm.getName())
                    .path("account").path("/").build().toString();
            int expiration = Time.currentTime() + lifespan;
            ExecuteActionsActionToken token = new ExecuteActionsActionToken(u.getId(), u.getEmail(), expiration, SETUP_ACTIONS,
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
        public Response create(Map<String, Object> body, @QueryParam("lifespan") Integer lifespanQ) {
            String username = str(body, "username"), email = str(body, "email"), first = str(body, "firstName"),
                   last = str(body, "lastName"), groupPath = str(body, "group");
            Integer lifespanB = body != null && body.get("lifespan") instanceof Number n ? n.intValue() : lifespanQ;
            if (!AccountsPolicy.validUsername(username)) return err(Response.Status.BAD_REQUEST, "username must be first.last in lower case");
            if (!AccountsPolicy.validEmail(email)) return err(Response.Status.BAD_REQUEST, "invalid e-mail address");
            if (!AccountsPolicy.validName(first) || !AccountsPolicy.validName(last)) return err(Response.Status.BAD_REQUEST, "firstName and lastName are required");
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
            SETUP_ACTIONS.forEach(u::addRequiredAction);
            u.joinGroup(g);
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("id", u.getId()); rep.put("username", username); rep.put("email", email); rep.put("group", g.getId());
            adminEvent.operation(OperationType.CREATE).resource(ResourceType.USER).resourcePath("users", u.getId()).representation(rep).success();
            LOG.infof("STIG-ACCOUNTS created realm=%s caller=%s user=%s group=%s", realm.getName(), caller(), username, groupPath);
            boolean sent = sendSetup(u, lifespan);
            Map<String, Object> out = new LinkedHashMap<>(rep); out.put("setupEmail", sent ? "sent" : "failed");
            return Response.status(Response.Status.CREATED).entity(out).type(MediaType.APPLICATION_JSON).build();
        }

        @POST @Path("users/{id}/setup-email")
        public Response resend(@PathParam("id") String id, @QueryParam("lifespan") Integer lifespanQ) {
            UserModel u = target(id, "setup-email");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            int lifespan = AccountsPolicy.lifespan(lifespanQ);
            if (lifespan < 0) return err(Response.Status.BAD_REQUEST, "lifespan must be 300..86400 seconds");
            if (u.getEmail() == null || u.getEmail().isBlank()) return err(Response.Status.BAD_REQUEST, "the account has no e-mail address");
            // only while the account is still being set up: no password, OTP or WebAuthn yet, set-up actions pending
            boolean hasCredential = u.credentialManager().getStoredCredentialsStream().findAny().isPresent();
            List<String> pending = u.getRequiredActionsStream().collect(Collectors.toList());
            if (hasCredential || !pending.contains("UPDATE_PASSWORD") || !pending.contains("CONFIGURE_TOTP")) {
                refused("setup-email", "account " + u.getUsername() + " is already set up");
                return err(Response.Status.CONFLICT, "the account is already set up");
            }
            if (session.singleUseObjects().contains("stig-accounts-setup:" + u.getId())) {
                return err(Response.Status.TOO_MANY_REQUESTS, "a set-up e-mail went to this account less than 15 minutes ago");
            }
            return sendSetup(u, lifespan) ? Response.noContent().build() : err(Response.Status.BAD_GATEWAY, "the e-mail could not be sent");
        }

        @POST @Path("users/{id}/disable")
        public Response disable(@PathParam("id") String id) {
            UserModel u = target(id, "disable");
            if (u == null) return err(Response.Status.FORBIDDEN, "not allowed");
            if (!u.isEnabled()) return Response.noContent().build();          // already disabled: nothing to do
            u.setEnabled(false);
            session.users().setNotBeforeForUser(realm, u, Time.currentTime());
            session.sessions().getUserSessionsStream(realm, u).collect(Collectors.toList())
                   .forEach(s -> AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(),
                           session.getContext().getConnection(), session.getContext().getRequestHeaders(), true));
            adminEvent.operation(OperationType.UPDATE).resource(ResourceType.USER).resourcePath("users", u.getId())
                    .representation(Map.of("enabled", false)).success();
            LOG.infof("STIG-ACCOUNTS disabled realm=%s caller=%s user=%s", realm.getName(), caller(), u.getUsername());
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
