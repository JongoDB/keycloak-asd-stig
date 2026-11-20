package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * First-broker-login step: link the brokered identity ONLY to the one existing account whose admin-set attribute
 * (default "entra_oid") equals the identity the configured provider and tenant vouch for (AdminBoundIdentity: the
 * provider's mappers copy the ID token's oid/tid into entra_vouched_oid/entra_vouched_tid; no mapper may write
 * entra_oid). No match - or more
 * than one - and the sign-in is refused. Nothing is ever created and nothing is matched by username or e-mail, so a
 * crafted UPN or a reused address cannot land on someone else's account. The attribute itself should be protected
 * with cac-identity-guard (unique, realm administrators only).
 *
 * Optional (configured domain; PendingInviteLink): when NO account carries the vouched identity, the FIRST sign-in may
 * bind it to the one pending invite - an account a delegated user manager created through stig-accounts, never used
 * or bound, younger than the configured age - whose username or e-mail is the provider's principal name (UPN) in that
 * domain. Matching is on the principal name the provider vouches for, never on the e-mail claim. Audited (an admin
 * event and STIG-IDP-PENDING-INVITE-BOUND); after that the binding is fixed like any administrator-set one.
 */
public class IdpLinkByAdminAttributeAuthenticatorFactory extends AbstractIdpAuthenticator implements AuthenticatorFactory {

    public static final String ID = "idp-link-by-admin-attribute";
    static final String ATTR = "entra_oid";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serialized,
                                    BrokeredIdentityContext broker) {
        AdminBoundIdentity id = AdminBoundIdentity.of(context);
        String alias = broker.getIdpConfig() == null ? null : broker.getIdpConfig().getAlias();
        String vouched = AdminBoundIdentity.first(broker, id.oidAttr);
        String why = AdminBoundIdentity.preconditions(id.cfg(), alias, vouched, AdminBoundIdentity.first(broker, id.tidAttr),
                AdminBoundIdentity.mapperTargets(context));
        if (why != null) {
            refuse(context, broker, why);
            return;
        }
        List<UserModel> found = context.getSession().users()
                .searchForUserByUserAttributeStream(context.getRealm(), id.adminAttr, vouched).limit(2).collect(Collectors.toList());
        if (found.isEmpty()) {
            PendingInviteLink.Cfg pc = PendingInviteLink.cfg(context.getAuthenticatorConfig() == null ? null
                    : context.getAuthenticatorConfig().getConfig());
            if (pc != null) {
                bindPendingInvite(context, broker, id, pc, alias, vouched);
                return;
            }
        }
        if (found.size() != 1) {
            refuse(context, broker, found.isEmpty() ? "no account carries this " + id.adminAttr : "more than one account carries this " + id.adminAttr);
            return;
        }
        UserModel user = found.get(0);
        context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO,
                new ExistingUserInfo(user.getId(), id.adminAttr, vouched).serialize());
        LOG.infof("STIG-IDP-LINK idp=%s user=%s via %s", alias, user.getUsername(), id.adminAttr);
        context.setUser(user);
        context.success();
    }

    /** No account carries the vouched identity: bind it to the ONE pending invite PendingInviteLink allows, or refuse. */
    private void bindPendingInvite(AuthenticationFlowContext context, BrokeredIdentityContext broker, AdminBoundIdentity id,
                                   PendingInviteLink.Cfg pc, String alias, String vouched) {
        KeycloakSession session = context.getSession(); RealmModel realm = context.getRealm();
        String upn = AdminBoundIdentity.first(broker, pc.upnAttr());
        String principal = PendingInviteLink.principal(pc, upn);
        Map<String, UserModel> users = new LinkedHashMap<>();
        if (principal != null) {
            UserModel byName = session.users().getUserByUsername(realm, principal);
            if (byName != null) users.put(byName.getId(), byName);
            session.users().searchForUserStream(realm, Map.of(UserModel.EMAIL, principal, UserModel.EXACT, "true"))
                    .limit(5).forEach(u -> users.put(u.getId(), u));
        }
        List<PendingInviteLink.Candidate> cands = new ArrayList<>();
        for (UserModel u : users.values()) {
            if (u.getServiceAccountClientLink() != null) continue;
            cands.add(new PendingInviteLink.Candidate(u.getId(), u.getUsername(), u.getEmail(), u.isEnabled(),
                    u.getFirstAttribute(pc.markerAttr()), u.getFirstAttribute(id.adminAttr),
                    u.credentialManager().getStoredCredentialsStream().findAny().isPresent(),
                    u.getFirstAttribute(pc.cardAttr()), u.getCreatedTimestamp(), u.getFirstAttribute(PendingInviteLink.PENDING_MARKER),
                    u.getRequiredActionsStream().collect(Collectors.toList())));
        }
        PendingInviteLink.Result r = PendingInviteLink.decide(pc, upn, cands, Time.currentTimeMillis());
        if (r.id() == null) {
            refuse(context, broker, "no account carries this " + id.adminAttr + ", and no pending invite may be bound: " + r.refusal());
            return;
        }
        UserModel user = users.get(r.id());
        // ONCE: two first sign-ins racing for the same invite - only the one that claims this slot binds (atomic in
        // the cluster cache); the other is refused, and after the binding the account no longer qualifies anyway
        if (!session.singleUseObjects().putIfAbsent("stig-pending-invite-bind:" + realm.getId() + ":" + user.getId(), 300)) {
            refuse(context, broker, "this pending invite is being bound by another sign-in");
            return;
        }
        // the binding becomes the administrator-set attribute, exactly as `link-entra` would set it: unique (checked
        // just above: no account carries it), fixed from now on; the pending marker goes
        user.setSingleAttribute(id.adminAttr, vouched);
        user.removeAttribute(PendingInviteLink.PENDING_MARKER);
        audit(context, realm, user, alias, id.adminAttr, vouched);
        LOG.infof("STIG-IDP-PENDING-INVITE-BOUND realm=%s idp=%s user=%s principal=%s: %s set by the first sign-in",
                realm.getName(), alias, user.getUsername(), principal, id.adminAttr);
        context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO,
                new ExistingUserInfo(user.getId(), id.adminAttr, vouched).serialize());
        context.setUser(user);
        context.success();
    }

    /** An admin event (UPDATE USER, attributed to the account itself, from the sign-in's address) recording the binding. */
    private static void audit(AuthenticationFlowContext context, RealmModel realm, UserModel user, String alias, String attr, String value) {
        if (!realm.isAdminEventsEnabled()) return;
        AdminEvent ev = new AdminEvent();
        ev.setId(KeycloakModelUtils.generateId()); ev.setTime(Time.currentTimeMillis()); ev.setRealmId(realm.getId());
        AuthDetails ad = new AuthDetails();
        ad.setRealmId(realm.getId()); ad.setUserId(user.getId());
        ad.setClientId(context.getAuthenticationSession().getClient() == null ? null : context.getAuthenticationSession().getClient().getId());
        ad.setIpAddress(context.getConnection() == null ? null : context.getConnection().getRemoteAddr());
        ev.setAuthDetails(ad);
        ev.setOperationType(OperationType.UPDATE); ev.setResourceTypeAsString(ResourceType.USER.name());
        ev.setResourcePath("users/" + user.getId());
        if (realm.isAdminEventsDetailsEnabled()) {
            ev.setRepresentation("{\"attributes\":{\"" + attr + "\":[\"" + value.replace("\"", "") + "\"]},\"stig\":\"bound by the first "
                    + alias + " sign-in to a pending invite\"}");
        }
        EventStoreProvider store = context.getSession().getProvider(EventStoreProvider.class);
        if (store != null) store.onEvent(ev, realm.isAdminEventsDetailsEnabled());
        realm.getEventsListenersStream().forEach(l -> {
            EventListenerProvider p = context.getSession().getProvider(EventListenerProvider.class, l);
            if (p != null) p.onEvent(ev, realm.isAdminEventsDetailsEnabled());
        });
    }

    private void refuse(AuthenticationFlowContext context, BrokeredIdentityContext broker, String why) {
        LOG.warnf("STIG-IDP-LINK-REFUSED idp=%s username=%s reason=%s", broker.getIdpConfig() == null ? "?" : broker.getIdpConfig().getAlias(),
                broker.getUsername(), why);
        sendFailureChallenge(context, Response.Status.UNAUTHORIZED, "idpLinkNotAuthorized", why,
                AuthenticationFlowError.UNKNOWN_USER);
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serialized,
                              BrokeredIdentityContext broker) {
        authenticateImpl(context, serialized, broker);
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }

    // ---- factory
    @Override public Authenticator create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Link only by admin-set attribute (entra_oid)"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return true; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Links the brokered identity only to the existing account whose admin-set entra_oid equals the IdP's; never creates or matches by name/e-mail.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> all = new ArrayList<>(AdminBoundIdentity.properties());
        all.addAll(PendingInviteLink.properties());
        return all;
    }
}
