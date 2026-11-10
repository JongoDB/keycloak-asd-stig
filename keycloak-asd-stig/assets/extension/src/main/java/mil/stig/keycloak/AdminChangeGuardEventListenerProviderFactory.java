package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Only the master realm (the automation service account and break-glass, which the network cannot reach) may make
 * anyone an administrator. Keycloak calls admin-event listeners synchronously, inside the request's transaction and
 * after the change: when an actor of the realm itself (a realm administrator in the admin console, a delegate)
 * grants administrator rights - joins a user to a group carrying any realm-management role, maps such a role (or a
 * composite holding one) to a user or a group, adds one to a composite, creates a user straight into such a group,
 * or moves a group with members under one - the change is undone in that same transaction, so it never takes effect,
 * and STIG-ADMIN-CHANGE-UNDONE is logged for the operator's alerting. Promotions go through the operator's tooling
 * (master service account), which vets the account first.
 */
public class AdminChangeGuardEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String ID = "stig-admin-change-guard";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override public EventListenerProvider create(KeycloakSession session) { return new Guard(session); }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    static final class Guard implements EventListenerProvider {
        private final KeycloakSession session;
        Guard(KeycloakSession session) { this.session = session; }

        @Override public void onEvent(Event event) { }
        @Override public void close() { }

        @Override
        public void onEvent(AdminEvent e, boolean includeRepresentation) {
            if (e.getOperationType() != OperationType.CREATE && e.getOperationType() != OperationType.UPDATE) return;
            AuthDetails ad = e.getAuthDetails();
            RealmModel actorRealm = ad == null || ad.getRealmId() == null ? null : session.realms().getRealm(ad.getRealmId());
            if (actorRealm != null && Config.getAdminRealm().equals(actorRealm.getName())) return;   // master: allowed
            RealmModel realm = session.realms().getRealm(e.getRealmId());
            if (realm == null || e.getResourcePath() == null) return;
            ClientModel rm = realm.getClientByClientId("realm-management");
            if (rm == null) return;
            List<String> undone = new ArrayList<>();
            try {
                undo(realm, rm, e, undone);
            } catch (RuntimeException ex) {
                LOG.errorf(ex, "STIG-ADMIN-CHANGE-GUARD-ERROR realm=%s path=%s", realm.getName(), e.getResourcePath());
                throw ex;
            }
            if (!undone.isEmpty()) {
                LOG.errorf("STIG-ADMIN-CHANGE-UNDONE realm=%s actor-realm=%s actor=%s client=%s ip=%s op=%s path=%s undone=%s: only the "
                        + "operator's tooling (master realm) may make an administrator", realm.getName(),
                        actorRealm == null ? "?" : actorRealm.getName(), ad == null ? "?" : ad.getUserId(), ad == null ? "?" : ad.getClientId(),
                        ad == null ? "?" : ad.getIpAddress(), e.getOperationType(), e.getResourcePath(), undone);
            }
        }

        static boolean grantsAdmin(ClientModel rm, RoleModel role) {
            return role != null && rm.getRolesStream().anyMatch(r -> role.getId().equals(r.getId()) || role.hasRole(r));
        }
        static boolean carriesAdmin(ClientModel rm, GroupModel g) {
            return g != null && rm.getRolesStream().anyMatch(g::hasRole);
        }

        /** Ids in the event's representation ("id":"<uuid>"; role representations carry no other "id" key). */
        static List<String> ids(String representation) {
            List<String> out = new ArrayList<>();
            if (representation == null) return out;
            Matcher m = ID.matcher(representation);
            while (m.find()) out.add(m.group(1));
            return out;
        }
        static final Pattern ID = Pattern.compile("\"id\"\\s*:\\s*\"([0-9A-Fa-f-]{36})\"");

        private List<RoleModel> roles(RealmModel realm, AdminEvent e) {
            List<RoleModel> out = new ArrayList<>();
            for (String id : ids(e.getRepresentation())) {
                RoleModel m = realm.getRoleById(id);
                if (m != null) out.add(m);
            }
            return out;
        }

        private void undo(RealmModel realm, ClientModel rm, AdminEvent e, List<String> undone) {
            String[] p = e.getResourcePath().split("/");
            ResourceType t = e.getResourceType();
            if (t == ResourceType.GROUP_MEMBERSHIP && p.length >= 4 && "users".equals(p[0]) && "groups".equals(p[2])) {
                UserModel u = session.users().getUserById(realm, p[1]);
                GroupModel g = realm.getGroupById(p[3]);
                if (u != null && carriesAdmin(rm, g)) { u.leaveGroup(g); undone.add("membership " + u.getUsername() + " in " + g.getName()); }
            } else if ((t == ResourceType.CLIENT_ROLE_MAPPING || t == ResourceType.REALM_ROLE_MAPPING) && p.length >= 3 && "role-mappings".equals(p[2])) {
                if ("users".equals(p[0])) {
                    UserModel u = session.users().getUserById(realm, p[1]);
                    for (RoleModel r : roles(realm, e)) if (u != null && grantsAdmin(rm, r)) { u.deleteRoleMapping(r); undone.add("role " + r.getName() + " of " + u.getUsername()); }
                } else if ("groups".equals(p[0])) {
                    GroupModel g = realm.getGroupById(p[1]);
                    for (RoleModel r : roles(realm, e)) if (g != null && grantsAdmin(rm, r)) { g.deleteRoleMapping(r); undone.add("role " + r.getName() + " of group " + g.getName()); }
                }
            } else if ((t == ResourceType.REALM_ROLE || t == ResourceType.CLIENT_ROLE) && p[p.length - 1].equals("composites")) {
                RoleModel parent = null;
                if (p.length == 3 && "roles-by-id".equals(p[0])) parent = realm.getRoleById(p[1]);
                else if (p.length == 3 && "roles".equals(p[0])) parent = realm.getRole(p[1]);
                else if (p.length == 5 && "clients".equals(p[0]) && "roles".equals(p[2])) {
                    ClientModel c = realm.getClientById(p[1]);
                    parent = c == null ? null : c.getRole(p[3]);
                }
                for (RoleModel r : roles(realm, e)) if (parent != null && grantsAdmin(rm, r)) { parent.removeCompositeRole(r); undone.add("composite " + r.getName() + " of " + parent.getName()); }
            } else if (t == ResourceType.USER && e.getOperationType() == OperationType.CREATE && p.length == 2 && "users".equals(p[0])) {
                UserModel u = session.users().getUserById(realm, p[1]);
                if (u != null) {
                    u.getGroupsStream().filter(g -> carriesAdmin(rm, g)).toList()
                     .forEach(g -> { u.leaveGroup(g); undone.add("membership " + u.getUsername() + " in " + g.getName()); });
                    rm.getRolesStream().filter(r -> u.getRoleMappingsStream().anyMatch(m -> m.getId().equals(r.getId()))).toList()
                     .forEach(r -> { u.deleteRoleMapping(r); undone.add("role " + r.getName() + " of " + u.getUsername()); });
                }
            } else if (t == ResourceType.GROUP && p.length >= 3 && "groups".equals(p[0]) && "children".equals(p[2])) {
                for (String id : ids(e.getRepresentation())) {
                    GroupModel g = realm.getGroupById(id);
                    if (g != null && carriesAdmin(rm, g) && session.users().getGroupMembersStream(realm, g, 0, 1).findAny().isPresent()) {
                        realm.moveGroup(g, null); undone.add("group " + g.getName() + " (with members) moved back to the top level");
                    }
                }
            }
        }
    }
}
