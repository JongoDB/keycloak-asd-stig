package mil.stig.keycloak;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Every admin-API request (/admin/realms/...), before it reaches its resource:
 *   - refused (403) for an account that holds administrator rights but is NOT on the realm's allowlist - so a token,
 *     refresh token or session obtained before (or without) vetting cannot be used against the API either;
 *   - refused (403) for anyone but a realm administrator or the master realm when any query parameter names a
 *     concealed attribute (q=cac_edipi:..., on /users, /users/count, group members, ...): no probing by value.
 * The master realm (the operator's tooling, break-glass) is never refused. A request that is not admin-authenticated
 * is left to Keycloak's own checks.
 */
@Provider
public class AdminApiGuardFilter implements ContainerRequestFilter {
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");

    @Override
    public void filter(ContainerRequestContext req) {
        String path = req.getUriInfo().getPath();
        if (path == null || !(path.startsWith("/admin/realms/") || path.startsWith("admin/realms/") || path.contains("/admin/realms/"))) return;
        KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
        if (session == null) return;
        AdminAuth auth = AdminRoot.getRealmAdminAuth(session).orElse(null);
        if (auth == null) {
            try {
                auth = AdminRoot.authenticateRealmAdminRequest(session);
            } catch (RuntimeException e) {
                return;                       // not admin-authenticated: Keycloak itself answers 401
            }
        }
        if (auth == null || auth.getRealm() == null || Config.getAdminRealm().equals(auth.getRealm().getName())) return;
        if (StigAdministrators.unvettedAdministrator(session, auth.getRealm(), auth.getUser())) {
            LOG.errorf("STIG-ADMIN-NOT-ALLOWLISTED realm=%s user=%s path=admin-api %s %s: refused", auth.getRealm().getName(),
                    auth.getUser().getUsername(), req.getMethod(), path);
            req.abortWith(forbidden());
            return;
        }
        if (!AdminAttributeConcealmentFilter.fullAdministrator(session) && namesConcealed(req.getUriInfo().getQueryParameters())) {
            LOG.warnf("STIG-ATTRIBUTE-PROBE-REFUSED realm=%s user=%s %s %s", auth.getRealm().getName(),
                    auth.getUser() == null ? "?" : auth.getUser().getUsername(), req.getMethod(), path);
            req.abortWith(forbidden());
        }
    }

    static boolean namesConcealed(MultivaluedMap<String, String> params) {
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            for (String v : e.getValue()) {
                String l = (e.getKey() + "=" + (v == null ? "" : v)).toLowerCase(Locale.ROOT);
                if (AdminAttributeConcealmentFilter.CONCEALED.stream().anyMatch(a -> l.contains(a.toLowerCase(Locale.ROOT)))) return true;
            }
        }
        return false;
    }

    static Response forbidden() {
        return Response.status(Response.Status.FORBIDDEN).entity(Map.of("error", "not allowed")).type(MediaType.APPLICATION_JSON).build();
    }
}
