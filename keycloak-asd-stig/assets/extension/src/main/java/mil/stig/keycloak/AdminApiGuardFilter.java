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

    enum Kind { ADMIN, NOT_ADMIN, UNCLASSIFIABLE }

    /** Decided on structure, not substrings: the request's decoded path SEGMENTS (matrix parameters removed, empty
     *  segments dropped) contain "admin" followed by "realms"; or a path naming admin in any form that has matrix
     *  parameters, empty segments, dot segments or encoded separators - which cannot be classified - is refused. */
    static Kind classify(List<String> segments, String rawPath) {
        List<String> seg = segments.stream().filter(x -> x != null && !x.isEmpty()).toList();
        for (int i = 0; i + 1 < seg.size(); i++) {
            if ("admin".equals(seg.get(i)) && "realms".equals(seg.get(i + 1))) return Kind.ADMIN;
        }
        String raw = rawPath == null ? "" : rawPath.toLowerCase(Locale.ROOT);
        if (raw.contains("admin") && (raw.contains(";") || raw.contains("//") || raw.contains("%2f") || raw.contains("%5c")
                || raw.contains("\\") || raw.contains("%2e") || raw.contains("%25") || raw.contains("/./") || raw.contains("/../")
                || raw.endsWith("/.") || raw.endsWith("/.."))) {
            return Kind.UNCLASSIFIABLE;
        }
        return Kind.NOT_ADMIN;
    }

    @Override
    public void filter(ContainerRequestContext req) {
        List<String> seg = req.getUriInfo().getPathSegments(true).stream().map(jakarta.ws.rs.core.PathSegment::getPath).toList();
        Kind kind = classify(seg, req.getUriInfo().getRequestUri().getRawPath());
        if (kind == Kind.NOT_ADMIN && req.getUriInfo().getMatchedResources().stream()
                .anyMatch(r -> r != null && r.getClass().getName().startsWith("org.keycloak.services.resources.admin.")
                        && !r.getClass().getSimpleName().equals("AdminConsole"))) {
            kind = Kind.ADMIN;                // matched by Keycloak's admin resources whatever the path looked like
        }
        if (kind == Kind.UNCLASSIFIABLE) {
            LOG.warnf("STIG-ADMIN-PATH-UNCLASSIFIABLE %s %s: refused", req.getMethod(), req.getUriInfo().getRequestUri().getRawPath());
            req.abortWith(forbidden());
            return;
        }
        if (kind != Kind.ADMIN) return;
        String path = req.getUriInfo().getPath();
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
