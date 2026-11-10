package mil.stig.keycloak;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import io.vertx.core.http.HttpServerRequest;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

/**
 * Keeps the admin (master) realm off the network: requests for /realms/{admin realm}/..., /admin/{admin realm}/...
 * and /admin/realms/{admin realm}/... are answered 404 unless they come from an allowed source address, whatever
 * host or port they arrive on. Paths are matched by AdminRealmPathMatcher on decoded segments (matrix parameters,
 * doubled or encoded slashes, dot segments and case variants all normalised; anything unreadable is denied). The user-facing realms - including their own admin console
 * - are untouched. Use it when the admin console must stay reachable for a user realm but the master realm should be
 * break-glass only (V-222574 compensating control).
 *
 * Off unless STIG_ADMIN_REALM_ALLOWED_SOURCES is set (comma-separated exact IPs, e.g. "127.0.0.1,172.18.0.1").
 * STIG_ADMIN_REALM (default "master") names the realm. The TCP peer is used; forwarded headers are never trusted.
 */
@Provider
@PreMatching
public class AdminRealmNetworkGuard implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger("mil.stig.audit");
    private static final String REALM = env("STIG_ADMIN_REALM", "master");
    private static final List<String> ALLOWED = Arrays.stream(env("STIG_ADMIN_REALM_ALLOWED_SOURCES", "").split(","))
            .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());

    @Context
    HttpServerRequest request;

    static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isBlank() ? d : v;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (ALLOWED.isEmpty()) {
            return;
        }
        boolean guarded;
        try {
            List<String> segs = ctx.getUriInfo().getPathSegments(true).stream()
                    .map(jakarta.ws.rs.core.PathSegment::getPath).collect(Collectors.toList());
            guarded = AdminRealmPathMatcher.guarded(segs, REALM);
        } catch (RuntimeException e) {
            guarded = true;                        // cannot parse the path confidently: default deny
        }
        if (!guarded) {
            return;
        }
        String peer = request == null || request.remoteAddress() == null ? "" : request.remoteAddress().host();
        if (!ALLOWED.contains(peer)) {
            LOG.warnf("STIG-ADMIN-REALM-BLOCKED path=%s peer=%s",
                    AdminRealmPathMatcher.printable(ctx.getUriInfo().getRequestUri().getRawPath()), AdminRealmPathMatcher.printable(peer));
            ctx.abortWith(Response.status(Response.Status.NOT_FOUND).build());
        }
    }
}
