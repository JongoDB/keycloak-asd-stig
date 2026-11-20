package mil.stig.keycloak;

import java.net.URI;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * V-222447 (audit records capture HTTP headers including the Referer): the HTTP access log records method, path and
 * User-Agent but NOT the Referer, which can carry a query string (an admin search with an EDIPI, login hints). This
 * filter records it SANITISED instead, for every request that carries one:
 *   STIG-REFERER ip=<client> <METHOD> <path> referer=<scheme>://<host>[:port]<path>
 * - only scheme, host, port and path: no user info, query or fragment;
 * - digits masked as in every other audit line (AccountsPolicy.maskDigitRuns), control and format characters replaced.
 * The client address, method and raw path are the ones the access log's %h and "%m %R" print, for correlation.
 * Off only when STIG_REFERER_AUDIT=off (the deployment check requires it on).
 */
@Provider
public class StigRefererAuditFilter implements ContainerRequestFilter {
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");
    static final boolean ON = !"off".equalsIgnoreCase(String.valueOf(System.getenv("STIG_REFERER_AUDIT")).trim());

    @Override
    public void filter(ContainerRequestContext req) {
        if (!ON) return;
        String ref = req.getHeaderString("Referer");
        if (ref == null || ref.isBlank()) return;
        KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
        String ip = session == null || session.getContext().getConnection() == null ? "?" : session.getContext().getConnection().getRemoteAddr();
        LOG.infof("STIG-REFERER ip=%s %s %s referer=%s", AdminApiGuardFilter.logSafe(ip), AdminApiGuardFilter.logSafe(req.getMethod()),
                AdminApiGuardFilter.logSafe(req.getUriInfo().getRequestUri().getRawPath()), AdminApiGuardFilter.logSafe(sanitise(ref)));
    }

    /** scheme://host[:port]/path of a Referer, the path's digits masked; "<unparsable>" when it is not an absolute http(s) URI. */
    static String sanitise(String referer) {
        try {
            URI u = new URI(referer.trim());
            String scheme = u.getScheme(), host = u.getHost();
            if (scheme == null || host == null || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))) return "<unparsable>";
            String path = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
            return scheme.toLowerCase(java.util.Locale.ROOT) + "://" + host.toLowerCase(java.util.Locale.ROOT)
                    + (u.getPort() > 0 ? ":" + u.getPort() : "") + AccountsPolicy.maskDigitRuns(path);     // the path's digits
        } catch (Exception e) {
            return "<unparsable>";
        }
    }
}
