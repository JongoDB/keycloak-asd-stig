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
 * Network clients see only an allowlist of paths (PublicPathPolicy, raw path, fails closed); trusted source
 * addresses (the host itself) see everything. Keeps the master realm - and any realm not listed - off the network
 * while a listed realm's own admin console stays public behind role + MFA (V-222574 compensating control).
 *
 * Off unless BOTH are set:
 *   STIG_PUBLIC_PATHS     comma-separated; an entry ending in '/' is a prefix, otherwise an exact path
 *   STIG_TRUSTED_SOURCES  comma-separated exact TCP peer IPs that bypass the list (e.g. 127.0.0.1,172.31.250.1)
 * The TCP peer is used; forwarded headers are never trusted. Refusals are 404.
 */
@Provider
@PreMatching
public class PublicPathAllowlistFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger("mil.stig.audit");
    private static final PublicPathPolicy POLICY = new PublicPathPolicy(split(System.getenv("STIG_PUBLIC_PATHS")));
    private static final List<String> TRUSTED = split(System.getenv("STIG_TRUSTED_SOURCES"));

    @Context
    HttpServerRequest request;

    static List<String> split(String v) {
        return v == null ? List.of() : Arrays.stream(v.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (POLICY.isEmpty() || TRUSTED.isEmpty()) {
            return;
        }
        String peer = request == null || request.remoteAddress() == null ? "" : request.remoteAddress().host();
        if (TRUSTED.contains(peer)) {
            return;
        }
        String raw;
        try {
            raw = ctx.getUriInfo().getRequestUri().getRawPath();
        } catch (RuntimeException e) {
            raw = null;                                   // unreadable: refuse
        }
        if (!POLICY.allows(raw)) {
            LOG.warnf("STIG-PUBLIC-PATH-REFUSED path=%s peer=%s", PublicPathPolicy.printable(raw), PublicPathPolicy.printable(peer));
            ctx.abortWith(Response.status(Response.Status.NOT_FOUND).build());
        }
    }
}
