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
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Every admin-API request (/admin/realms/...), before it reaches its resource:
 *   - refused (403) for an account that holds administrator rights but is NOT on the realm's allowlist, or holds a
 *     realm-management role beyond its entry - so a token,
 *     refresh token or session obtained before (or without) vetting cannot be used against the API either;
 *   - refused (403) for anyone but a realm administrator or the master realm when any query parameter names a
 *     concealed attribute (q=cac_edipi:..., on /users, /users/count, group members, ...): no probing by value;
 *   - for a token issued to a client held to an admin-API profile (client attribute stig.admin-api.profile, see
 *     AdminApiStepUp): refused (403) outside the profile's calls, and a write answered 401 with a step-up challenge
 *     (RFC 9470) when the authentication behind the token is older than the client's stig.admin-api.max-auth-age.
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
            LOG.warnf("STIG-ADMIN-PATH-UNCLASSIFIABLE %s %s: refused", logSafe(req.getMethod()), logSafe(req.getUriInfo().getRequestUri().getRawPath()));
            req.abortWith(forbidden());
            return;
        }
        if (kind != Kind.ADMIN) return;
        // logged as the RAW path (percent-encoding kept) with any control character replaced: a %0a in the request
        // can never start a forged audit line
        String path = logSafe(req.getUriInfo().getRequestUri().getRawPath());
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
        if (auth == null || auth.getRealm() == null) return;
        ClientModel client = auth.getClient();
        String profile = client == null ? null : client.getAttribute(AdminApiStepUp.PROFILE_ATTR);
        String opsAttr = client == null ? null : client.getAttribute(AdminApiStepUp.OPS_ATTR);
        if (Config.getAdminRealm().equals(auth.getRealm().getName())) {
            // the master realm (the operator's tooling, break-glass) is never confined - so a client of it must never
            // look as if it were: one carrying the profile attribute is refused outright
            if (profile != null || opsAttr != null) {
                LOG.errorf("STIG-ADMIN-API-PROFILE-REFUSED realm=%s client=%s %s %s: a master-realm client carries %s; refused",
                        auth.getRealm().getName(), client.getClientId(), logSafe(req.getMethod()), path,
                        profile != null ? AdminApiStepUp.PROFILE_ATTR : AdminApiStepUp.OPS_ATTR);
                req.abortWith(forbidden());
                return;
            }
            auditQuery(req, auth, path);
            return;
        }
        if (StigAdministrators.unvettedAdministrator(session, auth.getRealm(), auth.getUser())) {
            LOG.errorf("STIG-ADMIN-NOT-ALLOWLISTED realm=%s user=%s path=admin-api %s %s: refused", auth.getRealm().getName(),
                    auth.getUser().getUsername(), logSafe(req.getMethod()), path);
            req.abortWith(forbidden());
            return;
        }
        if (!AdminAttributeConcealmentFilter.fullAdministrator(session) && namesConcealed(req.getUriInfo().getQueryParameters())) {
            LOG.warnf("STIG-ATTRIBUTE-PROBE-REFUSED realm=%s user=%s %s %s", auth.getRealm().getName(),
                    auth.getUser() == null ? "?" : auth.getUser().getUsername(), logSafe(req.getMethod()), path);
            req.abortWith(forbidden());
            return;
        }
        // A client held to an admin-API profile (AdminApiStepUp): its tokens reach only the profile's calls, and its
        // writes need a recent authentication. Checked for every caller of that client, administrators included.
        if (profile != null || opsAttr != null) {                // set, even blank: decide() fails closed on blank
            List<String> rest = AdminApiStepUp.afterRealm(seg);
            Long authTime = auth.getToken() == null ? null : auth.getToken().getAuth_time();
            String maxAttr = client.getAttribute(AdminApiStepUp.MAX_AGE_ATTR);
            AdminApiStepUp.Verdict v = AdminApiStepUp.decide(profile, maxAttr, opsAttr,
                    req.getMethod(), rest, authTime, Time.currentTime());
            String who = auth.getUser() == null ? "?" : auth.getUser().getUsername();
            if (v == AdminApiStepUp.Verdict.STEP_UP) {
                LOG.warnf("STIG-ADMIN-API-STEP-UP-REQUIRED realm=%s user=%s client=%s auth_age=%s %s %s: refused (401)",
                        auth.getRealm().getName(), who, client.getClientId(),
                        authTime == null ? "none" : String.valueOf(Time.currentTime() - authTime), logSafe(req.getMethod()), path);
                req.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                        .header("WWW-Authenticate", AdminApiStepUp.challenge(Math.max(AdminApiStepUp.maxAge(maxAttr), AdminApiStepUp.MIN_MAX_AGE)))
                        // a browser page reads a cross-origin response header only if it is exposed: without this the
                        // page sees the 401 but not the challenge (and its max_age)
                        .header("Access-Control-Expose-Headers", AdminApiStepUp.EXPOSE_HEADERS)
                        .entity(Map.of("error", "insufficient_user_authentication")).type(MediaType.APPLICATION_JSON).build());
            } else if (v == AdminApiStepUp.Verdict.REFUSE) {
                LOG.warnf("STIG-ADMIN-API-PROFILE-REFUSED realm=%s user=%s client=%s profile=%s %s %s: refused",
                        auth.getRealm().getName(), who, client.getClientId(),
                        profile != null ? logSafe(profile) : "(none: " + AdminApiStepUp.OPS_ATTR + " set without it)",
                        logSafe(req.getMethod()), path);
                req.abortWith(forbidden());
            }
            if (v == AdminApiStepUp.Verdict.STEP_UP || v == AdminApiStepUp.Verdict.REFUSE) return;   // refused: logged without the query
        }
        auditQuery(req, auth, path);
    }

    /** An ALLOWED admin request's query string, audited (STIG-ADMIN-QUERY) as maskedQuery() renders it: the access log
     *  records the path only, since a query can carry an EDIPI (users?q=cac_edipi:...) or another concealed value.
     *  Refused requests are logged by their refusal line, without the query. */
    private static void auditQuery(ContainerRequestContext req, AdminAuth auth, String path) {
        String query = req.getUriInfo().getRequestUri().getRawQuery();
        if (query == null || query.isEmpty()) return;
        LOG.infof("STIG-ADMIN-QUERY realm=%s user=%s client=%s %s %s?%s", auth.getRealm().getName(),
                auth.getUser() == null ? "?" : auth.getUser().getUsername(), auth.getClient() == null ? "?" : auth.getClient().getClientId(),
                logSafe(req.getMethod()), path,
                logSafe(maskedQuery(query, req.getUriInfo().getQueryParameters(true), AdminAttributeConcealmentFilter.CONCEALED)));
    }

    static final String CONCEALED_MASK = "<concealed>";

    /**
     * A query string for the audit line. Fail closed against parser and decoder differentials:
     *  - each raw parameter is decoded strictly; one that does not decode is logged as key=<concealed>;
     *  - a parameter whose NAME is a concealed attribute: key=<concealed>;
     *  - `q`: if a concealed attribute's name appears ANYWHERE in it - as this method decodes it, or as Keycloak decoded it
     *    (`keycloakView`, UriInfo.getQueryParameters(true), the values Keycloak's search acts on; quotes and all), case
     *    ignored - the WHOLE value is masked: q=<concealed>;
     *  - any other value naming a concealed attribute (in either view): <concealed>;
     *  - everything else: every run of four or more digits becomes "####".
     * Pure; unit-tested.
     */
    static String maskedQuery(String rawQuery, java.util.Map<String, List<String>> keycloakView, List<String> concealed) {
        java.util.function.Predicate<String> names = v -> {
            if (v == null) return false;
            String l = v.toLowerCase(Locale.ROOT);
            return concealed.stream().anyMatch(a -> l.contains(a.toLowerCase(Locale.ROOT)));
        };
        java.util.function.Function<String, Boolean> kcNames = k -> {
            List<String> vs = keycloakView == null ? null : keycloakView.get(k);
            return vs != null && vs.stream().anyMatch(names::test);
        };
        List<String> out = new java.util.ArrayList<>();
        for (String pair : rawQuery.split("&", -1)) {
            int i = pair.indexOf('=');
            String rk = i < 0 ? pair : pair.substring(0, i), rv = i < 0 ? null : pair.substring(i + 1);
            String k = decStrict(rk), v = rv == null ? null : decStrict(rv);
            if (k == null) { out.add("<undecodable>=" + CONCEALED_MASK); continue; }
            if (rv != null && v == null) { out.add(digits(k) + "=" + CONCEALED_MASK); continue; }
            boolean keyHidden = concealed.stream().anyMatch(a -> a.equalsIgnoreCase(k.trim())) || names.test(k);
            if (keyHidden || names.test(v) || kcNames.apply(k)) { out.add(digits(k) + (v == null && !keyHidden ? "" : "=" + CONCEALED_MASK)); continue; }
            out.add(v == null ? digits(k) : digits(k) + "=" + digits(v));
        }
        return String.join("&", out);
    }

    private static String digits(String s) { return AccountsPolicy.maskDigitRuns(s); }

    /** Form-decoding that FAILS (null) on a malformed escape instead of keeping the raw text. */
    private static String decStrict(String s) {
        try {
            return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
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

    /** For audit lines: control characters (CR, LF, ...) replaced by '?', at most 512 characters. */
    static String logSafe(String s) {
        if (s == null) return "-";
        StringBuilder b = new StringBuilder(Math.min(s.length(), 512));
        for (int i = 0; i < s.length() && b.length() < 512; i++) {
            char c = s.charAt(i);
            // control characters, line/paragraph separators AND format characters (Cf: e.g. U+202E, which reorders
            // what a reader of the log sees) all become '?'
            b.append(c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == 0x2028 || c == 0x2029
                    || Character.getType(c) == Character.FORMAT ? '?' : c);
        }
        return b.toString();
    }

    static Response forbidden() {
        return Response.status(Response.Status.FORBIDDEN).entity(Map.of("error", "not allowed")).type(MediaType.APPLICATION_JSON).build();
    }
}
