package mil.stig.keycloak;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.AdminEventRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.utils.KeycloakSessionUtil;

/**
 * Identity bindings and sign-in evidence (the card mapping, Entra binding and evidence, the delegate-created marker)
 * are visible through the admin API ONLY to true realm administrators (realm-admin) and the master realm. A
 * fine-grained delegate counts as "admin" for user-profile permissions, so the user profile cannot hide them; this
 * filter removes them from every user representation the admin API returns to anyone else, and empties a user search
 * that names one of them (no probing by value). The same names are removed from the representation an admin event
 * carries (an auditor reading admin events sees what was changed, not the card mapping); a representation that cannot
 * be cleaned is withheld. STIG_CONCEALED_ATTRIBUTES overrides the list (comma-separated).
 */
@Provider
public class AdminAttributeConcealmentFilter implements ContainerResponseFilter {
    static final List<String> DEFAULT = List.of("cac_edipi", "cac_upn", "cac_cn", "cac_subject_dn", "alt_token_upn", "entra_oid",
            "entra_vouched_oid", "entra_vouched_tid", "entra_amr", "stig_created_by");
    static final List<String> CONCEALED = configured();

    static List<String> configured() {
        String v = System.getenv("STIG_CONCEALED_ATTRIBUTES");
        if (v == null || v.isBlank()) return DEFAULT;
        return Arrays.stream(v.split(",")).map(String::trim).filter(x -> !x.isEmpty()).collect(Collectors.toList());
    }

    @Override
    public void filter(ContainerRequestContext req, ContainerResponseContext res) {
        String path = req.getUriInfo().getPath();
        if (path == null || !path.contains("/admin/realms/")) return;
        Object entity = res.getEntity();
        if (entity == null) return;
        KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
        if (session == null || fullAdministrator(session)) return;
        String q = req.getUriInfo().getQueryParameters().getFirst("q");
        boolean probing = q != null && CONCEALED.stream().anyMatch(a -> q.toLowerCase(Locale.ROOT).contains(a.toLowerCase(Locale.ROOT)));
        if (entity instanceof UserRepresentation u) {
            strip(u);
        } else if (entity instanceof Stream<?> st) {
            res.setEntity(probing ? Stream.empty() : st.map(AdminAttributeConcealmentFilter::stripAny));
        } else if (entity instanceof Collection<?> c) {
            if (probing && c.stream().anyMatch(x -> x instanceof UserRepresentation)) res.setEntity(List.of());
            else c.forEach(AdminAttributeConcealmentFilter::stripAny);
        }
    }

    static Object stripAny(Object o) {
        if (o instanceof UserRepresentation u) strip(u);
        else if (o instanceof AdminEventRepresentation e) e.setRepresentation(scrub(e.getRepresentation()));
        return o;
    }

    /** An admin event's representation (JSON) without any concealed name, at any depth; null (withheld) when it
     *  cannot be parsed, or when a concealed name still appears anywhere after cleaning (e.g. inside a value). */
    static String scrub(String json) {
        if (json == null || !mentionsConcealed(json)) return json;
        try {
            Object tree = JsonSerialization.readValue(json, Object.class);
            String out = JsonSerialization.writeValueAsString(prune(tree));
            return mentionsConcealed(out) ? null : out;
        } catch (Exception e) {
            return null;
        }
    }

    static boolean mentionsConcealed(String s) {
        String l = s.toLowerCase(Locale.ROOT);
        return CONCEALED.stream().anyMatch(a -> l.contains(a.toLowerCase(Locale.ROOT)));
    }

    @SuppressWarnings("unchecked")
    static Object prune(Object o) {
        if (o instanceof Map<?, ?> m) {
            Map<String, Object> out = new java.util.LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                String k = String.valueOf(e.getKey());
                if (CONCEALED.stream().anyMatch(a -> a.equalsIgnoreCase(k))) continue;
                out.put(k, prune(e.getValue()));
            }
            return out;
        }
        if (o instanceof List<?> l) return l.stream().map(AdminAttributeConcealmentFilter::prune).collect(Collectors.toList());
        return o;
    }

    static void strip(UserRepresentation u) {
        Map<String, List<String>> at = u.getAttributes();
        if (at != null && CONCEALED.stream().anyMatch(at::containsKey)) {
            Map<String, List<String>> copy = new java.util.HashMap<>(at);
            CONCEALED.forEach(copy::remove);
            u.setAttributes(copy);
        }
    }

    /** The master realm, or an account holding realm-admin in the realm. No admin authentication = not one (conceal). */
    static boolean fullAdministrator(KeycloakSession session) {
        AdminAuth auth = AdminRoot.getRealmAdminAuth(session).orElse(null);
        if (auth == null) return false;
        RealmModel r = auth.getRealm();
        if (r != null && Config.getAdminRealm().equals(r.getName())) return true;
        UserModel u = auth.getUser();
        ClientModel rm = r == null ? null : r.getClientByClientId("realm-management");
        RoleModel ra = rm == null ? null : rm.getRole("realm-admin");
        return u != null && ra != null && u.hasRole(ra);
    }
}
