package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.keycloak.provider.ProviderConfigProperty;

/**
 * Whether ONE brokered sign-in carries a trusted identity provider's own multi-factor evidence, decided from the claims
 * of the ID token that provider issued for THIS sign-in (Keycloak validated its signature, issuer, audience and expiry
 * before the post-broker flow runs). Nothing is read from, or written to, the user: a value stored by an earlier
 * sign-in, an administrator or a mapper can never stand in for this sign-in's evidence.
 *
 * Accepted only when ALL hold - anything else, a missing or malformed claim included, is a refusal (fail closed):
 *  - the configuration names at least one trusted tenant, each a GUID ({@code stig.idp-mfa.trusted-tenants});
 *  - the sign-in came through the configured provider alias ({@code stig.idp-mfa.idp-alias}, default entra);
 *  - the token's {@code tid} is one of the trusted tenants;
 *  - the user is the tenant's own member: no {@code idp} claim naming anything but the tenant itself (in either
 *    endpoint's issuer form), no {@code acct} other than 0
 *    (a guest's methods are its home provider's, not the tenant's);
 *  - {@code amr} (RFC 8176: an array of method names) contains an accepted method ({@code stig.idp-mfa.accept-amr},
 *    default mfa), or {@code acr} / {@code acrs} carries a value of the optional allow-list
 *    ({@code stig.idp-mfa.accept-acr}, default empty = acr is never enough).
 *
 * Pure: unit-tested without Keycloak (IdpMfaEvidenceTest).
 */
final class IdpMfaEvidence {
    static final String P_ALIAS = "stig.idp-mfa.idp-alias", P_TENANTS = "stig.idp-mfa.trusted-tenants",
            P_AMR = "stig.idp-mfa.accept-amr", P_ACR = "stig.idp-mfa.accept-acr";
    static final Pattern GUID = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    /** An amr method name as Entra and RFC 8176 spell them; anything else makes the claim malformed. */
    static final Pattern METHOD = Pattern.compile("[A-Za-z0-9_.-]{1,32}");
    /** An acr / acrs value (Entra auth-context ids are c1..c99; URIs and short tokens elsewhere). */
    static final Pattern ACR = Pattern.compile("[A-Za-z0-9_.:/#-]{1,128}");
    static final int MAX_METHODS = 16;

    record Cfg(String alias, Set<String> tenants, Set<String> acceptAmr, Set<String> acceptAcr, String problem) {
        boolean usable() { return problem == null; }
    }

    record Decision(boolean accepted, String reason, List<String> amr, String acr) {
        /** amr for the log and the event: method names only, or "?" for a claim that was not a list of names. */
        String amrText() { return amr == null ? "" : String.join(",", amr); }
    }

    /** The configuration, read once. Splits on "##" (Keycloak's multivalued separator) and on commas or whitespace. */
    static Cfg cfg(Map<String, String> c) {
        Map<String, String> m = c == null ? Map.of() : c;
        String alias = m.getOrDefault(P_ALIAS, "entra");
        alias = alias == null || alias.isBlank() ? "entra" : alias.trim();
        Set<String> tenants = new LinkedHashSet<>(), amr = new LinkedHashSet<>(), acr = new LinkedHashSet<>();
        String problem = null;
        for (String t : split(m.get(P_TENANTS))) {
            if (!GUID.matcher(t).matches()) { problem = "malformed " + P_TENANTS; break; }
            tenants.add(t.toLowerCase(Locale.ROOT));
        }
        if (problem == null && tenants.isEmpty()) problem = "not configured (" + P_TENANTS + " is empty)";
        List<String> wantAmr = m.containsKey(P_AMR) ? split(m.get(P_AMR)) : List.of("mfa");
        for (String x : wantAmr) {
            if (!METHOD.matcher(x).matches()) { if (problem == null) problem = "malformed " + P_AMR; break; }
            amr.add(x.toLowerCase(Locale.ROOT));
        }
        for (String x : split(m.get(P_ACR))) {
            if (!ACR.matcher(x).matches()) { if (problem == null) problem = "malformed " + P_ACR; break; }
            acr.add(x);
        }
        if (problem == null && amr.isEmpty() && acr.isEmpty()) problem = "nothing accepted (" + P_AMR + " and " + P_ACR + " empty)";
        return new Cfg(alias, Collections.unmodifiableSet(tenants), Collections.unmodifiableSet(amr), Collections.unmodifiableSet(acr), problem);
    }

    static List<String> split(String v) {
        if (v == null || v.isBlank()) return List.of();
        List<String> out = new ArrayList<>();
        for (String s : v.split("##|[,\\s]+")) if (!s.isBlank()) out.add(s.trim());
        return out;
    }

    /**
     * The decision for one sign-in. {@code claims} is the validated ID token as a JSON object (null: no token - e.g.
     * not an OIDC provider, or a sign-in that is not brokered).
     */
    static Decision decide(Cfg c, String brokeredAlias, Map<String, Object> claims) {
        List<String> amr = null;
        String acr = null;
        if (claims != null) {
            Object a = claims.get("amr");
            if (a != null) amr = methods(a);
            Object r = claims.get("acr");
            if (r instanceof String s && ACR.matcher(s).matches()) acr = s;
        }
        String why = refusal(c, brokeredAlias, claims, amr);
        return new Decision(why == null, why == null ? "tenant MFA" : why, amr, acr);
    }

    /** amr as method names; a claim that is not a JSON array of names gives ["?"] (and is refused as malformed). */
    static List<String> methods(Object a) {
        if (!(a instanceof List<?> l) || l.isEmpty() || l.size() > MAX_METHODS) return List.of("?");
        List<String> out = new ArrayList<>();
        for (Object o : l) {
            if (!(o instanceof String s) || !METHOD.matcher(s).matches()) return List.of("?");
            out.add(s);
        }
        return out;
    }

    private static String refusal(Cfg c, String brokeredAlias, Map<String, Object> claims, List<String> amr) {
        if (!c.usable()) return c.problem();
        if (brokeredAlias == null) return "not a brokered sign-in";
        if (!brokeredAlias.equals(c.alias())) return "provider " + brokeredAlias + " is not " + c.alias();
        if (claims == null) return "no validated ID token from the provider";
        Object tid = claims.get("tid");
        if (tid == null) return "no tid claim";
        if (!(tid instanceof String t) || !GUID.matcher(t).matches()) return "malformed tid claim";
        if (!c.tenants().contains(t.toLowerCase(Locale.ROOT))) return "tenant is not trusted";
        Object idp = claims.get("idp");
        if (idp != null && !(idp instanceof String i && tenantItself(i, t))) return "a guest (idp names another identity provider)";
        Object acct = claims.get("acct");
        if (acct != null && !"0".equals(String.valueOf(acct))) return "a guest (acct is not 0)";
        Object acrC = claims.get("acr"), acrsC = claims.get("acrs");
        if (acrC != null && !(acrC instanceof String s && ACR.matcher(s).matches())) return "malformed acr claim";
        List<String> acrs = acrsC == null ? List.of() : acrsList(acrsC);
        if (acrs == null) return "malformed acrs claim";
        if (amr != null && amr.equals(List.of("?"))) return "malformed amr claim";
        if (amr != null) for (String m : amr) if (c.acceptAmr().contains(m.toLowerCase(Locale.ROOT))) return null;
        if (!c.acceptAcr().isEmpty()) {
            if (acrC != null && c.acceptAcr().contains((String) acrC)) return null;
            for (String x : acrs) if (c.acceptAcr().contains(x)) return null;
        }
        if (amr == null && acrC == null && acrs.isEmpty()) return "no amr claim";
        return "no accepted MFA method in amr" + (c.acceptAcr().isEmpty() ? "" : " or acr/acrs");
    }

    /** idp naming the tenant itself (either endpoint's issuer form), as Entra does for some members. */
    static boolean tenantItself(String idp, String tid) {
        String i = idp.trim().toLowerCase(Locale.ROOT), t = tid.toLowerCase(Locale.ROOT);
        return i.equals("https://sts.windows.net/" + t + "/") || i.equals("https://login.microsoftonline.com/" + t + "/v2.0");
    }

    /** acrs as a list of values, or null when malformed (Entra sends an array; a single string is tolerated). */
    static List<String> acrsList(Object v) {
        List<?> l = v instanceof String s ? List.of(s) : v instanceof List<?> x ? x : null;
        if (l == null || l.size() > MAX_METHODS) return null;
        List<String> out = new ArrayList<>();
        for (Object o : l) {
            if (!(o instanceof String s) || !ACR.matcher(s).matches()) return null;
            out.add(s);
        }
        return out;
    }

    static List<ProviderConfigProperty> properties() {
        return Arrays.asList(
            prop(P_ALIAS, "Identity provider alias", "Only this provider's sign-ins can satisfy the second factor.", "entra"),
            prop(P_TENANTS, "Trusted tenant ids", "Required. GUIDs (comma separated); the ID token's tid must be one of them. Empty: never accepted.", null),
            prop(P_AMR, "Accepted amr methods", "The ID token's amr must contain one of these (comma separated).", "mfa"),
            prop(P_ACR, "Accepted acr / acrs values", "Optional. An acr or acrs value from this list also counts. Empty: acr never counts.", null));
    }

    private static ProviderConfigProperty prop(String name, String label, String help, String def) {
        return new ProviderConfigProperty(name, label, help, ProviderConfigProperty.STRING_TYPE, def);
    }
}
