package mil.stig.keycloak;

import java.util.List;
import java.util.regex.Pattern;

/**
 * The admin-API profile a client can be held to (pure rules, unit-tested without Keycloak; applied by
 * AdminApiGuardFilter to every admin-API request whose token was issued to that client).
 *
 * A client whose attribute {@value #PROFILE_ATTR} is {@value #ACCOUNT_ONBOARDING} is a browser client through which
 * a person who manages accounts (a delegated user manager) works from another application's page. Its tokens may:
 *   - read: users (search), one user, a user's groups, groups, one group, its children and members, group-by-path;
 *   - write, and only with an authentication no older than {@value #MAX_AGE_ATTR} seconds (default 300, 30..900):
 *       POST stig-accounts/users                       create (the stig-accounts endpoint's own rules apply)
 *       POST stig-accounts/users/{id}/setup-email      re-send the set-up mail
 *       POST stig-accounts/users/{id}/disable          disable
 *       PUT | DELETE users/{id}/groups/{groupId}       a membership change (Keycloak's own permissions apply)
 *   - nothing else (403), whatever the person's own roles: a token from such a client never reaches the rest of the
 *     admin API, so a page it was issued to cannot be turned against anything but those calls.
 * A write with an older authentication (or none recorded in the token) is answered 401 with an RFC 9470 step-up
 * challenge, so the page re-authenticates with max_age and retries. Any other value of the profile attribute (a blank
 * one included), or a malformed or blank max age, refuses every request from that client (fail closed). No attribute:
 * not restricted here. A MASTER-realm client carrying the attribute is refused outright (the master realm is never
 * confined, so a client there must not look as if it were). The profile confines the ADMIN API only.
 */
final class AdminApiStepUp {
    private AdminApiStepUp() { }

    static final String PROFILE_ATTR = "stig.admin-api.profile";
    static final String MAX_AGE_ATTR = "stig.admin-api.max-auth-age";
    static final String ACCOUNT_ONBOARDING = "account-onboarding";
    static final int DEFAULT_MAX_AGE = 300, MIN_MAX_AGE = 30, MAX_MAX_AGE = 900;
    /** Tolerated clock skew for an auth_time in the future (seconds). */
    static final int SKEW = 30;
    /** An id segment: Keycloak's ids are UUIDs; a realm may use other plain ids. */
    static final Pattern ID = Pattern.compile("^[A-Za-z0-9-]{1,64}$");

    enum Verdict { NOT_RESTRICTED, ALLOW, STEP_UP, REFUSE }

    /** The max age the client is held to, or -1 when the attribute is malformed (fail closed). */
    static int maxAge(String attr) {
        if (attr == null) return DEFAULT_MAX_AGE;              // unset: the default; set but blank: fail closed
        if (attr.isBlank()) return -1;
        try {
            int v = Integer.parseInt(attr.trim());
            return v >= MIN_MAX_AGE && v <= MAX_MAX_AGE ? v : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * @param profile    the client's {@value #PROFILE_ATTR}
     * @param maxAgeAttr the client's {@value #MAX_AGE_ATTR}
     * @param method     the HTTP method
     * @param segs       the decoded path segments AFTER admin/realms/{realm} (empty: the realm itself)
     * @param authTime   the token's auth_time (seconds), or null when it carries none
     * @param now        the current time (seconds)
     */
    static Verdict decide(String profile, String maxAgeAttr, String method, List<String> segs, Long authTime, long now) {
        if (profile == null) return Verdict.NOT_RESTRICTED;     // unset; set but blank fails closed (as stig-accounts' domains)
        if (!ACCOUNT_ONBOARDING.equals(profile.trim())) return Verdict.REFUSE;
        int max = maxAge(maxAgeAttr);
        if (max < 0 || method == null || segs == null) return Verdict.REFUSE;
        String m = method.toUpperCase(java.util.Locale.ROOT);
        if (m.equals("GET") || m.equals("HEAD")) return readAllowed(segs) ? Verdict.ALLOW : Verdict.REFUSE;
        if (!writeAllowed(m, segs)) return Verdict.REFUSE;
        if (authTime == null || authTime <= 0 || authTime > now + SKEW || now - authTime > max) return Verdict.STEP_UP;
        return Verdict.ALLOW;
    }

    static boolean readAllowed(List<String> s) {
        int n = s.size();
        if (n == 0) return false;
        switch (s.get(0)) {
            case "users":
                if (n == 1) return true;                                                     // search
                if (!id(s.get(1))) return false;
                return n == 2 || (n == 3 && s.get(2).equals("groups"));
            case "groups":
                if (n == 1) return true;
                if (!id(s.get(1))) return false;
                return n == 2 || (n == 3 && (s.get(2).equals("children") || s.get(2).equals("members")));
            case "group-by-path":
                return n >= 2 && s.subList(1, n).stream().allMatch(x -> x != null && !x.isEmpty());
            default:
                return false;
        }
    }

    static boolean writeAllowed(String m, List<String> s) {
        int n = s.size();
        if (m.equals("POST") && n >= 2 && s.get(0).equals("stig-accounts") && s.get(1).equals("users")) {
            if (n == 2) return true;
            return n == 4 && id(s.get(2)) && (s.get(3).equals("setup-email") || s.get(3).equals("disable"));
        }
        if ((m.equals("PUT") || m.equals("DELETE")) && n == 4 && s.get(0).equals("users") && id(s.get(1))
                && s.get(2).equals("groups") && id(s.get(3))) {
            return true;
        }
        return false;
    }

    static boolean id(String x) { return x != null && ID.matcher(x).matches(); }

    /** The segments after admin/realms/{realm}, or null when the path is not a realm's admin API. */
    static List<String> afterRealm(List<String> segments) {
        List<String> seg = segments.stream().filter(x -> x != null && !x.isEmpty()).toList();
        for (int i = 0; i + 1 < seg.size(); i++) {
            if ("admin".equals(seg.get(i)) && "realms".equals(seg.get(i + 1))) {
                return i + 2 < seg.size() ? seg.subList(i + 3, seg.size()) : null;
            }
        }
        return null;
    }

    /** The RFC 9470 challenge for a write that needs a fresher authentication. */
    static String challenge(int maxAge) {
        return "Bearer error=\"insufficient_user_authentication\", error_description=\"A more recent authentication is "
                + "required\", max_age=\"" + maxAge + "\"";
    }
}
