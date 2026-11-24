package mil.stig.keycloak;

import java.util.Arrays;
import java.util.List;

import mil.stig.keycloak.AdminApiStepUp.Verdict;

/** Unit tests of the admin-API client profile (AdminApiStepUp) and the stig-accounts reference rule. Run by build.sh. */
public final class AdminApiStepUpTest {
    static int run = 0, failed = 0;
    static final String P = AdminApiStepUp.ACCOUNT_ONBOARDING;
    static final String U = "0b3c7f7e-1d2a-4c55-9a51-2a8f3b2e9c10", G = "6f1d2c3b-4a59-4e68-8b7a-1c2d3e4f5a6b";
    static final long NOW = 2_000_000_000L;

    static void t(String n, Object got, Object want) {
        run++; boolean ok = java.util.Objects.equals(got, want); if (!ok) failed++;
        System.out.printf("%s  %-78s %s%n", ok ? "PASS" : "FAIL", n, ok ? "" : "got " + got + ", want " + want);
    }
    static List<String> s(String... x) { return Arrays.asList(x); }
    static Verdict d(String method, List<String> segs, Long authTime) { return AdminApiStepUp.decide(P, null, method, segs, authTime, NOW); }

    public static void main(String[] a) {
        // no profile: nothing restricted here, whatever the call
        t("no profile attribute: not restricted", AdminApiStepUp.decide(null, null, "DELETE", s("users", U), null, NOW), Verdict.NOT_RESTRICTED);
        t("profile attribute set but blank: every call refused (fail closed)", AdminApiStepUp.decide(" ", null, "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("profile attribute set but empty: every call refused (fail closed)", AdminApiStepUp.decide("", null, "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("max age set but blank: refused (fail closed)", AdminApiStepUp.decide(P, " ", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("max age set but empty: refused (fail closed)", AdminApiStepUp.maxAge(""), -1);
        t("unknown profile value: every call refused (fail closed)", AdminApiStepUp.decide("other", null, "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("malformed max age: refused (fail closed)", AdminApiStepUp.decide(P, "5m", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("max age below 30: refused", AdminApiStepUp.decide(P, "10", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("max age above 900: refused", AdminApiStepUp.decide(P, "3600", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("max age default 300", AdminApiStepUp.maxAge(null), 300);
        t("max age 600 accepted", AdminApiStepUp.maxAge("600"), 600);

        // reads
        t("GET users (search)", d("GET", s("users"), null), Verdict.ALLOW);
        t("GET users/{id}", d("GET", s("users", U), null), Verdict.ALLOW);
        t("GET users/{id}/groups", d("GET", s("users", U, "groups"), null), Verdict.ALLOW);
        t("GET groups", d("GET", s("groups"), null), Verdict.ALLOW);
        t("GET groups/{id}/members", d("GET", s("groups", G, "members"), null), Verdict.ALLOW);
        t("GET groups/{id}/children", d("GET", s("groups", G, "children"), null), Verdict.ALLOW);
        t("GET group-by-path/app/ROLE", d("GET", s("group-by-path", "app", "ROLE"), null), Verdict.ALLOW);
        t("HEAD users/{id}", d("HEAD", s("users", U), null), Verdict.ALLOW);
        t("GET the realm itself refused", d("GET", s(), null), Verdict.REFUSE);
        t("GET events refused", d("GET", s("events"), null), Verdict.REFUSE);
        t("GET admin-events refused", d("GET", s("admin-events"), null), Verdict.REFUSE);
        t("GET clients refused", d("GET", s("clients"), null), Verdict.REFUSE);
        t("GET users/{id}/credentials refused", d("GET", s("users", U, "credentials"), null), Verdict.REFUSE);
        t("GET users/{id}/role-mappings refused", d("GET", s("users", U, "role-mappings"), null), Verdict.REFUSE);
        t("GET users/{id}/sessions refused", d("GET", s("users", U, "sessions"), null), Verdict.REFUSE);
        t("GET users/count allowed (a count, filtered by Keycloak's own permissions)", d("GET", s("users", "count"), null), Verdict.ALLOW);
        t("GET groups/{id}/role-mappings refused", d("GET", s("groups", G, "role-mappings"), null), Verdict.REFUSE);
        t("GET group-by-path with no path refused", d("GET", s("group-by-path"), null), Verdict.REFUSE);
        t("GET stig-accounts refused", d("GET", s("stig-accounts", "users"), null), Verdict.REFUSE);
        t("GET users/{bad id} refused", d("GET", s("users", "a b"), null), Verdict.REFUSE);

        // writes: the listed ones, with a fresh authentication
        t("POST stig-accounts/users, fresh: allowed", d("POST", s("stig-accounts", "users"), NOW - 10), Verdict.ALLOW);
        t("POST stig-accounts/users/{id}/setup-email, fresh", d("POST", s("stig-accounts", "users", U, "setup-email"), NOW - 299), Verdict.ALLOW);
        t("POST stig-accounts/users/{id}/disable, fresh", d("POST", s("stig-accounts", "users", U, "disable"), NOW), Verdict.ALLOW);
        t("PUT users/{id}/groups/{gid}, fresh", d("PUT", s("users", U, "groups", G), NOW - 60), Verdict.ALLOW);
        t("DELETE users/{id}/groups/{gid}, fresh", d("DELETE", s("users", U, "groups", G), NOW - 60), Verdict.ALLOW);
        t("write exactly at the max age: allowed", d("POST", s("stig-accounts", "users"), NOW - 300), Verdict.ALLOW);
        t("write one second past the max age: step-up", d("POST", s("stig-accounts", "users"), NOW - 301), Verdict.STEP_UP);
        t("write with no auth_time in the token: step-up", d("POST", s("stig-accounts", "users"), null), Verdict.STEP_UP);
        t("write with auth_time 0: step-up", d("PUT", s("users", U, "groups", G), 0L), Verdict.STEP_UP);
        t("write with auth_time far in the future: step-up", d("PUT", s("users", U, "groups", G), NOW + 3600), Verdict.STEP_UP);
        t("write with auth_time within clock skew: allowed", d("PUT", s("users", U, "groups", G), NOW + 20), Verdict.ALLOW);
        t("custom max age 600: 500 s old allowed", AdminApiStepUp.decide(P, "600", "POST", s("stig-accounts", "users"), NOW - 500, NOW), Verdict.ALLOW);
        t("custom max age 60: 61 s old step-up", AdminApiStepUp.decide(P, "60", "POST", s("stig-accounts", "users"), NOW - 61, NOW), Verdict.STEP_UP);

        // writes outside the profile: refused even when fresh
        t("PUT users/{id} (edit) refused", d("PUT", s("users", U), NOW), Verdict.REFUSE);
        t("DELETE users/{id} refused", d("DELETE", s("users", U), NOW), Verdict.REFUSE);
        t("POST users (create through the admin API) refused", d("POST", s("users"), NOW), Verdict.REFUSE);
        t("PUT users/{id}/reset-password refused", d("PUT", s("users", U, "reset-password"), NOW), Verdict.REFUSE);
        t("PUT users/{id}/execute-actions-email refused", d("PUT", s("users", U, "execute-actions-email"), NOW), Verdict.REFUSE);
        t("DELETE users/{id}/credentials/{c} refused", d("DELETE", s("users", U, "credentials", G), NOW), Verdict.REFUSE);
        t("POST users/{id}/role-mappings/realm refused", d("POST", s("users", U, "role-mappings", "realm"), NOW), Verdict.REFUSE);
        t("POST users/{id}/impersonation refused", d("POST", s("users", U, "impersonation"), NOW), Verdict.REFUSE);
        t("POST users/{id}/logout refused", d("POST", s("users", U, "logout"), NOW), Verdict.REFUSE);
        t("PUT users/{id}/groups (no group id) refused", d("PUT", s("users", U, "groups"), NOW), Verdict.REFUSE);
        t("POST users/{id}/groups/{gid} refused (PUT only)", d("POST", s("users", U, "groups", G), NOW), Verdict.REFUSE);
        t("PATCH stig-accounts/users refused", d("PATCH", s("stig-accounts", "users"), NOW), Verdict.REFUSE);
        t("POST stig-accounts/users/{id}/enable refused", d("POST", s("stig-accounts", "users", U, "enable"), NOW), Verdict.REFUSE);
        t("POST stig-accounts/users/{id}/recover refused", d("POST", s("stig-accounts", "users", U, "recover"), NOW), Verdict.REFUSE);
        t("DELETE stig-accounts/users/{id} refused", d("DELETE", s("stig-accounts", "users", U), NOW), Verdict.REFUSE);
        t("POST groups/{id}/children refused", d("POST", s("groups", G, "children"), NOW), Verdict.REFUSE);
        t("PUT clients/{id} refused", d("PUT", s("clients", G), NOW), Verdict.REFUSE);
        t("PUT the realm refused", d("PUT", s(), NOW), Verdict.REFUSE);
        t("an out-of-profile write is refused, not stepped up, even when stale", d("PUT", s("users", U), NOW - 9999), Verdict.REFUSE);

        // stig.admin-api.operations
        String OPS = "create,setup-email,membership";
        t("operations unset: the four legacy ones only", AdminApiStepUp.operations(null), AdminApiStepUp.LEGACY_OPERATIONS);
        t("... and no portal operation", AdminApiStepUp.operations(null).stream().noneMatch(AdminApiStepUp.PORTAL_OPERATIONS::contains), true);
        t("operations create,setup-email,membership: disable REFUSED, even fresh",
                AdminApiStepUp.decide(P, null, OPS, "POST", s("stig-accounts", "users", U, "disable"), NOW, NOW), Verdict.REFUSE);
        t("... create allowed", AdminApiStepUp.decide(P, null, OPS, "POST", s("stig-accounts", "users"), NOW, NOW), Verdict.ALLOW);
        t("... setup-email allowed", AdminApiStepUp.decide(P, null, OPS, "POST", s("stig-accounts", "users", U, "setup-email"), NOW, NOW), Verdict.ALLOW);
        t("... membership PUT allowed", AdminApiStepUp.decide(P, null, OPS, "PUT", s("users", U, "groups", G), NOW, NOW), Verdict.ALLOW);
        t("... membership DELETE allowed", AdminApiStepUp.decide(P, null, OPS, "DELETE", s("users", U, "groups", G), NOW, NOW), Verdict.ALLOW);
        t("... a stale allowed write still steps up", AdminApiStepUp.decide(P, null, OPS, "POST", s("stig-accounts", "users"), NOW - 999, NOW), Verdict.STEP_UP);
        t("... reads unaffected", AdminApiStepUp.decide(P, null, OPS, "GET", s("users", U, "groups"), null, NOW), Verdict.ALLOW);
        t("operations create,setup-email only: membership REFUSED",
                AdminApiStepUp.decide(P, null, "create,setup-email", "DELETE", s("users", U, "groups", G), NOW, NOW), Verdict.REFUSE);
        t("operations set but blank: every request refused", AdminApiStepUp.decide(P, null, " ", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("operations with an empty entry: refused", AdminApiStepUp.decide(P, null, "create,", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("operations naming an unknown one: refused", AdminApiStepUp.decide(P, null, "create,impersonate", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("operations set WITHOUT the profile: every request refused (it would confine nothing)",
                AdminApiStepUp.decide(null, null, "create", "GET", s("users"), NOW, NOW), Verdict.REFUSE);
        t("... and a write too", AdminApiStepUp.decide(null, null, OPS, "POST", s("stig-accounts", "users"), NOW, NOW), Verdict.REFUSE);
        t("neither attribute: not restricted", AdminApiStepUp.decide(null, null, null, "DELETE", s("users", U), NOW, NOW), Verdict.NOT_RESTRICTED);
        t("operations tolerate spaces", AdminApiStepUp.operations(" create , membership "), java.util.Set.of("create", "membership"));

        // the portal operations: off unless listed, each its own entry, writes stepped up, status a read
        String[] PW = {"reset-otp", "reset-password", "unlock", "logout", "link-cac"};
        for (String op : PW) {
            t("POST stig-accounts/users/{id}/" + op + ": the operation is " + op, AdminApiStepUp.writeOperation("POST", s("stig-accounts", "users", U, op)), op);
            t("... refused with the operations list unset (off unless listed), even fresh", d("POST", s("stig-accounts", "users", U, op), NOW), Verdict.REFUSE);
            t("... refused when the list names everything else", AdminApiStepUp.decide(P, null,
                    "create,setup-email,disable,membership,status," + String.join(",", java.util.Arrays.stream(PW).filter(x -> !x.equals(op)).toList()),
                    "POST", s("stig-accounts", "users", U, op), NOW, NOW), Verdict.REFUSE);
            t("... allowed when listed, fresh", AdminApiStepUp.decide(P, null, op, "POST", s("stig-accounts", "users", U, op), NOW - 10, NOW), Verdict.ALLOW);
            t("... step-up when listed and stale", AdminApiStepUp.decide(P, null, op, "POST", s("stig-accounts", "users", U, op), NOW - 301, NOW), Verdict.STEP_UP);
            t("... step-up when listed and no auth_time", AdminApiStepUp.decide(P, null, op, "POST", s("stig-accounts", "users", U, op), null, NOW), Verdict.STEP_UP);
            t("... GET of it refused", AdminApiStepUp.decide(P, null, op, "GET", s("stig-accounts", "users", U, op), NOW, NOW), Verdict.REFUSE);
            t("... PUT of it refused", AdminApiStepUp.decide(P, null, op, "PUT", s("stig-accounts", "users", U, op), NOW, NOW), Verdict.REFUSE);
            t("... with a bad id refused", AdminApiStepUp.decide(P, null, op, "POST", s("stig-accounts", "users", "a b", op), NOW, NOW), Verdict.REFUSE);
            t("... one segment deeper refused", AdminApiStepUp.decide(P, null, op, "POST", s("stig-accounts", "users", U, op, "x"), NOW, NOW), Verdict.REFUSE);
        }
        t("Keycloak's own POST users/{id}/logout stays refused, even with logout listed",
                AdminApiStepUp.decide(P, null, "logout", "POST", s("users", U, "logout"), NOW, NOW), Verdict.REFUSE);
        t("Keycloak's own DELETE attack-detection stays refused, even with unlock listed",
                AdminApiStepUp.decide(P, null, "unlock", "DELETE", s("attack-detection", "brute-force", "users", U), NOW, NOW), Verdict.REFUSE);
        t("Keycloak's own credentials DELETE stays refused, even with reset-otp listed",
                AdminApiStepUp.decide(P, null, "reset-otp", "DELETE", s("users", U, "credentials", G), NOW, NOW), Verdict.REFUSE);
        t("GET stig-accounts/users/{id}/status: refused unless listed", d("GET", s("stig-accounts", "users", U, "status"), null), Verdict.REFUSE);
        t("GET stig-accounts/users/status: refused unless listed", d("GET", s("stig-accounts", "users", "status"), null), Verdict.REFUSE);
        t("status listed: GET users/{id}/status allowed with NO step-up (a read; stale token)",
                AdminApiStepUp.decide(P, null, "status", "GET", s("stig-accounts", "users", U, "status"), NOW - 9999, NOW), Verdict.ALLOW);
        t("status listed: GET users/status allowed", AdminApiStepUp.decide(P, null, "status", "GET", s("stig-accounts", "users", "status"), null, NOW), Verdict.ALLOW);
        t("status listed: POST users/{id}/status refused", AdminApiStepUp.decide(P, null, "status", "POST", s("stig-accounts", "users", U, "status"), NOW, NOW), Verdict.REFUSE);
        t("status listed: GET stig-accounts/users (a list) still refused", AdminApiStepUp.decide(P, null, "status", "GET", s("stig-accounts", "users"), NOW, NOW), Verdict.REFUSE);
        t("status listed: GET users/{bad id}/status refused", AdminApiStepUp.decide(P, null, "status", "GET", s("stig-accounts", "users", "a;b", "status"), NOW, NOW), Verdict.REFUSE);
        t("status listed: other reads unaffected", AdminApiStepUp.decide(P, null, "status", "GET", s("users", U, "groups"), null, NOW), Verdict.ALLOW);
        t("a list naming every operation parses", AdminApiStepUp.operations(String.join(",", AdminApiStepUp.OPERATIONS)), AdminApiStepUp.OPERATIONS);
        t("ten operations in all", AdminApiStepUp.OPERATIONS.size(), 10);
        t("fresh: at the max age", AdminApiStepUp.fresh(NOW - 300, 300, NOW), true);
        t("fresh: one second past", AdminApiStepUp.fresh(NOW - 301, 300, NOW), false);
        t("fresh: a malformed max age is never fresh", AdminApiStepUp.fresh(NOW, -1, NOW), false);
        t("capability marker is 3 (the portal operations)", AdminAllowlistGateAuthenticatorFactory.ADMIN_API_PROFILE_VERSION, "3");

        // path parsing
        t("afterRealm: a realm's sub-path", AdminApiStepUp.afterRealm(s("admin", "realms", "r1", "users", U)), s("users", U));
        t("afterRealm: the realm itself", AdminApiStepUp.afterRealm(s("admin", "realms", "r1")), s());
        t("afterRealm: /admin/realms (realm list)", AdminApiStepUp.afterRealm(s("admin", "realms")), null);
        t("afterRealm: under a relative path", AdminApiStepUp.afterRealm(s("auth", "admin", "realms", "r1", "groups")), s("groups"));
        t("afterRealm: empty segments dropped", AdminApiStepUp.afterRealm(s("admin", "", "realms", "r1", "", "users")), s("users"));
        t("challenge names insufficient_user_authentication and max_age",
                AdminApiStepUp.challenge(300).contains("insufficient_user_authentication") && AdminApiStepUp.challenge(300).contains("max_age=\"300\""), true);

        // audit lines: a %0a (or a decoded newline) in the path never starts a forged line
        String raw = "/admin/realms/r1/users%0aSTIG-ADMIN-FORGED%20line";
        t("logSafe keeps a raw path's percent-encoding as it is", AdminApiGuardFilter.logSafe(raw), raw);
        t("logSafe: a decoded LF/CR becomes '?'", AdminApiGuardFilter.logSafe("/admin/realms/r1/users\nSTIG-FORGED\r\n"), "/admin/realms/r1/users?STIG-FORGED??");
        t("logSafe: other control characters (NUL, ESC, DEL, NEL, U+2028) become '?'",
                AdminApiGuardFilter.logSafe("a\u0000b\u001bc\u007fd\u0085e\u2028f"), "a?b?c?d?e?f");
        t("logSafe: no line break survives in any input", !AdminApiGuardFilter.logSafe(java.net.URI.create("http://h" + raw).getPath()).contains("\n"), true);
        t("logSafe caps the length at 512", AdminApiGuardFilter.logSafe("x".repeat(2000)).length(), 512);
        t("logSafe(null)", AdminApiGuardFilter.logSafe(null), "-");
        t("rate window is a sliding hour", AccountsPolicy.RATE_WINDOW, 3600);

        // stig-accounts reference
        t("reference absent", AccountsPolicy.reference(null), null);
        t("reference AR-1234", AccountsPolicy.reference("AR-1234"), "AR-1234");
        t("reference trimmed", AccountsPolicy.reference(" req:42 "), "req:42");
        t("reference with a space invalid", AccountsPolicy.reference("a b"), "");
        t("reference with markup invalid", AccountsPolicy.reference("<x>"), "");
        t("reference blank invalid", AccountsPolicy.reference(" "), "");
        t("reference of 65 characters invalid", AccountsPolicy.reference("a".repeat(65)), "");
        t("disable limit is 20 per hour", AccountsPolicy.DISABLE_PER_HOUR, 20);

        System.out.printf("AdminApiStepUpTest: %d/%d passed%n", run - failed, run);
        if (failed > 0) System.exit(1);
    }
}
