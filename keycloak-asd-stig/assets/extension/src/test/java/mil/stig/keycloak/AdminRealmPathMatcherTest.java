package mil.stig.keycloak;

import java.util.Arrays;
import java.util.List;

/** Plain-Java test (no framework): java AdminRealmPathMatcherTest; exit 1 on any failure. The inputs are what
 *  JAX-RS getPathSegments(true) yields for each raw request path (decoded, matrix parameters removed). */
public final class AdminRealmPathMatcherTest {
    static int failed = 0;
    static void expect(boolean want, String label, String... segs) {
        boolean got = AdminRealmPathMatcher.guarded(Arrays.asList(segs), "master");
        System.out.println((got == want ? "PASS " : "FAIL ") + (want ? "guarded   " : "allowed   ") + label);
        if (got != want) failed++;
    }
    public static void main(String[] a) {
        expect(true, "/realms/master", "realms", "master");
        expect(true, "/realms/master/protocol/openid-connect/token", "realms", "master", "protocol", "openid-connect", "token");
        expect(true, "/realms/master;x=y/account (matrix stripped)", "realms", "master", "account");
        expect(true, "//realms/master (empty segment)", "", "realms", "master");
        expect(true, "/realms/MASTER (case)", "realms", "MASTER");
        expect(true, "/realms%2Fmaster (encoded slash, one segment)", "realms/master");
        expect(true, "/realms/%6Daster (encoded letter, decoded)", "realms", "master");
        expect(true, "/realms/master/. (trailing dot)", "realms", "master", ".");
        expect(true, "/realms/master/../master", "realms", "master", "..", "master");
        expect(true, "/realms/defconai/../master", "realms", "defconai", "..", "master");
        expect(true, "/admin/master/console/", "admin", "master", "console", "");
        expect(true, "/admin/realms/master/users", "admin", "realms", "master", "users");
        expect(true, "/admin/realms/Master (case)", "admin", "realms", "Master");
        expect(true, "/realms\\master (backslash)", "realms\\master");
        expect(true, "/realms/ma%00ster (control char)", "realms", "ma\u0000ster");
        expect(true, "/realms/%25... (still encoded)", "realms", "%6Daster");
        expect(true, "/../realms/master (above root)", "..", "realms", "master");
        expect(false, "/realms/defconai", "realms", "defconai");
        expect(false, "/realms/defconai/protocol/openid-connect/auth", "realms", "defconai", "protocol", "openid-connect", "auth");
        expect(false, "/admin/defconai/console/", "admin", "defconai", "console", "");
        expect(false, "/admin/realms/defconai/users", "admin", "realms", "defconai", "users");
        expect(false, "/realms/masterful (prefix only)", "realms", "masterful");
        expect(false, "/resources/x/master.js", "resources", "x", "master.js");
        expect(false, "/health/ready", "health", "ready");
        System.out.println(failed == 0 ? "all passed" : failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
