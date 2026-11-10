package mil.stig.keycloak;

import java.util.List;

/** Plain-Java test (no framework); exit 1 on any failure. Raw (undecoded) request paths. */
public final class PublicPathPolicyTest {
    static int failed = 0;
    static final PublicPathPolicy P = new PublicPathPolicy(List.of("/realms/defconai", "/realms/defconai/", "/admin/defconai/",
            "/admin/realms/defconai/", "/admin/serverinfo", "/resources/"));
    static void expect(boolean allow, String raw) {
        boolean got = P.allows(raw);
        System.out.println((got == allow ? "PASS " : "FAIL ") + (allow ? "allowed " : "refused ") + raw.replace("\u0000", "\\0"));
        if (got != allow) failed++;
    }
    public static void main(String[] a) {
        for (String bad : new String[] {
                "/realms/master", "/realms/master/protocol/openid-connect/token", "/admin/master/console/", "/admin/realms/master",
                "/realms/master;x=y/account", "//realms/master", "/realms/MASTER", "/realms%2Fmaster", "/realms/%6Daster",
                "/realms/master/.", "/realms/master/../master", "/realms/defconai/../master", "/realms/defconai/..",
                "/realms/x%2F..%2Fmaster", "/realms/defconai%2F..%2Fmaster", "/realms/x%5Cmaster", "/realms\\master",
                "/realms/defconai/./account", "/realms/ master", "/realms/ｍａｓｔｅｒ",
                "/realms/defconai\u0000", "/realms/defconai/é", "/realms/defconaı", "/realms/DEFCONAI/account",
                "/realms/defconaix/account", "/realms/defconai.", "/", "", "/favicon.ico", "/health/ready", "/metrics",
                "/admin/serverinfo/", "/admin/realms/", "/admin/", "/realms/", "/js/keycloak.js", "/realms/defconai/account%20x"}) {
            expect(false, bad);
        }
        for (String ok : new String[] {
                "/realms/defconai", "/realms/defconai/", "/realms/defconai/.well-known/openid-configuration",
                "/realms/defconai/protocol/openid-connect/auth", "/realms/defconai/account/", "/realms/defconai/broker/entra/endpoint",
                "/admin/defconai/console/", "/admin/defconai/console/whoami", "/admin/realms/defconai/users",
                "/admin/serverinfo", "/resources/b8x1q/login/dod-stig/js/dod-banner.js"}) {
            expect(true, ok);
        }
        System.out.println(failed == 0 ? "all passed" : failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
