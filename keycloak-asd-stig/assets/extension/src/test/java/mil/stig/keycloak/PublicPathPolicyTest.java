package mil.stig.keycloak;

import java.util.List;

/** Plain-Java test (no framework); exit 1 on any failure. Raw (undecoded) request paths. */
public final class PublicPathPolicyTest {
    static int failed = 0;
    static final PublicPathPolicy P = new PublicPathPolicy(List.of("/realms/example", "/realms/example/", "/admin/example/",
            "/admin/realms/example", "/admin/realms/example/", "/admin/serverinfo", "/resources/"));
    static void expect(boolean allow, String raw) {
        boolean got = P.allows(raw);
        System.out.println((got == allow ? "PASS " : "FAIL ") + (allow ? "allowed " : "refused ") + raw.replace("\u0000", "\\0"));
        if (got != allow) failed++;
    }
    public static void main(String[] a) {
        for (String bad : new String[] {
                "/realms/master", "/realms/master/protocol/openid-connect/token", "/admin/master/console/", "/admin/realms/master",
                "/realms/master;x=y/account", "//realms/master", "/realms/MASTER", "/realms%2Fmaster", "/realms/%6Daster",
                "/realms/master/.", "/realms/master/../master", "/realms/example/../master", "/realms/example/..",
                "/realms/x%2F..%2Fmaster", "/realms/example%2F..%2Fmaster", "/realms/x%5Cmaster", "/realms\\master",
                "/realms/example/./account", "/realms/ master", "/realms/ｍａｓｔｅｒ",
                "/realms/example\u0000", "/realms/example/é", "/realms/exampl\u0435", "/realms/EXAMPLE/account",
                "/realms/examplex/account", "/realms/example.", "/", "", "/favicon.ico", "/health/ready", "/metrics",
                "/admin/serverinfo/", "/admin/realms/", "/admin/", "/realms/", "/js/keycloak.js", "/realms/example/account%20x"}) {
            expect(false, bad);
        }
        for (String ok : new String[] {
                "/realms/example", "/realms/example/", "/realms/example/.well-known/openid-configuration",
                "/realms/example/protocol/openid-connect/auth", "/realms/example/account/", "/realms/example/broker/entra/endpoint",
                "/admin/example/console/", "/admin/example/console/whoami", "/admin/realms/example", "/admin/realms/example/users",
                "/admin/serverinfo", "/resources/b8x1q/login/dod-stig/js/dod-banner.js"}) {
            expect(true, ok);
        }
        System.out.println(failed == 0 ? "all passed" : failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
