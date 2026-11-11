package mil.stig.keycloak;

import jakarta.ws.rs.core.MultivaluedHashMap;

/** Unit tests of the concealed-attribute probe detection. Run by build.sh. */
public final class AdminApiGuardTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean got, boolean want) { run++; boolean ok = got == want; if (!ok) failed++; System.out.printf("%s  %-60s%n", ok ? "PASS" : "FAIL", n); }
    static MultivaluedHashMap<String, String> m(String... kv) {
        MultivaluedHashMap<String, String> x = new MultivaluedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) x.add(kv[i], kv[i + 1]);
        return x;
    }
    public static void main(String[] a) {
        t("q=cac_edipi:1234567890", AdminApiGuardFilter.namesConcealed(m("q", "cac_edipi:1234567890")), true);
        t("q=CAC_EDIPI:... (case)", AdminApiGuardFilter.namesConcealed(m("q", "CAC_EDIPI:1")), true);
        t("q with two attributes, one concealed", AdminApiGuardFilter.namesConcealed(m("q", "dept:x entra_oid:abc")), true);
        t("search=entra_amr", AdminApiGuardFilter.namesConcealed(m("search", "entra_amr")), true);
        t("a concealed name as a parameter KEY", AdminApiGuardFilter.namesConcealed(m("stig_created_by", "x")), true);
        t("q=dept:x", AdminApiGuardFilter.namesConcealed(m("q", "dept:x")), false);
        t("search=jane", AdminApiGuardFilter.namesConcealed(m("search", "jane", "max", "10")), false);
        t("no parameters", AdminApiGuardFilter.namesConcealed(m()), false);
        java.util.function.BiFunction<String, String, AdminApiGuardFilter.Kind> c = (segs, raw) ->
                AdminApiGuardFilter.classify(java.util.Arrays.asList(segs.split("/", -1)), raw);
        t("admin API path", c.apply("admin/realms/defconai/users", "/admin/realms/defconai/users") == AdminApiGuardFilter.Kind.ADMIN, true);
        t("double slash: segments still admin,realms", c.apply("admin//realms/defconai/users", "/admin//realms/defconai/users") == AdminApiGuardFilter.Kind.ADMIN, true);
        t("matrix params stripped from segments", c.apply("admin/realms/defconai/users", "/admin;x=y/realms;a=b/defconai/users") == AdminApiGuardFilter.Kind.ADMIN, true);
        t("leading empty segment", c.apply("/admin/realms/x", "//admin/realms/x") == AdminApiGuardFilter.Kind.ADMIN, true);
        t("encoded slash: unclassifiable -> refused", c.apply("admin%2Frealms", "/admin%2Frealms/x/users") == AdminApiGuardFilter.Kind.UNCLASSIFIABLE, true);
        t("encoded backslash: unclassifiable", c.apply("admin\\realms", "/admin%5Crealms/x") == AdminApiGuardFilter.Kind.UNCLASSIFIABLE, true);
        t("dot segment near admin: unclassifiable", c.apply("x/admin", "/x/./admin/realms") == AdminApiGuardFilter.Kind.UNCLASSIFIABLE, true);
        t("double-encoded: unclassifiable", c.apply("admin%252Frealms", "/admin%252Frealms") == AdminApiGuardFilter.Kind.UNCLASSIFIABLE, true);
        t("realm sign-in path: not admin", c.apply("realms/defconai/protocol/openid-connect/auth", "/realms/defconai/protocol/openid-connect/auth") == AdminApiGuardFilter.Kind.NOT_ADMIN, true);
        t("admin console (not the API): not admin by segments", c.apply("admin/defconai/console/", "/admin/defconai/console/") == AdminApiGuardFilter.Kind.NOT_ADMIN, true);
        t("upper-case ADMIN: not Keycloak's admin path", c.apply("ADMIN/realms/x", "/ADMIN/realms/x") == AdminApiGuardFilter.Kind.NOT_ADMIN, true);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
