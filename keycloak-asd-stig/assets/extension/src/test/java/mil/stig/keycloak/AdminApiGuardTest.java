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
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
