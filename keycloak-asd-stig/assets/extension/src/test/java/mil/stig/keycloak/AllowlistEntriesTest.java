package mil.stig.keycloak;

import java.util.Set;

/** Unit tests of the allowlist entries the gate reads (role extent per vetted administrator). Run by build.sh. */
public final class AllowlistEntriesTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean ok) { run++; if (!ok) failed++; System.out.printf("%s  %-70s%n", ok ? "PASS" : "FAIL", n); }
    public static void main(String[] a) {
        var e = StigAdministrators.parseEntries("u1=query-users,view-users;u2=realm-admin,manage-users,view-users");
        t("parses two entries", e != null && e.size() == 2 && e.get("u1").equals(Set.of("query-users", "view-users")));
        t("absent value -> null (fail closed)", StigAdministrators.parseEntries(null) == null);
        t("blank value -> null", StigAdministrators.parseEntries("  ") == null);
        t("entry without '=' -> null", StigAdministrators.parseEntries("u1=view-users;u2") == null);
        t("empty id -> null", StigAdministrators.parseEntries("=view-users") == null);
        t("empty role list -> null", StigAdministrators.parseEntries("u1=") == null);
        t("empty role between commas -> null", StigAdministrators.parseEntries("u1=a,,b") == null);
        t("duplicate id -> null", StigAdministrators.parseEntries("u1=a;u1=b") == null);
        t("second '=' -> null", StigAdministrators.parseEntries("u1=a=b") == null);
        t("trailing ';' -> null", StigAdministrators.parseEntries("u1=a;") == null);
        t("effective within entry -> not exceeding", !StigAdministrators.exceedsEntry(Set.of("query-users"), Set.of("query-users", "view-users")));
        t("effective equals entry -> not exceeding", !StigAdministrators.exceedsEntry(Set.of("a", "b"), Set.of("a", "b")));
        t("one role beyond the entry -> exceeding", StigAdministrators.exceedsEntry(Set.of("query-users", "realm-admin"), Set.of("query-users")));
        t("no entry -> exceeding (fail closed)", StigAdministrators.exceedsEntry(Set.of("query-users"), null));
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
