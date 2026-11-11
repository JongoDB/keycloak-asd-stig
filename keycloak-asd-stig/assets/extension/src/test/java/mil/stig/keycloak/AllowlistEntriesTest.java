package mil.stig.keycloak;

import java.util.Set;

/** Unit tests of the allowlist entries the gate reads, enforced realms, and admin-event concealment. Run by build.sh. */
public final class AllowlistEntriesTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean ok) { run++; if (!ok) failed++; System.out.printf("%s  %-74s%n", ok ? "PASS" : "FAIL", n); }
    public static void main(String[] a) {
        var e = StigAdministrators.parseEntries("u1=group:/roles/idp-admin;u2=role:query-users,view-users");
        t("parses grant items (group:, role:, bare)", e != null && e.size() == 2 && e.get("u1").equals(Set.of("group:/roles/idp-admin"))
                && e.get("u2").equals(Set.of("role:query-users", "view-users")));
        t("absent value -> null (fail closed)", StigAdministrators.parseEntries(null) == null);
        t("blank value -> null", StigAdministrators.parseEntries("  ") == null);
        t("entry without '=' -> null", StigAdministrators.parseEntries("u1=view-users;u2") == null);
        t("empty id -> null", StigAdministrators.parseEntries("=view-users") == null);
        t("empty item list -> null", StigAdministrators.parseEntries("u1=") == null);
        t("empty item between commas -> null", StigAdministrators.parseEntries("u1=a,,b") == null);
        t("duplicate id -> null", StigAdministrators.parseEntries("u1=a;u1=b") == null);
        t("second '=' -> null", StigAdministrators.parseEntries("u1=a=b") == null);
        t("trailing ';' -> null", StigAdministrators.parseEntries("u1=a;") == null);
        t("effective within what the grant permits -> not exceeding", !StigAdministrators.exceedsEntry(Set.of("query-users"), Set.of("query-users", "view-users")));
        t("one role beyond -> exceeding", StigAdministrators.exceedsEntry(Set.of("query-users", "realm-admin"), Set.of("query-users")));
        t("grant could not be resolved (null) -> exceeding (fail closed)", StigAdministrators.exceedsEntry(Set.of("query-users"), null));
        t("enforced realms: parsed from the configuration", StigAdministrators.enforcedRealms("defconai, other ,").equals(Set.of("defconai", "other")));
        t("enforced realms: none configured -> empty", StigAdministrators.enforcedRealms(null).isEmpty());
        String ev = "{\"username\":\"j\",\"attributes\":{\"cac_edipi\":[\"1234567890\"],\"dept\":[\"x\"]},\"x\":[{\"entra_oid\":\"o\"}]}";
        String s = AdminAttributeConcealmentFilter.scrub(ev);
        t("admin-event representation: concealed names removed at any depth", s != null && !s.contains("cac_edipi") && !s.contains("1234567890")
                && !s.contains("entra_oid") && s.contains("dept"));
        t("admin-event representation: nothing concealed -> unchanged", "{\"a\":1}".equals(AdminAttributeConcealmentFilter.scrub("{\"a\":1}")));
        t("admin-event representation: a concealed name inside a value -> withheld (null)",
                AdminAttributeConcealmentFilter.scrub("{\"q\":\"cac_edipi:1234567890\"}") == null);
        t("admin-event representation: unparseable and mentions one -> withheld", AdminAttributeConcealmentFilter.scrub("cac_edipi=1") == null);
        t("admin-event representation: null stays null", AdminAttributeConcealmentFilter.scrub(null) == null);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
