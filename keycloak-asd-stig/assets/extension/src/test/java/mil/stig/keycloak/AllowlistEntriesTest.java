package mil.stig.keycloak;

import java.util.Set;

/** Unit tests of the allowlist entries the gate reads, enforced realms, and admin-event concealment. Run by build.sh. */
public final class AllowlistEntriesTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean ok) { run++; if (!ok) failed++; System.out.printf("%s  %-74s%n", ok ? "PASS" : "FAIL", n); }
    public static void main(String[] a) {
        var e = StigAdministrators.parseEntries("u1=group:g1@query-users+view-users;u2=view-users,query-users");
        t("parses items (group:<id>@snapshot, older bare names)", e != null && e.size() == 2
                && e.get("u1").equals(Set.of("group:g1@query-users+view-users")) && e.get("u2").equals(Set.of("view-users", "query-users")));
        t("absent value -> null (fail closed)", StigAdministrators.parseEntries(null) == null);
        t("blank value -> null", StigAdministrators.parseEntries("  ") == null);
        t("entry without '=' -> null", StigAdministrators.parseEntries("u1=view-users;u2") == null);
        t("empty id -> null", StigAdministrators.parseEntries("=view-users") == null);
        t("empty item list -> null", StigAdministrators.parseEntries("u1=") == null);
        t("empty item between commas -> null", StigAdministrators.parseEntries("u1=a,,b") == null);
        t("duplicate id -> null", StigAdministrators.parseEntries("u1=a;u1=b") == null);
        t("second '=' -> null", StigAdministrators.parseEntries("u1=a=b") == null);
        t("trailing ';' -> null", StigAdministrators.parseEntries("u1=a;") == null);
        java.util.Map<String, Set<String>> groups = new java.util.HashMap<>();
        groups.put("g1", Set.of("query-users", "view-users"));
        java.util.function.Function<String, Set<String>> live = groups::get;
        t("within the snapshot -> VETTED", StigAdministrators.classify(Set.of("query-users"), Set.of("group:g1@query-users+view-users"), live)
                == StigAdministrators.Standing.VETTED);
        groups.put("g1", Set.of("query-users", "view-users", "manage-users"));
        t("the group carries MORE now and the user holds it -> NEEDS_REGRANT (not over-entry)",
                StigAdministrators.classify(Set.of("query-users", "manage-users"), Set.of("group:g1@query-users+view-users"), live)
                == StigAdministrators.Standing.NEEDS_REGRANT);
        t("a role outside even the live grant -> OVER_ENTRY",
                StigAdministrators.classify(Set.of("query-users", "realm-admin"), Set.of("group:g1@query-users+view-users"), live)
                == StigAdministrators.Standing.OVER_ENTRY);
        t("granted group id gone, nothing extra held -> NEEDS_REGRANT (refused)",
                StigAdministrators.classify(Set.of("query-users"), Set.of("group:gone@query-users"), live) == StigAdministrators.Standing.NEEDS_REGRANT);
        t("granted group id gone, a role beyond the snapshot -> OVER_ENTRY",
                StigAdministrators.classify(Set.of("query-users", "realm-admin"), Set.of("group:gone@query-users"), live) == StigAdministrators.Standing.OVER_ENTRY);
        t("the group is resolved by ID (a path is not an id: unknown -> refused)",
                StigAdministrators.classify(Set.of("query-users"), Set.of("group:/roles/idp-admin@query-users"), live) != StigAdministrators.Standing.VETTED);
        t("group item without a snapshot marker -> NOT_LISTED", StigAdministrators.classify(Set.of("query-users"), Set.of("group:g1"), live)
                == StigAdministrators.Standing.NOT_LISTED);
        t("unknown item kind (role:...) -> NOT_LISTED", StigAdministrators.classify(Set.of("query-users"), Set.of("role:query-users"), live)
                == StigAdministrators.Standing.NOT_LISTED);
        t("no items -> NOT_LISTED", StigAdministrators.classify(Set.of("query-users"), null, live) == StigAdministrators.Standing.NOT_LISTED);
        t("older format (bare expanded names) still read", StigAdministrators.classify(Set.of("query-users"), Set.of("query-users", "view-users"), live)
                == StigAdministrators.Standing.VETTED && StigAdministrators.classify(Set.of("realm-admin"), Set.of("query-users"), live)
                == StigAdministrators.Standing.OVER_ENTRY);
        t("enforced realms: parsed from the configuration", StigAdministrators.enforcedRealms("example, other ,").equals(Set.of("example", "other")));
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
