package mil.stig.keycloak;

import java.util.List;

/** Unit tests of the admin-change guard's representation parsing (role / group ids). Run by build.sh. */
public final class AdminChangeGuardTest {
    public static void main(String[] a) {
        int failed = 0, run = 0;
        String roles = "[{\"id\":\"11111111-2222-4333-8444-555555555555\",\"name\":\"realm-admin\",\"composite\":true,"
                + "\"clientRole\":true,\"containerId\":\"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\"},{\"id\" : \"66666666-7777-4888-9999-000000000000\",\"name\":\"view-users\"}]";
        Object[][] cases = {
            {"two role representations -> both ids, containerId ignored", roles,
             List.of("11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000")},
            {"no representation -> nothing", null, List.of()},
            {"a group representation -> its id", "{\"id\":\"12345678-1234-4234-8234-123456789012\",\"name\":\"idp-admin\",\"path\":\"/roles/idp-admin\"}",
             List.of("12345678-1234-4234-8234-123456789012")},
            {"not an id-shaped value -> nothing", "[{\"id\":\"realm-admin\"}]", List.of()},
        };
        for (Object[] c : cases) {
            run++;
            List<String> got = AdminChangeGuardEventListenerProviderFactory.Guard.ids((String) c[1]);
            boolean ok = got.equals(c[2]);
            if (!ok) failed++;
            System.out.printf("%s  %-62s %s%n", ok ? "PASS" : "FAIL", c[0], got);
        }
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
