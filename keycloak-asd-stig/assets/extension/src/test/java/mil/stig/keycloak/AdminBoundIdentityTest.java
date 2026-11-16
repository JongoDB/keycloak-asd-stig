package mil.stig.keycloak;

import java.util.List;
import java.util.Map;

/** Unit tests of the administrator-bound identity decision (no Keycloak runtime needed). Run by build.sh. */
public final class AdminBoundIdentityTest {
    static int failed = 0, run = 0;
    static final String T = "00000000-0000-4000-8000-000000000001", OID = "00000000-0000-4000-8000-0000000000a1";
    static final AdminBoundIdentity.Cfg C = new AdminBoundIdentity(Map.of(AdminBoundIdentity.P_TENANT, T)).cfg();

    static void expect(String name, String why, boolean allowed) {
        run++;
        boolean ok = allowed ? why == null : why != null;
        if (!ok) failed++;
        System.out.printf("%s  %-70s %s%n", ok ? "PASS" : "FAIL", name, why == null ? "allowed" : "refused: " + why);
    }

    public static void main(String[] a) {
        List<String> none = List.of();
        expect("the configured provider, tenant and administrator-set identity", AdminBoundIdentity.refusal(C, "entra", OID, T, OID, none), true);
        expect("tenant compared case-insensitively", AdminBoundIdentity.refusal(C, "entra", OID, T.toUpperCase(), OID, none), true);
        expect("another identity than the administrator-set one", AdminBoundIdentity.refusal(C, "entra", "ffffffff-0000-4000-8000-000000000000", T, OID, none), false);
        expect("a second provider presenting the SAME oid", AdminBoundIdentity.refusal(C, "entra2", OID, T, OID, none), false);
        expect("the same provider, another tenant", AdminBoundIdentity.refusal(C, "entra", OID, "11111111-2222-4333-8444-555555555555", OID, none), false);
        expect("no tenant vouched", AdminBoundIdentity.refusal(C, "entra", OID, null, OID, none), false);
        expect("nothing vouched", AdminBoundIdentity.refusal(C, "entra", null, T, OID, none), false);
        expect("no administrator-set identity on the account", AdminBoundIdentity.refusal(C, "entra", OID, T, null, none), false);
        expect("a mapper writes the administrator-set attribute (even with matching values)",
               AdminBoundIdentity.refusal(C, "entra", OID, T, OID, List.of("entra_vouched_oid", "entra_oid")), false);
        expect("... matched case-insensitively", AdminBoundIdentity.refusal(C, "entra", OID, T, OID, List.of("entra_oid")), false);
        AdminBoundIdentity.Cfg unconf = new AdminBoundIdentity(null).cfg();
        expect("unconfigured (no tenant-id)", AdminBoundIdentity.refusal(unconf, "entra", OID, T, OID, none), false);
        expect("preconditions alone: first broker login, configured provider and tenant",
               AdminBoundIdentity.preconditions(C, "entra", OID, T, none), true);
        expect("preconditions alone: another provider", AdminBoundIdentity.preconditions(C, "t-entra", OID, T, none), false);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
