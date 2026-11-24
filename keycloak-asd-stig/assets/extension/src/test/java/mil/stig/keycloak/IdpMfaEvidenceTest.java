package mil.stig.keycloak;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Unit tests of the identity-provider MFA decision (no Keycloak runtime needed). Run by build.sh. */
public final class IdpMfaEvidenceTest {
    static int failed = 0, run = 0;
    static final String T = "00000000-0000-4000-8000-000000000001", T2 = "00000000-0000-4000-8000-000000000002",
            OTHER = "11111111-2222-4333-8444-555555555555", ISS = "https://issuer.example/" + T + "/v2.0";
    static final IdpMfaEvidence.Cfg C = IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, T));

    static void expect(String name, IdpMfaEvidence.Decision d, boolean accepted) {
        run++;
        boolean ok = d.accepted() == accepted;
        if (!ok) failed++;
        System.out.printf("%s  %-72s %s reason=%s amr=[%s]%n", ok ? "PASS" : "FAIL", name, d.accepted() ? "accepted" : "refused",
                d.reason(), d.amrText());
    }

    static Map<String, Object> tok(Object... kv) {
        Map<String, Object> m = new HashMap<>();
        m.put("iss", ISS);
        m.put("tid", T);
        m.put("amr", List.of("pwd", "mfa"));
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) m.remove((String) kv[i]); else m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    public static void main(String[] a) {
        // accept
        expect("accept: entra, trusted tenant, amr [pwd, mfa]", IdpMfaEvidence.decide(C, "entra", tok()), true);
        expect("accept: tenant compared case-insensitively", IdpMfaEvidence.decide(C, "entra", tok("tid", T.toUpperCase())), true);
        expect("accept: one of several trusted tenants",
               IdpMfaEvidence.decide(IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, OTHER + "##" + T)), "entra", tok()), true);
        expect("accept: a member, idp the tenant (v1 issuer form), acct 0",
               IdpMfaEvidence.decide(C, "entra", tok("idp", "https://sts.windows.net/" + T + "/", "acct", 0)), true);
        expect("accept: a member, idp the tenant (v2 issuer form)",
               IdpMfaEvidence.decide(C, "entra", tok("idp", "https://login.microsoftonline.com/" + T + "/v2.0")), true);
        expect("accept: a v1.0 ID token (iss sts.windows.net, upn, amr [pwd, mfa])",
               IdpMfaEvidence.decide(C, "entra", tok("iss", "https://sts.windows.net/" + T + "/", "ver", "1.0", "upn", "a@b.c")), true);
        IdpMfaEvidence.Cfg acr = IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, T, IdpMfaEvidence.P_ACR, "c1"));
        expect("accept: configured acr allow-list, acrs [c1], no amr", IdpMfaEvidence.decide(acr, "entra", tok("amr", null, "acrs", List.of("c1"))), true);
        expect("accept: configured acr allow-list, acr c1, no amr", IdpMfaEvidence.decide(acr, "entra", tok("amr", null, "acr", "c1")), true);
        // amr lacks mfa
        expect("refuse: amr [pwd]", IdpMfaEvidence.decide(C, "entra", tok("amr", List.of("pwd"))), false);
        expect("refuse: amr [pwd, rsa] (no mfa)", IdpMfaEvidence.decide(C, "entra", tok("amr", List.of("pwd", "rsa"))), false);
        expect("refuse: acr c1 when no acr allow-list is configured", IdpMfaEvidence.decide(C, "entra", tok("amr", List.of("pwd"), "acr", "c1")), false);
        expect("refuse: acrs [c2] not on the allow-list", IdpMfaEvidence.decide(acr, "entra", tok("amr", null, "acrs", List.of("c2"))), false);
        // wrong tid
        expect("refuse: another tenant", IdpMfaEvidence.decide(C, "entra", tok("tid", OTHER)), false);
        expect("refuse: tenant T2 when only T is trusted", IdpMfaEvidence.decide(C, "entra", tok("tid", T2)), false);
        // wrong IdP
        expect("refuse: another provider alias", IdpMfaEvidence.decide(C, "entra2", tok()), false);
        expect("refuse: not a brokered sign-in", IdpMfaEvidence.decide(C, null, tok()), false);
        expect("refuse: a guest (idp names another provider)", IdpMfaEvidence.decide(C, "entra", tok("idp", "live.com")), false);
        expect("refuse: a guest whose idp is ANOTHER tenant", IdpMfaEvidence.decide(C, "entra", tok("idp", "https://sts.windows.net/" + OTHER + "/")), false);
        expect("refuse: a guest (acct 1)", IdpMfaEvidence.decide(C, "entra", tok("acct", 1)), false);
        // missing claim
        expect("refuse: no amr claim (and no acr)", IdpMfaEvidence.decide(C, "entra", tok("amr", null)), false);
        expect("refuse: no tid claim", IdpMfaEvidence.decide(C, "entra", tok("tid", null)), false);
        expect("refuse: no validated token at all", IdpMfaEvidence.decide(C, "entra", null), false);
        // malformed
        expect("refuse: amr a string, not an array", IdpMfaEvidence.decide(C, "entra", tok("amr", "mfa")), false);
        expect("refuse: amr with a non-string element", IdpMfaEvidence.decide(C, "entra", tok("amr", List.of("mfa", 7))), false);
        expect("refuse: amr with an odd method name", IdpMfaEvidence.decide(C, "entra", tok("amr", List.of("mfa", "x y=1"))), false);
        expect("refuse: amr empty array", IdpMfaEvidence.decide(C, "entra", tok("amr", List.of())), false);
        expect("refuse: tid not a GUID", IdpMfaEvidence.decide(C, "entra", tok("tid", "common")), false);
        expect("refuse: tid a number", IdpMfaEvidence.decide(C, "entra", tok("tid", 42)), false);
        expect("refuse: acr not a string (even with amr mfa)", IdpMfaEvidence.decide(C, "entra", tok("acr", List.of("c1"))), false);
        expect("refuse: acrs malformed (even with amr mfa)", IdpMfaEvidence.decide(C, "entra", tok("acrs", Map.of("x", 1))), false);
        // no / bad config
        expect("refuse: no configuration", IdpMfaEvidence.decide(IdpMfaEvidence.cfg(null), "entra", tok()), false);
        expect("refuse: empty trusted-tenants", IdpMfaEvidence.decide(IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, " ")), "entra", tok()), false);
        expect("refuse: a malformed trusted tenant (even alongside the right one)",
               IdpMfaEvidence.decide(IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, T + ",*")), "entra", tok()), false);
        expect("refuse: accept-amr emptied and no acr list",
               IdpMfaEvidence.decide(IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, T, IdpMfaEvidence.P_AMR, "")), "entra", tok()), false);
        expect("refuse: a configured alias other than the sign-in's",
               IdpMfaEvidence.decide(IdpMfaEvidence.cfg(Map.of(IdpMfaEvidence.P_TENANTS, T, IdpMfaEvidence.P_ALIAS, "corp")), "entra", tok()), false);
        // the log shows method names only
        run++;
        String shown = IdpMfaEvidence.decide(C, "entra", tok("amr", List.of("mfa", "<script>"))).amrText();
        boolean ok = shown.equals("?");
        if (!ok) failed++;
        System.out.printf("%s  %-72s amr=[%s]%n", ok ? "PASS" : "FAIL", "a malformed amr is logged as [?], never its raw value", shown);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
