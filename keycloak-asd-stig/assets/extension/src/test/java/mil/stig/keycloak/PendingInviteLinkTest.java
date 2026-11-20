package mil.stig.keycloak;

import java.util.List;
import java.util.Map;

import mil.stig.keycloak.PendingInviteLink.Candidate;

/** Unit tests of the pending-invite binding rules (PendingInviteLink) and stig-accounts' provider sign-in rule. Run by build.sh. */
public final class PendingInviteLinkTest {
    static int run = 0, failed = 0;
    static final long NOW = 2_000_000_000_000L, DAY = 86_400_000L;
    static void t(String n, Object got, Object want) {
        run++; boolean ok = java.util.Objects.equals(got, want); if (!ok) failed++;
        System.out.printf("%s  %-86s %s%n", ok ? "PASS" : "FAIL", n, ok ? "" : "got " + got + ", want " + want);
    }
    static final PendingInviteLink.Cfg C = PendingInviteLink.cfg(Map.of(PendingInviteLink.P_DOMAIN, "example.org"));
    static Candidate invite(String id, String username, String email) {
        return new Candidate(id, username, email, true, "mgr.one " + (NOW - DAY), null, false, null, NOW - DAY, String.valueOf(NOW - DAY), List.of("TERMS_AND_CONDITIONS"));
    }
    static String why(String upn, List<Candidate> cs) { return PendingInviteLink.decide(C, upn, cs, NOW).refusal(); }
    static String bound(String upn, List<Candidate> cs) { return PendingInviteLink.decide(C, upn, cs, NOW).id(); }

    public static void main(String[] a) {
        // configuration
        t("no domain configured: off", PendingInviteLink.cfg(Map.of()), null);
        t("blank domain: off", PendingInviteLink.cfg(Map.of(PendingInviteLink.P_DOMAIN, " ")), null);
        t("malformed domain: off (fail closed)", PendingInviteLink.cfg(Map.of(PendingInviteLink.P_DOMAIN, "*.org")), null);
        t("max age 0: off", PendingInviteLink.cfg(Map.of(PendingInviteLink.P_DOMAIN, "example.org", PendingInviteLink.P_MAX_DAYS, "0")), null);
        t("max age 31: off", PendingInviteLink.cfg(Map.of(PendingInviteLink.P_DOMAIN, "example.org", PendingInviteLink.P_MAX_DAYS, "31")), null);
        t("max age not a number: off", PendingInviteLink.cfg(Map.of(PendingInviteLink.P_DOMAIN, "example.org", PendingInviteLink.P_MAX_DAYS, "7d")), null);
        t("default max age 7", C.maxDays(), 7);
        t("decide with the mode off refuses", PendingInviteLink.decide(null, "a@example.org", List.of(invite("1", "a.b", "a@example.org")), NOW).id(), null);

        // the principal name
        t("principal: lower-cased, domain matched case-insensitively", PendingInviteLink.principal(C, "Jane.Doe@Example.ORG"), "jane.doe@example.org");
        t("principal in another domain: none", PendingInviteLink.principal(C, "jane@other.org"), null);
        t("principal in a SUBdomain: none", PendingInviteLink.principal(C, "jane@x.example.org"), null);
        t("a guest-style principal (#EXT#): none", PendingInviteLink.principal(C, "jane_other.org#EXT#@example.org"), null);
        t("no principal vouched: none", PendingInviteLink.principal(C, null), null);
        t("marker time read from '<caller> <ms>'", PendingInviteLink.markerTime("mgr.one 1234"), 1234L);
        t("marker time absent", PendingInviteLink.markerTime("mgr.one"), null);

        // the happy path
        t("ONE pending invite whose e-mail is the principal: bound", bound("jane.doe@example.org", List.of(invite("1", "jane.doe", "jane.doe@example.org"))), "1");
        t("... matched case-insensitively", bound("JANE.DOE@example.org", List.of(invite("1", "jane.doe", "Jane.Doe@Example.org"))), "1");
        t("... or whose USERNAME is the principal", bound("jane.doe@example.org", List.of(invite("1", "jane.doe@example.org", "j.doe@example.org"))), "1");
        t("the same account found by username AND e-mail counts once", bound("j@example.org",
                List.of(invite("1", "j@example.org", "j@example.org"), invite("1", "j@example.org", "j@example.org"))), "1");

        // refusals
        t("no account", why("nobody@example.org", List.of()) != null, true);
        t("the candidate list holds an account whose username/e-mail is NOT the principal (e.g. matched by e-mail claim): ignored",
                bound("robert@example.org", List.of(invite("1", "bob", "bob@example.org"))), null);
        t("two accounts match: refused", why("j@example.org", List.of(invite("1", "j@example.org", null), invite("2", "j.x", "j@example.org"))).contains("more than one"), true);
        t("not created by a delegate (no marker): refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, null, null, false, null, NOW, String.valueOf(NOW - DAY), List.of()))).contains("delegated"), true);
        t("disabled: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", false, "m " + NOW, null, false, null, NOW, String.valueOf(NOW - DAY), List.of()))).contains("disabled"), true);
        t("already bound (another object id): refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, "11111111-1111-1111-1111-111111111111", false, null, NOW, String.valueOf(NOW - DAY), List.of()))).contains("already bound"), true);
        t("has a credential: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, true, null, NOW, String.valueOf(NOW - DAY), List.of()))).contains("credential"), true);
        t("has a card binding: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, "1234567890", NOW, String.valueOf(NOW - DAY), List.of()))).contains("card"), true);
        t("older than 7 days by Keycloak's creation time: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, null, NOW - 8 * DAY, String.valueOf(NOW - DAY), List.of()))).contains("older"), true);
        t("older than 7 days by the marker's time (Keycloak's is recent): refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + (NOW - 8 * DAY), null, false, null, NOW, String.valueOf(NOW - DAY), List.of()))).contains("older"), true);
        t("exactly 7 days old: still bound", bound("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + (NOW - 7 * DAY), null, false, null, NOW - 7 * DAY, String.valueOf(NOW - DAY), List.of()))), "1");
        t("a creation time in the future: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + (NOW + DAY), null, false, null, NOW + DAY, String.valueOf(NOW - DAY), List.of()))).contains("future"), true);
        t("no creation time at all: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m", null, false, null, null, "yes", List.of()))).contains("unknown"), true);
        t("no pending marker (a password-type invite): refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, null, NOW, null, List.of()))).contains("not invited"), true);
        t("a password-type invite still in set-up (UPDATE_PASSWORD, CONFIGURE_TOTP), even WITH the marker: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, null, NOW, String.valueOf(NOW),
                        List.of("UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS")))).contains("password-type"), true);
        t("the account's e-mail outside the domain (matched by USERNAME only): refused", why("a@example.org",
                List.of(new Candidate("1", "a@example.org", "a@other.org", true, "m " + NOW, null, false, null, NOW, String.valueOf(NOW), List.of()))).contains("not in"), true);
        t("the marker's own time older than 7 days: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, null, NOW, String.valueOf(NOW - 8 * DAY), List.of()))).contains("older"), true);
        t("the fixed marker value (stig-accounts writes \"pending\"): bound, aged by the other two times", bound("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + (NOW - DAY), null, false, null, NOW - DAY, PendingInviteLink.PENDING_VALUE, List.of()))), "1");
        t("the fixed marker value on an 8-day-old account: refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + (NOW - 8 * DAY), null, false, null, NOW - DAY, PendingInviteLink.PENDING_VALUE, List.of()))).contains("older"), true);
        t("a principal in another domain never binds", bound("a@other.org", List.of(invite("1", "a", "a@other.org"))), null);

        // guests of the tenant (B2B, one-time passcode, Microsoft account): never bound
        String T = "11111111-2222-3333-4444-555555555555";
        t("a member: no idp claim", PendingInviteLink.guest(null, null, T), null);
        t("a member: idp names the tenant itself (sts)", PendingInviteLink.guest("https://sts.windows.net/" + T + "/", null, T), null);
        t("a member: acct 0", PendingInviteLink.guest(null, "0", T), null);
        t("a B2B guest (idp = another tenant): refused", PendingInviteLink.guest("https://sts.windows.net/99999999-2222-3333-4444-555555555555/", null, T) != null, true);
        t("a Microsoft-account guest (idp live.com): refused", PendingInviteLink.guest("live.com", null, T) != null, true);
        t("an e-mail one-time-passcode guest (idp mail): refused", PendingInviteLink.guest("mail", null, T) != null, true);
        t("acct 1 (guest), even without idp: refused", PendingInviteLink.guest(null, "1", T) != null, true);
        // the mappers feeding it are pinned
        PendingInviteLink.Mapper upn = new PendingInviteLink.Mapper("entra", PendingInviteLink.ATTRIBUTE_MAPPER, "preferred_username", "entra_vouched_upn");
        PendingInviteLink.Mapper idp = new PendingInviteLink.Mapper("entra", PendingInviteLink.ATTRIBUTE_MAPPER, "idp", "entra_vouched_idp");
        t("pinned: one upn mapper from preferred_username, one idp mapper from idp", PendingInviteLink.mappersPinned(C, "entra", List.of(upn, idp)), null);
        t("no idp mapper: refused (a guest would pass unseen)", PendingInviteLink.mappersPinned(C, "entra", List.of(upn)) != null, true);
        t("the upn attribute from the EMAIL claim: refused", PendingInviteLink.mappersPinned(C, "entra", List.of(idp,
                new PendingInviteLink.Mapper("entra", PendingInviteLink.ATTRIBUTE_MAPPER, "email", "entra_vouched_upn"))) != null, true);
        t("a second mapper writing the upn attribute (another provider): refused", PendingInviteLink.mappersPinned(C, "entra", List.of(upn, idp,
                new PendingInviteLink.Mapper("other", "hardcoded-attribute-idp-mapper", null, "entra_vouched_upn"))) != null, true);
        t("an acct mapper from another claim: refused", PendingInviteLink.mappersPinned(C, "entra", List.of(upn, idp,
                new PendingInviteLink.Mapper("entra", PendingInviteLink.ATTRIBUTE_MAPPER, "upn", "entra_vouched_acct"))) != null, true);

        // both on one account: the create's own card binding is accepted, no other
        t("a card bound by the SAME create for an account invited for both: bound", bound("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, "1234567890", NOW, "pending", List.of(), true))), "1");
        t("a card bound any other way (or changed since): refused", why("a@example.org",
                List.of(new Candidate("1", "a", "a@example.org", true, "m " + NOW, null, false, "1234567890", NOW, "pending", List.of(), false))).contains("card"), true);
        t("signIn: a string", AccountsPolicy.signInMethods("entra"), List.of("entra"));
        t("signIn: absent = password", AccountsPolicy.signInMethods(null), List.of("password"));
        t("signIn: [entra, cac] = both, sorted", AccountsPolicy.signInMethods(List.of("entra", "cac")), List.of("cac", "entra"));
        t("signIn: [password, cac] refused", AccountsPolicy.signInMethods(List.of("password", "cac")), null);
        t("signIn: [] refused", AccountsPolicy.signInMethods(List.of()), null);
        t("signIn: [fido] refused", AccountsPolicy.signInMethods(List.of("fido")), null);
        t("signIn: a number refused", AccountsPolicy.signInMethods(3), null);
        t("card digest: not the EDIPI, stable", AccountsPolicy.cardDigest("r", "1234567890").equals(AccountsPolicy.cardDigest("r", "1234567890"))
                && !AccountsPolicy.cardDigest("r", "1234567890").contains("1234567890"), true);

        // stig-accounts: signIn cac
        t("edipi: ten digits", AccountsPolicy.validEdipi("1234567890"), true);
        t("edipi: nine digits refused", AccountsPolicy.validEdipi("123456789"), false);
        t("edipi: letters refused", AccountsPolicy.validEdipi("12345678x0"), false);
        t("edipi: masked to the last four", AccountsPolicy.maskEdipi("1234567890"), "******7890");
        t("card attribute unset: no card accounts", AccountsPolicy.cardAttribute(null), null);
        t("card attribute malformed: no card accounts", AccountsPolicy.cardAttribute("cac edipi"), null);
        t("card attribute set", AccountsPolicy.cardAttribute("cac_edipi"), "cac_edipi");

        // stig-accounts: signIn entra
        t("provider domain: exact match", AccountsPolicy.providerDomainMatches("a@Example.org", "example.org"), true);
        t("provider domain: a subdomain does not match", AccountsPolicy.providerDomainMatches("a@x.example.org", "example.org"), false);
        t("provider domain: unset realm attribute allows nothing", AccountsPolicy.providerDomainMatches("a@example.org", null), false);
        t("provider domain: blank allows nothing", AccountsPolicy.providerDomainMatches("a@example.org", " "), false);

        System.out.printf("PendingInviteLinkTest: %d/%d passed%n", run - failed, run);
        if (failed > 0) System.exit(1);
    }
}
