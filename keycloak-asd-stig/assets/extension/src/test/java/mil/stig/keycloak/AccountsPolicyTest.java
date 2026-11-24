package mil.stig.keycloak;

/** Unit tests of the stig-accounts endpoint's input rules. Run by build.sh. */
public final class AccountsPolicyTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean got, boolean want) { run++; boolean ok = got == want; if (!ok) failed++; System.out.printf("%s  %-60s%n", ok ? "PASS" : "FAIL", n); }
    public static void main(String[] a) {
        t("jane.doe", AccountsPolicy.validUsername("jane.doe"), true);
        t("mary-ann.o-brien2", AccountsPolicy.validUsername("mary-ann.o-brien2"), true);
        t("no dot", AccountsPolicy.validUsername("janedoe"), false);
        t("upper case", AccountsPolicy.validUsername("Jane.Doe"), false);
        t("trailing dot", AccountsPolicy.validUsername("jane.doe."), false);
        t("double dot", AccountsPolicy.validUsername("jane..doe"), false);
        t("leading digit", AccountsPolicy.validUsername("1jane.doe"), false);
        t("spaces/at", AccountsPolicy.validUsername("jane.doe@x"), false);
        t("null", AccountsPolicy.validUsername(null), false);
        t("too long", AccountsPolicy.validUsername("a." + "b".repeat(70)), false);
        t("jane.doe@example.org", AccountsPolicy.validEmail("jane.doe@example.org"), true);
        t("sub.domain mail", AccountsPolicy.validEmail("j+x@mail.army.mil"), true);
        t("no domain dot", AccountsPolicy.validEmail("jane@localhost"), false);
        t("display name", AccountsPolicy.validEmail("Jane <jane@x.com>"), false);
        t("two @", AccountsPolicy.validEmail("a@b@c.com"), false);
        t("comma list", AccountsPolicy.validEmail("a@b.com,c@d.com"), false);
        t("double dot", AccountsPolicy.validEmail("a..b@c.com"), false);
        t("name ok", AccountsPolicy.validName("Jane"), true);
        t("name blank", AccountsPolicy.validName(" "), false);
        t("name markup", AccountsPolicy.validName("<script>"), false);
        t("name with a URL", AccountsPolicy.validName("click https://evil.example"), false);
        t("name with ://", AccountsPolicy.validName("x://y"), false);
        t("name with www.", AccountsPolicy.validName("www.evil"), false);
        t("name that is a domain", AccountsPolicy.validName("evil.com"), false);
        t("name with an @", AccountsPolicy.validName("a@b"), false);
        t("ordinary name O'Brien-Smith", AccountsPolicy.validName("O'Brien-Smith"), true);
        t("e-mail .mil (default)", AccountsPolicy.emailDomainAllowed("john.doe@army.mil", null), true);
        t("e-mail af.mil (default)", AccountsPolicy.emailDomainAllowed("j@af.mil", null), true);
        t("e-mail example.org refused (default is .mil only)", AccountsPolicy.emailDomainAllowed("j@example.org", null), false);
        t("e-mail gmail.com refused (default)", AccountsPolicy.emailDomainAllowed("j@gmail.com", null), false);
        t("e-mail notmil.com refused", AccountsPolicy.emailDomainAllowed("j@notmil.com", null), false);
        t("configured exact entry allowed", AccountsPolicy.emailDomainAllowed("j@example.org", ".mil,example.org"), true);
        t("e-mail evil-example.org refused", AccountsPolicy.emailDomainAllowed("j@evil-example.org", ".mil,example.org"), false);
        t("e-mail sub.example.org refused (exact entry)", AccountsPolicy.emailDomainAllowed("j@x.example.org", ".mil,example.org"), false);
        t("bare 'mil' domain refused for .mil", AccountsPolicy.emailDomainAllowed("j@mil", null), false);
        t("configured list honoured", AccountsPolicy.emailDomainAllowed("j@notify.example.net", ".mil,notify.example.net"), true);
        t("configured list replaces the default", AccountsPolicy.emailDomainAllowed("j@army.mil", "example.org"), false);
        t("set but empty: fails closed", AccountsPolicy.emailDomainAllowed("j@army.mil", ""), false);
        t("set but blank: fails closed", AccountsPolicy.emailDomainAllowed("j@army.mil", "   "), false);
        t("set to ',': fails closed", AccountsPolicy.emailDomainAllowed("j@army.mil", ","), false);
        t("malformed entry '*.mil': fails closed", AccountsPolicy.emailDomainAllowed("j@army.mil", "*.mil"), false);
        t("one malformed entry refuses the whole list", AccountsPolicy.emailDomainAllowed("j@army.mil", ".mil,@x.org"), false);
        t("entry with a space: fails closed", AccountsPolicy.emailDomainAllowed("j@army.mil", ".mil,x .org"), false);
        t("lifespan default 12 h", AccountsPolicy.lifespan(null) == 43200, true);
        t("lifespan 24 h ok", AccountsPolicy.lifespan(86400) == 86400, true);
        t("lifespan > 24 h refused", AccountsPolicy.lifespan(86401) == -1, true);
        t("lifespan < 5 min refused", AccountsPolicy.lifespan(60) == -1, true);
        // the portal operations' pure rules
        t("/roles is the IdP's role tree", AccountsPolicy.inRolesTree(java.util.List.of("roles")), true);
        t("/roles/idp-admin is in it", AccountsPolicy.inRolesTree(java.util.List.of("roles", "idp-admin")), true);
        t("/roles/app-user-manager/x (any depth) is in it", AccountsPolicy.inRolesTree(java.util.List.of("roles", "app-user-manager", "x")), true);
        t("/app/roles is not", AccountsPolicy.inRolesTree(java.util.List.of("app", "roles")), false);
        t("/rolesx is not", AccountsPolicy.inRolesTree(java.util.List.of("rolesx")), false);
        t("no path is not", AccountsPolicy.inRolesTree(java.util.List.of()), false);
        String U1 = "0b3c7f7e-1d2a-4c55-9a51-2a8f3b2e9c10";
        t("status ids: one", java.util.List.of(U1).equals(AccountsPolicy.statusIds(java.util.List.of(U1))), true);
        t("status ids: duplicates dropped", java.util.List.of(U1).equals(AccountsPolicy.statusIds(java.util.List.of(U1, U1))), true);
        t("status ids: none -> invalid", AccountsPolicy.statusIds(java.util.List.of()) == null, true);
        t("status ids: a malformed id -> invalid", AccountsPolicy.statusIds(java.util.List.of(U1, "a b")) == null, true);
        java.util.List<String> many = new java.util.ArrayList<>();
        for (int i = 0; i < 51; i++) many.add("id-" + i);
        t("status ids: 51 -> invalid", AccountsPolicy.statusIds(many) == null, true);
        t("status ids: 50 -> valid", AccountsPolicy.statusIds(many.subList(0, 50)) != null, true);
        java.util.Map<String, Object> v = AccountsPolicy.statusView(U1, "jane.doe", true, false, true, true, true, false, false, 2);
        t("status: exactly id, username, eight booleans and a count",
                v.keySet().equals(new java.util.LinkedHashSet<>(java.util.List.of("id", "username", "enabled", "locked", "passwordSet",
                        "otpEnrolled", "cardBound", "cardPending", "entraLinked", "activeSessions"))), true);
        t("status: every value but id/username/activeSessions is a boolean",
                v.entrySet().stream().filter(e -> !java.util.Set.of("id", "username", "activeSessions").contains(e.getKey()))
                        .allMatch(e -> e.getValue() instanceof Boolean), true);
        t("status: activeSessions is a number", v.get("activeSessions") instanceof Long, true);
        String P = AdminApiStepUp.ACCOUNT_ONBOARDING;
        t("portal: an onboarding client listing the op may", AccountsPolicy.portalRefusal(P, "create,unlock", "unlock") == null, true);
        t("portal: not listed -> refused", AccountsPolicy.portalRefusal(P, "create,logout", "unlock") != null, true);
        t("portal: operations unset -> refused (off unless listed)", AccountsPolicy.portalRefusal(P, null, "unlock") != null, true);
        t("portal: malformed operations -> refused", AccountsPolicy.portalRefusal(P, "unlock,", "unlock") != null, true);
        t("portal: no profile (an admin-console token) -> refused", AccountsPolicy.portalRefusal(null, "unlock", "unlock") != null, true);
        t("portal: another profile -> refused", AccountsPolicy.portalRefusal("other", "unlock", "unlock") != null, true);
        t("link: an ordinary account may", AccountsPolicy.portalLinkRefusal(true, null, null, false, true) == null, true);
        t("link: a disabled account -> refused", AccountsPolicy.portalLinkRefusal(false, null, null, false, true) != null, true);
        t("link: one that has a card -> refused (no replace from the portal)", AccountsPolicy.portalLinkRefusal(true, "1234567890", null, false, true) != null, true);
        t("link: an invite's pending card -> refused", AccountsPolicy.portalLinkRefusal(true, null, "1234567890", false, true) != null, true);
        t("link: an earlier link request's pending card -> replaced (may)", AccountsPolicy.portalLinkRefusal(true, null, "1234567890", true, true) == null, true);
        t("link: an account that cannot sign in -> refused", AccountsPolicy.portalLinkRefusal(true, null, null, false, false) != null, true);
        t("link: a refusal never carries the card", String.valueOf(AccountsPolicy.portalLinkRefusal(true, "1234567890", null, false, true)).contains("1234"), false);
        t("portal writes: 20 per caller and operation per hour", AccountsPolicy.PORTAL_OPS_PER_HOUR == 20, true);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
