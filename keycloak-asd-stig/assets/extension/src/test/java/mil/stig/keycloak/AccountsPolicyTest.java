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
        t("jane.doe@defconai.com", AccountsPolicy.validEmail("jane.doe@defconai.com"), true);
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
        t("e-mail usmc.mil (default)", AccountsPolicy.emailDomainAllowed("j@usmc.mil", null), true);
        t("e-mail defconai.com (default)", AccountsPolicy.emailDomainAllowed("j@defconai.com", null), true);
        t("e-mail gmail.com refused (default)", AccountsPolicy.emailDomainAllowed("j@gmail.com", null), false);
        t("e-mail notmil.com refused", AccountsPolicy.emailDomainAllowed("j@notmil.com", null), false);
        t("e-mail evil-defconai.com refused", AccountsPolicy.emailDomainAllowed("j@evil-defconai.com", null), false);
        t("e-mail sub.defconai.com refused (exact entry)", AccountsPolicy.emailDomainAllowed("j@x.defconai.com", null), false);
        t("bare 'mil' domain refused for .mil", AccountsPolicy.emailDomainAllowed("j@mil", null), false);
        t("configured list honoured", AccountsPolicy.emailDomainAllowed("j@notify.defconai.dev", ".mil,notify.defconai.dev"), true);
        t("lifespan default 12 h", AccountsPolicy.lifespan(null) == 43200, true);
        t("lifespan 24 h ok", AccountsPolicy.lifespan(86400) == 86400, true);
        t("lifespan > 24 h refused", AccountsPolicy.lifespan(86401) == -1, true);
        t("lifespan < 5 min refused", AccountsPolicy.lifespan(60) == -1, true);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
