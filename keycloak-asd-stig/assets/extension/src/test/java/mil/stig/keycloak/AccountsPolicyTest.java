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
        // U2: "*" any domain, the denylist, organization domains
        t("'*' allows any domain", AccountsPolicy.emailDomainAllowed("j@acme.example", "*"), true);
        t("default still refuses gmail", AccountsPolicy.emailDomainAllowed("j@gmail.com", ""), false);
        t("deny .mil", AccountsPolicy.emailDomainDenied("j@army.mil", ".mil,defconai.com"), true);
        t("deny defconai.com", AccountsPolicy.emailDomainDenied("j@defconai.com", ".mil,defconai.com"), true);
        t("deny list does not hit acme", AccountsPolicy.emailDomainDenied("j@acme.example", ".mil,defconai.com"), false);
        t("deny '*' is not honoured", AccountsPolicy.emailDomainDenied("j@acme.example", "*"), false);
        t("no deny list", AccountsPolicy.emailDomainDenied("j@army.mil", null), false);
        t("org domain exact", AccountsPolicy.emailInDomains("j@Acme.Example", java.util.List.of("acme.example")), true);
        t("org domain: subdomain refused", AccountsPolicy.emailInDomains("j@x.acme.example", java.util.List.of("acme.example")), false);
        t("org domain: ANY never matches", AccountsPolicy.emailInDomains("j@acme.example", java.util.List.of("ANY")), false);
        t("org domain: wildcard never matches", AccountsPolicy.emailInDomains("j@acme.example", java.util.List.of("*.example", "*")), false);
        t("org domain: none", AccountsPolicy.emailInDomains("j@acme.example", java.util.List.of()), false);
        // U1: set-up actions
        t("setup default", AccountsPolicy.parseSetupActions(null).equals(AccountsPolicy.DEFAULT_SETUP_ACTIONS), true);
        t("setup passkey", java.util.List.of("VERIFY_EMAIL", "TERMS_AND_CONDITIONS", "webauthn-register-passwordless")
                .equals(AccountsPolicy.parseSetupActions("VERIFY_EMAIL, TERMS_AND_CONDITIONS,webauthn-register-passwordless")), true);
        t("setup unknown action refused", AccountsPolicy.parseSetupActions("VERIFY_EMAIL,delete_account") == null, true);
        t("setup no credential action refused", AccountsPolicy.parseSetupActions("VERIFY_EMAIL,TERMS_AND_CONDITIONS") == null, true);
        t("setup duplicate refused", AccountsPolicy.parseSetupActions("UPDATE_PASSWORD,UPDATE_PASSWORD") == null, true);
        t("setup empty item refused", AccountsPolicy.parseSetupActions("UPDATE_PASSWORD,,CONFIGURE_TOTP") == null, true);
        java.util.List<String> pk = AccountsPolicy.parseSetupActions("VERIFY_EMAIL,TERMS_AND_CONDITIONS,webauthn-register-passwordless");
        t("still setting up: passkey pending", AccountsPolicy.stillSettingUp(false, java.util.List.of("webauthn-register-passwordless"), pk), true);
        t("not setting up: has a credential", AccountsPolicy.stillSettingUp(true, java.util.List.of("webauthn-register-passwordless"), pk), false);
        t("not setting up: passkey action done", AccountsPolicy.stillSettingUp(false, java.util.List.of("TERMS_AND_CONDITIONS"), pk), false);
        t("default: both password and TOTP pending", AccountsPolicy.stillSettingUp(false, java.util.List.of("UPDATE_PASSWORD", "CONFIGURE_TOTP"), AccountsPolicy.DEFAULT_SETUP_ACTIONS), true);
        t("default: TOTP done", AccountsPolicy.stillSettingUp(false, java.util.List.of("UPDATE_PASSWORD"), AccountsPolicy.DEFAULT_SETUP_ACTIONS), false);
        // U5
        t("onBehalfOf absent", AccountsPolicy.validOnBehalfOf(null), true);
        t("onBehalfOf sub + username", AccountsPolicy.validOnBehalfOf("2b1f0c3e-1111-4a2b-9c3d-123456789abc jane.lead"), true);
        t("onBehalfOf newline refused", AccountsPolicy.validOnBehalfOf("a\nb"), false);
        t("onBehalfOf markup refused", AccountsPolicy.validOnBehalfOf("<x>"), false);
        t("onBehalfOf double space refused", AccountsPolicy.validOnBehalfOf("a  b"), false);
        t("onBehalfOf empty refused", AccountsPolicy.validOnBehalfOf(""), false);
        t("onBehalfOf too long refused", AccountsPolicy.validOnBehalfOf("a".repeat(201)), false);
        // U3 lifespan, U7 id list
        t("recover lifespan default 1 h", AccountsPolicy.recoverLifespan(null) == 3600, true);
        t("recover lifespan > 1 h refused", AccountsPolicy.recoverLifespan(3601) == -1, true);
        t("id list", AccountsPolicy.idList(" a, b,,c ").equals(java.util.Set.of("a", "b", "c")), true);
        t("log-safe: control characters replaced", AccountsPolicy.logSafe("a\nb\u0007c").equals("a?b?c"), true);
        t("log-safe: long value cut", AccountsPolicy.logSafe("x".repeat(300)).length() == 123, true);
        t("log-safe: null", AccountsPolicy.logSafe(null).equals("-"), true);
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
