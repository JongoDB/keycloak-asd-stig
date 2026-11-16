package mil.stig.keycloak;

import java.util.regex.Pattern;

/** Pure input rules of the stig-accounts endpoint (unit-tested without Keycloak). */
final class AccountsPolicy {
    private AccountsPolicy() { }
    /** first.last, lower case: a letter, letters/digits/hyphens, a dot, then letters/digits/dots/hyphens; at most 64. */
    static final Pattern USERNAME = Pattern.compile("^[a-z][a-z0-9-]*\\.[a-z][a-z0-9.-]*$");
    /** A plain mailbox: no spaces, quotes, angle brackets, commas or semicolons; one @; a dotted domain. */
    static final Pattern EMAIL = Pattern.compile("^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,63}$");
    static final int MAX_LIFESPAN = 86400, DEFAULT_LIFESPAN = 43200, RESEND_INTERVAL = 900;

    static boolean validUsername(String u) { return u != null && u.length() <= 64 && USERNAME.matcher(u).matches() && !u.endsWith(".") && !u.contains(".."); }
    static boolean validEmail(String e) { return e != null && e.length() <= 254 && EMAIL.matcher(e).matches() && !e.contains(".."); }
    static boolean validName(String n) {
        if (n == null || n.isBlank() || n.length() > 255 || n.chars().anyMatch(c -> c < 0x20 || c == '<' || c == '>')) return false;
        String l = n.toLowerCase(java.util.Locale.ROOT);
        return !(l.contains("://") || l.contains("www.") || l.contains("http") || l.contains("@") || l.matches(".*\\.[a-z]{2,}(/.*)?$"));
    }
    /** Default e-mail domains a delegate may create accounts for: any .mil domain, and defconai.com. */
    static final String DEFAULT_EMAIL_DOMAINS = ".mil,defconai.com";
    static final int CREATE_PER_HOUR = 20;
    /** `domains`: comma list; ".mil" matches any domain ending in .mil, "defconai.com" exactly that domain, and "*" any
     *  domain (for a realm whose readers may use any address - pair it with a denylist). */
    static boolean emailDomainAllowed(String email, String domains) {
        return domainMatches(email, domains == null || domains.isBlank() ? DEFAULT_EMAIL_DOMAINS : domains, true);
    }

    /** The realm's denylist (same syntax, "*" not honoured): an address in it is refused whatever else allows it. */
    static boolean emailDomainDenied(String email, String deny) {
        return deny != null && !deny.isBlank() && domainMatches(email, deny, false);
    }

    private static String domainOf(String email) {
        return email == null || email.indexOf('@') < 0 ? null : email.substring(email.lastIndexOf('@') + 1).toLowerCase(java.util.Locale.ROOT);
    }

    private static boolean domainMatches(String email, String list, boolean starAllowed) {
        String d = domainOf(email);
        if (d == null) return false;
        for (String e : list.split(",")) {
            String x = e.trim().toLowerCase(java.util.Locale.ROOT);
            if (x.isEmpty()) continue;
            if (x.equals("*")) { if (starAllowed) return true; continue; }
            if (x.startsWith(".") ? d.endsWith(x) && d.length() > x.length() : d.equals(x)) return true;
        }
        return false;
    }

    /** An organization's domains: the address's domain must be EXACTLY one of them. Keycloak's "any domain" marker and
     *  wildcards never match - an organization must name its domains. */
    static boolean emailInDomains(String email, java.util.Collection<String> domains) {
        String d = domainOf(email);
        if (d == null || domains == null) return false;
        for (String x : domains) {
            if (x == null) continue;
            String l = x.trim().toLowerCase(java.util.Locale.ROOT);
            if (l.isEmpty() || l.equals("any") || l.contains("*")) continue;
            if (d.equals(l)) return true;
        }
        return false;
    }

    /** Set-up actions an account may be created with (U1). The default is the password realm's. */
    static final java.util.List<String> DEFAULT_SETUP_ACTIONS = java.util.List.of("UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS");
    static final java.util.Set<String> SETUP_ALLOWED = java.util.Set.of("UPDATE_PASSWORD", "CONFIGURE_TOTP", "TERMS_AND_CONDITIONS",
            "VERIFY_EMAIL", "webauthn-register", "webauthn-register-passwordless");
    /** The actions that create a credential: an account is "still being set up" while none of them has been done. */
    static final java.util.Set<String> CREDENTIAL_ACTIONS = java.util.Set.of("UPDATE_PASSWORD", "CONFIGURE_TOTP", "webauthn-register",
            "webauthn-register-passwordless");

    /** A realm's set-up actions from its (master-realm) setting: absent -> the default; otherwise a comma list of known
     *  actions, no duplicates, at least one that creates a credential. Anything else -> null (callers refuse: fail closed). */
    static java.util.List<String> parseSetupActions(String v) {
        if (v == null || v.isBlank()) return DEFAULT_SETUP_ACTIONS;
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String x : v.split(",", -1)) {
            String a = x.trim();
            if (a.isEmpty() || !SETUP_ALLOWED.contains(a) || out.contains(a)) return null;
            out.add(a);
        }
        return out.stream().anyMatch(CREDENTIAL_ACTIONS::contains) ? java.util.List.copyOf(out) : null;
    }

    /** No stored credential, and every credential-creating set-up action still pending. */
    static boolean stillSettingUp(boolean hasCredential, java.util.Collection<String> pending, java.util.List<String> setup) {
        if (hasCredential || setup == null) return false;
        java.util.List<String> creds = setup.stream().filter(CREDENTIAL_ACTIONS::contains).toList();
        return !creds.isEmpty() && pending.containsAll(creds);
    }

    /** onBehalfOf (U5): who the calling application says asked, e.g. "<sub> <username>". Recorded as asserted by the
     *  caller, never trusted. Absent is fine; present must be 1..200 printable characters from a small set. */
    static final Pattern ON_BEHALF_OF = Pattern.compile("^[A-Za-z0-9._@:+/=-]+( [A-Za-z0-9._@:+/=-]+)*$");
    static boolean validOnBehalfOf(String v) { return v == null || (v.length() <= 200 && ON_BEHALF_OF.matcher(v).matches()); }

    /** A comma list of ids (an organization allow-list): blank entries ignored. */
    static java.util.Set<String> idList(String v) {
        java.util.Set<String> out = new java.util.HashSet<>();
        if (v != null) for (String x : v.split(",")) if (!x.isBlank()) out.add(x.trim());
        return out;
    }

    /** Recovery (U3): the link lives at most 1 h (default 1 h); one recovery per account per 24 h. */
    static final int RECOVER_MAX_LIFESPAN = 3600, RECOVER_INTERVAL = 86400;
    static int recoverLifespan(Integer requested) {
        if (requested == null) return RECOVER_MAX_LIFESPAN;
        return requested >= 300 && requested <= RECOVER_MAX_LIFESPAN ? requested : -1;
    }
    /** The set-up link's lifetime in seconds: the request's, never more than 24 h; default 12 h; invalid -> -1. */
    static int lifespan(Integer requested) {
        if (requested == null) return DEFAULT_LIFESPAN;
        return requested >= 300 && requested <= MAX_LIFESPAN ? requested : -1;
    }

    /** A caller-supplied value for a log line: printable ASCII only, at most 120 characters. */
    static String logSafe(String v) {
        if (v == null) return "-";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < v.length() && b.length() < 120; i++) {
            char c = v.charAt(i);
            b.append(c < 0x20 || c >= 0x7f ? '?' : c);
        }
        return v.length() > 120 ? b + "..." : b.toString();
    }
}
