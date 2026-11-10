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
    /** `domains`: comma list; ".mil" matches any domain ending in .mil, "defconai.com" exactly that domain. */
    static boolean emailDomainAllowed(String email, String domains) {
        if (email == null || email.indexOf('@') < 0) return false;
        String d = email.substring(email.lastIndexOf('@') + 1).toLowerCase(java.util.Locale.ROOT);
        for (String e : (domains == null || domains.isBlank() ? DEFAULT_EMAIL_DOMAINS : domains).split(",")) {
            String x = e.trim().toLowerCase(java.util.Locale.ROOT);
            if (x.isEmpty()) continue;
            if (x.startsWith(".") ? d.endsWith(x) && d.length() > x.length() : d.equals(x)) return true;
        }
        return false;
    }
    /** The set-up link's lifetime in seconds: the request's, never more than 24 h; default 12 h; invalid -> -1. */
    static int lifespan(Integer requested) {
        if (requested == null) return DEFAULT_LIFESPAN;
        return requested >= 300 && requested <= MAX_LIFESPAN ? requested : -1;
    }
}
