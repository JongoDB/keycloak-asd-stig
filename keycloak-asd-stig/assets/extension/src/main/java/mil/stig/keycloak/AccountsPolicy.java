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
    /** Default e-mail domains a delegate may create accounts for when nothing is configured: any .mil domain.
     *  Organizations add theirs with the client or realm attribute stig.accounts.email-domains. */
    static final String DEFAULT_EMAIL_DOMAINS = ".mil";
    /** One allowlist entry: ".suffix" (any domain ending in it) or an exact domain. */
    static final Pattern DOMAIN_ENTRY = Pattern.compile("^\\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$");
    static final int CREATE_PER_HOUR = 20;
    /** "signIn" value of a create for an account that signs in only through the realm's external identity provider. */
    static final String SIGN_IN_PROVIDER = "entra";
    /** Realm attribute: the one e-mail domain such accounts may have (the provider's own); unset = no such accounts. */
    static final String PROVIDER_DOMAIN = "stig.accounts.entra-domain";
    /** The address is exactly in the realm's provider domain (case-insensitive; no subdomain). Unset or blank: false. */
    static boolean providerDomainMatches(String email, String domain) {
        if (email == null || domain == null || domain.isBlank() || email.indexOf('@') < 0) return false;
        return email.substring(email.lastIndexOf('@') + 1).equalsIgnoreCase(domain.trim());
    }
    /** "signIn" value of a create for an account that signs in only with a card (CAC/PIV), bound at creation. */
    static final String SIGN_IN_CARD = "cac";
    /** Realm attribute: the user attribute the realm's X.509 step maps a card to (e.g. cac_edipi). Unset or malformed:
     *  stig-accounts makes no card accounts (fail closed). */
    static final String CARD_ATTRIBUTE = "stig.accounts.card-attribute";
    static final Pattern ATTR_NAME = Pattern.compile("^[a-z][a-z0-9_]{0,63}$");
    /** A DoD EDIPI: exactly ten digits. */
    static final Pattern EDIPI = Pattern.compile("^[0-9]{10}$");
    static boolean validEdipi(String e) { return e != null && EDIPI.matcher(e).matches(); }
    /** The realm's card attribute, or null (no card accounts) when unset, blank or malformed. */
    static String cardAttribute(String v) { return v != null && ATTR_NAME.matcher(v.trim()).matches() ? v.trim() : null; }
    /** Any EDIPI-like run (10 or more digits) in a text - a certificate subject (CN=LAST.FIRST.MI.<EDIPI>), an exception
     *  message - reduced to its last four digits, for log lines. */
    static String redactEdipis(String s) { return s == null ? null : s.replaceAll("\\d{6,}(\\d{4})", "******$1"); }
    /** An EDIPI for a log line or an admin event: the last four digits at most. */
    static String maskEdipi(String e) { return e == null || e.length() < 4 ? "****" : "******" + e.substring(e.length() - 4); }
    /** Admin-only attribute stig-accounts writes on every create: the sign-in methods the create intended, sorted,
     *  comma-separated (password | cac | entra | cac,entra). */
    static final String SIGNIN_METHODS = "stig_signin_methods";
    /** Suffix of the admin-only (and concealed) attribute holding the card an Entra + card invite NAMED, e.g.
     *  cac_edipi_pending: never bound at create; bound only when the account holder presents that very card after
     *  their first provider sign-in (PresentCardRequiredAction). Reserved while live: no other create may name it. */
    static final String PENDING_SUFFIX = "_pending";
    static final int PENDING_CARD_DAYS = 7;
    /** A pending card is live for 7 days from the account's creation (Keycloak's time and the delegate marker's, the
     *  older counts); after that it is ignored - never bound, and free for another create. */
    static boolean pendingExpired(Long createdMs, Long markerMs, long nowMs) {
        long oldest = Math.min(createdMs == null ? Long.MAX_VALUE : createdMs, markerMs == null ? Long.MAX_VALUE : markerMs);
        return oldest == Long.MAX_VALUE || nowMs - oldest > PENDING_CARD_DAYS * 86_400_000L;
    }
    /** The sign-in methods a create asks for, sorted; null when invalid. "signIn" absent: password (set-up mail); a
     *  string: "password", "entra" or "cac"; a list: entra and/or cac, in any order, each once - an empty list, a
     *  duplicate, "password" or anything else in a list is invalid. */
    static java.util.List<String> signInMethods(Object v) {
        java.util.TreeSet<String> m = new java.util.TreeSet<>();
        if (v == null) m.add("password");
        else if (v instanceof String s) m.add(s.trim());
        else if (v instanceof java.util.Collection<?> c && !c.isEmpty() && c.size() <= 2) {
            for (Object x : c) {
                if (!(x instanceof String s) || !m.add(s.trim()) || s.trim().equals("password")) return null;
            }
        } else return null;
        java.util.List<String> out = new java.util.ArrayList<>(m);
        if (out.equals(java.util.List.of("password")) || out.equals(java.util.List.of(SIGN_IN_CARD))
                || out.equals(java.util.List.of(SIGN_IN_PROVIDER)) || out.equals(java.util.List.of(SIGN_IN_CARD, SIGN_IN_PROVIDER))) return out;
        return null;
    }
    /** The 409 of a card create: one message whichever of username, e-mail address or card is taken. */
    static final String CARD_CONFLICT = "username, e-mail address or card already in use";
    /** The rate window in seconds: a sliding hour (a slot frees itself this long after it was claimed). */
    static final int RATE_WINDOW = 3600;
    /** At most this many accounts disabled per caller in any 60 minutes (a stolen session cannot empty a tree at once). */
    static final int DISABLE_PER_HOUR = 20;
    /** An optional caller reference (e.g. the request it fulfils), recorded in the admin event and the audit log. */
    static final Pattern REFERENCE = Pattern.compile("^[A-Za-z0-9._:-]{1,64}$");
    /** null when absent; "" when present but invalid; else the reference. */
    static String reference(String r) {
        if (r == null) return null;
        String x = r.trim();
        return REFERENCE.matcher(x).matches() ? x : "";
    }
    /** `domains`: comma list; ".mil" matches any domain ending in .mil, "example.org" exactly that domain.
     *  null (nothing configured) means DEFAULT_EMAIL_DOMAINS. A configured value fails closed: one with no entries
     *  (blank, ",") or with any malformed entry ("*.mil", "@x.org", "x .org") allows no domain at all. */
    static boolean emailDomainAllowed(String email, String domains) {
        if (email == null || email.indexOf('@') < 0) return false;
        String d = email.substring(email.lastIndexOf('@') + 1).toLowerCase(java.util.Locale.ROOT);
        java.util.List<String> entries = new java.util.ArrayList<>();
        for (String e : (domains == null ? DEFAULT_EMAIL_DOMAINS : domains).split(",", -1)) {
            String x = e.trim().toLowerCase(java.util.Locale.ROOT);
            if (x.isEmpty()) continue;
            if (!DOMAIN_ENTRY.matcher(x).matches()) return false;      // misconfigured: refuse everything
            entries.add(x);
        }
        for (String x : entries) {
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
