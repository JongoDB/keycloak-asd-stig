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
    /** Digits in a logged value (any script: \p{Nd}): every run of four or more becomes "####"; and when the value holds
     *  ten or more digits in all (an EDIPI however it is split: 123-456-7890, 12-34-56-78-90), EVERY digit is masked
     *  ("#") except the value's last four. */
    static String maskDigitRuns(String s) {
        if (s == null) return null;
        long total = s.codePoints().filter(Character::isDigit).count();
        if (total < 10) return s.replaceAll("\\p{Nd}{4,}", "####");
        long keepFrom = total - 4, seen = 0;
        StringBuilder b = new StringBuilder(s.length());
        for (int cp : s.codePoints().toArray()) {
            if (Character.isDigit(cp)) b.append(seen++ >= keepFrom ? new String(Character.toChars(cp)) : "#");
            else b.appendCodePoint(cp);
        }
        return b.toString();
    }
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
    /** Admin-only (and concealed) attribute an administrator's link request writes (idp-admin.py link-cac): "<epoch-ms>",
     *  the time of the request. It asks the holder of an EXISTING account to present a card at their next sign-in
     *  (PresentCardRequiredAction); with `<card attribute>_pending` set as well, only that card binds. Live for 7 days
     *  from the request - not from the account's creation, as an invite's pending card is. */
    static final String LINK_ATTRIBUTE = "stig_card_link";
    static final int LINK_DAYS = 7;
    /** The time a link request records, or null (absent, or not "<epoch-ms>" / "<epoch-ms> admin"). */
    static Long linkTime(String v) {
        if (v == null || !v.trim().matches("[0-9]{1,15}( admin)?")) return null;
        return Long.parseLong(v.trim().split(" ")[0]);
    }
    /** The request was made while the account was an IdP administrator ("<epoch-ms> admin"). */
    static boolean linkForAdmin(String v) {
        return v != null && v.trim().matches("[0-9]{1,15} admin");
    }
    /** Why a link request must not run for this account (null: it may). An IdP administrator - when the request was
     *  made, or now - gets only a card an administrator NAMED (expected != null), never "any card": whoever could
     *  write the request must not be able to make an administrator's next sign-in bind the card in the reader. */
    static String adminLinkRefusal(String expected, boolean adminAtRequest, boolean adminNow) {
        if (expected == null && (adminAtRequest || adminNow))
            return "an IdP administrator gets only a card an administrator named (link-cac --allow-admin --edipi), never any card";
        return null;
    }
    /** Release a claim (a single-use key) only once the transaction that relied on it has COMMITTED or rolled back:
     *  a release before the commit would let a second writer claim, check and bind before this write is visible. */
    static void releaseAfterCompletion(org.keycloak.models.KeycloakSession session, String key) {
        session.getTransactionManager().enlistAfterCompletion(new org.keycloak.models.AbstractKeycloakTransaction() {
            @Override protected void commitImpl() { session.singleUseObjects().remove(key); }
            @Override protected void rollbackImpl() { session.singleUseObjects().remove(key); }
        });
    }
    /** A link request is live for 7 days from its time; one dated more than five minutes in the future is not. */
    static boolean linkLive(Long requestMs, long nowMs) {
        return requestMs != null && requestMs <= nowMs + 300_000L && nowMs - requestMs <= LINK_DAYS * 86_400_000L;
    }
    /** Why the card a person presented must NOT be bound to their account (null: bind it). `expected` is the card the
     *  invite or the administrator named (null: any card - a link request without one), `identity` the presented card's
     *  identity as the realm maps cards, `current` the card the account holds now. */
    static String presentRefusal(String expected, String identity, String current, boolean boundElsewhere,
                                 boolean reservedElsewhere, boolean link) {
        if (identity == null || identity.isBlank()) return "the card presented carries no identity the realm maps cards by";
        if (expected != null && !identity.trim().equals(expected))
            return link ? "the card presented is not the one the administrator named" : "the card presented is not the one the invite named";
        if (current != null && !current.isBlank() && !current.trim().equals(identity.trim())) return "the account already has another card";
        if (boundElsewhere) return "that card is already bound to another account";
        if (reservedElsewhere) return "that card is reserved for another account";
        return null;
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
    /** At most this many of EACH portal write (reset-otp, reset-password, unlock, logout, link-cac) per caller in any
     *  60 minutes: a stolen page session cannot sweep a tree at once. */
    static final int PORTAL_OPS_PER_HOUR = 20;
    /** At most this many accounts in one status request (GET stig-accounts/users/status?id=...). */
    static final int STATUS_MAX = 50;
    /** The top-level group whose tree holds the IdP's own role groups (/roles/idp-admin, /roles/<app>-user-manager, ...):
     *  an account in it, or anywhere beneath it, is an IdP administrator for the portal operations. */
    static final String ROLES_TREE = "roles";
    /** The names of a group's path from the top (["roles", "idp-admin"]) lies in the /roles tree. */
    static boolean inRolesTree(java.util.List<String> pathFromTop) {
        return pathFromTop != null && !pathFromTop.isEmpty() && ROLES_TREE.equals(pathFromTop.get(0));
    }
    /** The ids of a status request: 1..STATUS_MAX ids, each an id segment, duplicates dropped (order kept); null when
     *  there are none, too many, or any is malformed. */
    static java.util.List<String> statusIds(java.util.List<String> ids) {
        if (ids == null || ids.isEmpty()) return null;
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        for (String i : ids) {
            String x = i == null ? "" : i.trim();
            if (!AdminApiStepUp.id(x)) return null;
            out.add(x);
        }
        return out.size() <= STATUS_MAX ? new java.util.ArrayList<>(out) : null;
    }
    /** One account's status as the portal sees it: the id and username it already shows, booleans, and a session
     *  count - never an identifier (no card number, no e-mail address, no provider id), never a secret. */
    static java.util.Map<String, Object> statusView(String id, String username, boolean enabled, boolean locked, boolean passwordSet,
                                                    boolean otpEnrolled, boolean cardBound, boolean cardPending,
                                                    boolean entraLinked, long activeSessions) {
        java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("id", id); m.put("username", username);
        m.put("enabled", enabled); m.put("locked", locked); m.put("passwordSet", passwordSet); m.put("otpEnrolled", otpEnrolled);
        m.put("cardBound", cardBound); m.put("cardPending", cardPending); m.put("entraLinked", entraLinked);
        m.put("activeSessions", activeSessions);
        return m;
    }
    /** Why a portal operation must not run for this caller's client (null: it may). The portal operations are for an
     *  application page's onboarding client only (the admin-API profile, its operations list naming `op`): never a
     *  token of the admin console or of any other client, whatever its holder's roles. */
    static String portalRefusal(String profile, String opsAttr, String op) {
        if (profile == null || !AdminApiStepUp.ACCOUNT_ONBOARDING.equals(profile.trim()))
            return "not a token of an onboarding client (" + AdminApiStepUp.PROFILE_ATTR + "=" + AdminApiStepUp.ACCOUNT_ONBOARDING + ")";
        java.util.Set<String> ops = AdminApiStepUp.operations(opsAttr);
        if (ops == null) return "the client's " + AdminApiStepUp.OPS_ATTR + " is malformed";
        if (!ops.contains(op)) return "the client's " + AdminApiStepUp.OPS_ATTR + " does not list " + op;
        return null;
    }
    /** Why a link request from the portal must not be written (null: it may). The portal never binds a card directly
     *  and never replaces one: those stay with the IdP's operators (idp-admin.py link-cac --replace / --bind-edipi). */
    static String portalLinkRefusal(boolean enabled, String currentCard, String pendingCard, boolean hasLinkRequest,
                                    boolean canSignIn) {
        if (!enabled) return "the account is disabled";
        if (currentCard != null && !currentCard.isBlank()) return "the account already has a card: replacing one is for the IdP's operators";
        if (pendingCard != null && !pendingCard.isBlank() && !hasLinkRequest)
            return "the account's invitation names a card not presented yet";
        if (!canSignIn) return "the account has no password and no identity-provider link, so it cannot sign in to present a card";
        return null;
    }
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
