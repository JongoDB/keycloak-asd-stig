package mil.stig.keycloak;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The FIRST sign-in through the configured identity provider may bind its identity to a PENDING INVITE - an account a
 * delegated user manager created through stig-accounts and that has never been bound or used - instead of requiring
 * the administrator to copy the provider's object id in advance. Off unless a domain is configured. Pure rules,
 * unit-tested without Keycloak; IdpLinkByAdminAttributeAuthenticatorFactory applies them only after the usual
 * admin-set binding found no account, and only once AdminBoundIdentity's preconditions held (provider alias, tenant,
 * no mapper writing the binding, a vouched object id).
 *
 * All of these, or no binding (the sign-in is refused, exactly as without this mode):
 *   - the provider vouches for a principal name (its UPN / preferred_username, read from the provider's own mapper
 *     into a dedicated attribute - never the mutable e-mail claim) of the form local@domain with domain = the
 *     configured one (case-insensitive);
 *   - EXACTLY ONE account has that principal name as its username or its e-mail on record (case-insensitive);
 *   - that account was invited FOR the provider: it carries the pending marker (entra_pending, set only by
 *     stig-accounts' signIn "entra"), its e-mail is in the configured domain, and it owes no password, OTP or passkey
 *     set-up (a password-type invite still in set-up is never claimed through the provider);
 *   - that account: carries the delegate-creation marker (stig_created_by), is enabled, has NO administrator-set
 *     binding yet, NO stored credential (password, OTP, passkey), NO card binding and no session (it has never been
 *     signed into: an invite for Entra AND a card only NAMES the card, which PresentCardRequiredAction binds after this
 *     step, once the person presents that card), and was created no more than
 *     max-age days ago (by Keycloak's creation time AND by the marker's own time: the older one counts).
 * After binding, the binding is the admin-set attribute like any other: a different object id for the account is
 * refused from then on (by this step and by the post-broker match).
 */
final class PendingInviteLink {
    private PendingInviteLink() { }

    static final String P_DOMAIN = "stig.pending-invite-domain", P_MAX_DAYS = "stig.pending-invite-max-age-days",
            P_UPN = "stig.vouched-upn-attribute", P_CARD = "stig.card-attribute", P_MARKER = "stig.created-by-attribute",
            P_IDP = "stig.vouched-idp-attribute", P_ACCT = "stig.vouched-acct-attribute";
    static final int DEFAULT_MAX_DAYS = 7, MAX_MAX_DAYS = 30;
    static final String PENDING_MARKER = "entra_pending";
    /** The marker's value: fixed, so the operator's tooling finds pending invites with an exact attribute search
     *  (q=entra_pending:pending) instead of reading every account. Their age comes from Keycloak's creation time and
     *  the delegate marker's; a numeric value (an epoch-ms time, as earlier builds wrote) still counts as a time too. */
    static final String PENDING_VALUE = "pending";
    static final Pattern PRINCIPAL = Pattern.compile("^[A-Za-z0-9._%+'-]{1,64}@([A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+)$");

    /** What the rules need to know about one candidate account. */
    record Candidate(String id, String username, String email, boolean enabled, String createdBy, String binding,
                     boolean hasCredential, String card, Long createdMs, String pending, java.util.List<String> requiredActions,
                     boolean hasSession) {
        Candidate(String id, String username, String email, boolean enabled, String createdBy, String binding, boolean hasCredential,
                  String card, Long createdMs, String pending, java.util.List<String> requiredActions) {
            this(id, username, email, enabled, createdBy, binding, hasCredential, card, createdMs, pending, requiredActions, false);
        }
    }
    /** Set-up actions of a password-type invite: an account still owing one of them was not invited for the provider. */
    static final java.util.Set<String> PASSWORD_SETUP = java.util.Set.of("UPDATE_PASSWORD", "CONFIGURE_TOTP", "webauthn-register",
            "webauthn-register-passwordless");

    /** The configuration, or null when the mode is off (no domain) or misconfigured (then also off: fail closed). */
    record Cfg(String domain, int maxDays, String upnAttr, String cardAttr, String markerAttr, String idpAttr, String acctAttr) { }

    static Cfg cfg(Map<String, String> c) {
        Map<String, String> m = c == null ? Map.of() : c;
        String d = m.get(P_DOMAIN);
        if (d == null || d.isBlank()) return null;
        d = d.trim().toLowerCase(Locale.ROOT);
        if (!d.matches("^[a-z0-9-]+(\\.[a-z0-9-]+)+$")) return null;
        int days;
        try {
            days = Integer.parseInt(m.getOrDefault(P_MAX_DAYS, String.valueOf(DEFAULT_MAX_DAYS)).trim());
        } catch (NumberFormatException e) {
            return null;
        }
        if (days < 1 || days > MAX_MAX_DAYS) return null;
        return new Cfg(d, days, m.getOrDefault(P_UPN, "entra_vouched_upn"), m.getOrDefault(P_CARD, "cac_edipi"),
                m.getOrDefault(P_MARKER, "stig_created_by"), m.getOrDefault(P_IDP, "entra_vouched_idp"),
                m.getOrDefault(P_ACCT, "entra_vouched_acct"));
    }

    /**
     * A GUEST of the tenant (B2B from another tenant, e-mail one-time passcode, a Microsoft account, a social or SAML
     * provider) carries the tenant's tid but its preferred_username is its HOME sign-in name - possibly in the domain.
     * Entra marks it: the `idp` claim names the provider that authenticated the person (absent for the tenant's own
     * members, or naming the tenant itself), and the optional `acct` claim is 1 for a guest. Null = a member; else why not.
     */
    static String guest(String idp, String acct, String tenant) {
        if (acct != null && !acct.isBlank() && !acct.trim().equals("0")) return "the provider reports a guest account (acct=" + acct.trim() + ")";
        if (idp == null || idp.isBlank()) return null;
        String i = idp.trim().toLowerCase(Locale.ROOT), t = tenant == null ? "" : tenant.trim().toLowerCase(Locale.ROOT);
        if (!t.isEmpty() && (i.equals("https://sts.windows.net/" + t + "/") || i.equals("https://login.microsoftonline.com/" + t + "/v2.0")))
            return null;
        return "the provider reports a guest of the tenant (idp=" + idp.trim() + ")";
    }

    /** One identity-provider mapper, as far as the pinning rule needs it. */
    record Mapper(String alias, String type, String claim, String target) { }
    static final String ATTRIBUTE_MAPPER = "oidc-user-attribute-idp-mapper";

    /**
     * The vouched attributes this mode reads must come from exactly the expected claims of the provider: EXACTLY ONE
     * mapper in the realm writes the UPN attribute, and it is the provider's attribute importer from preferred_username;
     * the same for the idp attribute from `idp` (without it a guest would pass unseen). The acct attribute is optional
     * (an optional claim), but if any mapper writes it, exactly one does, from `acct`. Null = pinned; else why not.
     */
    static String mappersPinned(Cfg c, String alias, Collection<Mapper> ms) {
        String w = pin(c.upnAttr(), "preferred_username", alias, ms, true);
        if (w == null) w = pin(c.idpAttr(), "idp", alias, ms, true);
        if (w == null) w = pin(c.acctAttr(), "acct", alias, ms, false);
        return w;
    }

    private static String pin(String attr, String claim, String alias, Collection<Mapper> ms, boolean required) {
        List<Mapper> w = ms.stream().filter(m -> m.target() != null && m.target().trim().equalsIgnoreCase(attr)).toList();
        if (w.isEmpty()) return required ? "no identity-provider mapper writes " + attr + " (from the " + claim + " claim)" : null;
        if (w.size() > 1) return "more than one identity-provider mapper writes " + attr;
        Mapper m = w.get(0);
        if (!alias.equals(m.alias()) || !ATTRIBUTE_MAPPER.equals(m.type()) || m.claim() == null || !claim.equals(m.claim().trim()))
            return "the mapper writing " + attr + " is not " + alias + "'s importer of the " + claim + " claim";
        return null;
    }

    /** The principal name, lower-cased, when it is local@<configured domain>; else null. */
    static String principal(Cfg c, String vouchedUpn) {
        if (c == null || vouchedUpn == null) return null;
        String u = vouchedUpn.trim();
        var mm = PRINCIPAL.matcher(u);
        if (!mm.matches() || !mm.group(1).equalsIgnoreCase(c.domain())) return null;
        return u.toLowerCase(Locale.ROOT);
    }

    /** The creation time a stig-accounts marker records ("<caller> <epoch ms>"), or null. */
    static Long markerTime(String createdBy) {
        if (createdBy == null) return null;
        String[] p = createdBy.trim().split("\\s+");
        try {
            return p.length >= 2 ? Long.parseLong(p[p.length - 1]) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** The result: the one account to bind (id), or why not. */
    record Result(String id, String refusal) {
        static Result bind(String id) { return new Result(id, null); }
        static Result refuse(String why) { return new Result(null, why); }
    }

    /**
     * @param candidates every account whose username OR e-mail equals the principal name (case-insensitive), each once
     */
    static Result decide(Cfg c, String vouchedUpn, Collection<Candidate> candidates, long nowMs) {
        if (c == null) return Result.refuse("pending-invite binding is off");
        String p = principal(c, vouchedUpn);
        if (p == null) return Result.refuse("the provider vouched for no principal name in " + c.domain());
        Map<String, Candidate> byId = new LinkedHashMap<>();
        for (Candidate x : candidates) {
            boolean same = (x.username() != null && x.username().equalsIgnoreCase(p)) || (x.email() != null && x.email().equalsIgnoreCase(p));
            if (same) byId.put(x.id(), x);
        }
        if (byId.isEmpty()) return Result.refuse("no account has " + p + " as its username or e-mail");
        if (byId.size() > 1) return Result.refuse("more than one account has " + p + " as its username or e-mail");
        Candidate a = byId.values().iterator().next();
        if (a.createdBy() == null || a.createdBy().isBlank()) return Result.refuse("the account was not created by a delegated user manager");
        if (a.pending() == null || a.pending().isBlank()) return Result.refuse("the account was not invited to sign in through the provider (no " + PENDING_MARKER + ")");
        if (a.email() == null || a.email().indexOf('@') < 0
                || !a.email().substring(a.email().lastIndexOf('@') + 1).equalsIgnoreCase(c.domain()))
            return Result.refuse("the account's e-mail is not in " + c.domain());
        if (a.requiredActions() != null && a.requiredActions().stream().anyMatch(PASSWORD_SETUP::contains))
            return Result.refuse("the account is a password-type invite still in set-up");
        if (!a.enabled()) return Result.refuse("the account is disabled");
        if (a.binding() != null && !a.binding().isBlank()) return Result.refuse("the account is already bound to another identity");
        if (a.hasCredential()) return Result.refuse("the account already has a credential");
        if (a.card() != null && !a.card().isBlank()) return Result.refuse("the account has a card binding");
        // signed into already (by any means) before the provider binding: never bound to the provider afterwards
        if (a.hasSession()) return Result.refuse("the account has already been signed into");
        long limit = c.maxDays() * 86_400_000L;
        Long t1 = a.createdMs(), t2 = markerTime(a.createdBy()), t3 = null;
        String pv = a.pending() == null ? "" : a.pending().trim();
        if (pv.matches("[0-9]{1,15}")) t3 = Long.parseLong(pv);
        if (t1 == null && t2 == null && t3 == null) return Result.refuse("the account's creation time is unknown");
        long oldest = Math.min(Math.min(t1 == null ? Long.MAX_VALUE : t1, t2 == null ? Long.MAX_VALUE : t2), t3 == null ? Long.MAX_VALUE : t3);
        for (Long t : new Long[] {t1, t2, t3})       // any recorded time in the future: something wrote it - refuse
            if (t != null && t > nowMs + 60_000L) return Result.refuse("the account's creation time is in the future");
        if (nowMs - oldest > limit) return Result.refuse("the invitation is older than " + c.maxDays() + " days");
        return Result.bind(a.id());
    }

    static List<org.keycloak.provider.ProviderConfigProperty> properties() {
        return List.of(
            new org.keycloak.provider.ProviderConfigProperty(P_DOMAIN, "Pending-invite domain",
                "Empty: off. Else the first sign-in may bind to a pending invite whose username or e-mail is the provider's principal name in this domain.",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, null),
            new org.keycloak.provider.ProviderConfigProperty(P_MAX_DAYS, "Pending-invite maximum age (days)", "1..30, default 7.",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_MAX_DAYS)),
            new org.keycloak.provider.ProviderConfigProperty(P_UPN, "Vouched principal-name attribute",
                "Filled by the provider's mapper from its UPN / preferred_username claim (never the e-mail claim).",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, "entra_vouched_upn"),
            new org.keycloak.provider.ProviderConfigProperty(P_IDP, "Vouched idp attribute",
                "Filled by the provider's mapper from the idp claim; a guest of the tenant is never bound.",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, "entra_vouched_idp"),
            new org.keycloak.provider.ProviderConfigProperty(P_ACCT, "Vouched acct attribute",
                "Optional: filled from the optional acct claim; anything but 0 (a guest) is never bound.",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, "entra_vouched_acct"),
            new org.keycloak.provider.ProviderConfigProperty(P_CARD, "Card binding attribute", "An account with one is never bound here.",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, "cac_edipi"),
            new org.keycloak.provider.ProviderConfigProperty(P_MARKER, "Delegate-creation marker", "Set by stig-accounts on the accounts it creates.",
                org.keycloak.provider.ProviderConfigProperty.STRING_TYPE, "stig_created_by"));
    }
}
