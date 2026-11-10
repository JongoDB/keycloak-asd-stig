package mil.stig.keycloak;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * The binding between an account and ONE identity at ONE identity provider, as an administrator recorded it.
 *
 *  - The administrator-set value lives in {@code admin-attribute} (default entra_oid). No identity-provider mapper may
 *    target it: if any does, every brokered sign-in is refused (a mapper - IMPORT or FORCE - could otherwise copy the
 *    incoming identity over the recorded one before this check reads it).
 *  - What the provider vouches for is read from the brokered context, filled on every sign-in by that provider's own
 *    mappers into dedicated attributes ({@code vouched-oid-attribute}, {@code vouched-tenant-attribute}; default
 *    entra_vouched_oid / entra_vouched_tid, from the ID token's oid / tid claims). There is no fallback to raw claims.
 *  - It counts only from the configured provider alias AND the configured tenant: another provider presenting the same
 *    oid, or another tenant, is refused.
 *  - Unconfigured (no tenant-id) is a refusal.
 */
final class AdminBoundIdentity {
    static final String P_ALIAS = "stig.idp-alias", P_TENANT = "stig.tenant-id", P_ADMIN = "stig.admin-attribute",
            P_OID = "stig.vouched-oid-attribute", P_TID = "stig.vouched-tenant-attribute";
    /** IdP mapper config keys that name a user attribute the mapper writes. */
    static final List<String> MAPPER_TARGET_KEYS = List.of("user.attribute", "attribute", "attribute.name");

    final String alias, tenant, adminAttr, oidAttr, tidAttr;

    Cfg cfg() { return new Cfg(alias, tenant, adminAttr, oidAttr, tidAttr); }
    record Cfg(String alias, String tenant, String adminAttr, String oidAttr, String tidAttr) { }

    AdminBoundIdentity(Map<String, String> c) {
        Map<String, String> m = c == null ? Map.of() : c;
        alias = m.getOrDefault(P_ALIAS, "entra");
        tenant = m.get(P_TENANT);
        adminAttr = m.getOrDefault(P_ADMIN, "entra_oid");
        oidAttr = m.getOrDefault(P_OID, "entra_vouched_oid");
        tidAttr = m.getOrDefault(P_TID, "entra_vouched_tid");
    }

    static AdminBoundIdentity of(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cm = context.getAuthenticatorConfig();
        return new AdminBoundIdentity(cm == null ? null : cm.getConfig());
    }

    /** Lower-cased attribute names that any identity-provider mapper of this realm writes. */
    static List<String> mapperTargets(AuthenticationFlowContext context) {
        return context.getSession().identityProviders().getMappersStream()
                .map(IdentityProviderMapperModel::getConfig).filter(java.util.Objects::nonNull)
                .flatMap(cfg -> MAPPER_TARGET_KEYS.stream().map(cfg::get))
                .filter(v -> v != null && !v.isBlank()).map(v -> v.trim().toLowerCase(Locale.ROOT)).collect(Collectors.toList());
    }

    static String first(BrokeredIdentityContext b, String attr) {
        Map<String, List<String>> at = b.getAttributes();
        List<String> v = at == null ? null : at.get(attr);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    /** Why the brokered identity may NOT be used, or null when it may. Pure: unit-tested without Keycloak. */
    static String preconditions(Cfg c, String brokeredAlias, String vouchedOid, String vouchedTid, Collection<String> mapperTargets) {
        if (c.tenant() == null || c.tenant().isBlank()) return "not configured (" + P_TENANT + ")";
        if (mapperTargets.contains(c.adminAttr().toLowerCase(Locale.ROOT)))
            return "an identity-provider mapper writes the administrator-set attribute " + c.adminAttr();
        if (brokeredAlias == null || !brokeredAlias.equals(c.alias())) return "provider " + brokeredAlias + " is not " + c.alias();
        if (vouchedTid == null || !vouchedTid.trim().equalsIgnoreCase(c.tenant().trim())) return "not from tenant " + c.tenant();
        if (vouchedOid == null || vouchedOid.isBlank()) return "the provider vouched for no " + c.oidAttr();
        return null;
    }

    /** As preconditions, and the vouched identity must equal the account's administrator-set one. */
    static String refusal(Cfg c, String brokeredAlias, String vouchedOid, String vouchedTid, String held, Collection<String> mapperTargets) {
        String why = preconditions(c, brokeredAlias, vouchedOid, vouchedTid, mapperTargets);
        if (why != null) return why;
        if (held == null || held.isBlank()) return "the account has no administrator-set " + c.adminAttr();
        if (!held.trim().equalsIgnoreCase(vouchedOid.trim())) return "the provider vouched for another identity";
        return null;
    }

    static List<ProviderConfigProperty> properties() {
        return List.of(
            prop(P_ALIAS, "Identity provider alias", "Only this provider's sign-ins count.", "entra"),
            prop(P_TENANT, "Tenant id", "Required. The vouched tenant (tid) must equal this.", null),
            prop(P_ADMIN, "Administrator-set attribute", "Holds the bound identity; no IdP mapper may write it.", "entra_oid"),
            prop(P_OID, "Vouched identity attribute", "Filled by the provider's mapper from the oid claim.", "entra_vouched_oid"),
            prop(P_TID, "Vouched tenant attribute", "Filled by the provider's mapper from the tid claim.", "entra_vouched_tid"));
    }

    private static ProviderConfigProperty prop(String name, String label, String help, String def) {
        ProviderConfigProperty p = new ProviderConfigProperty(name, label, help, ProviderConfigProperty.STRING_TYPE, def);
        return p;
    }
}
