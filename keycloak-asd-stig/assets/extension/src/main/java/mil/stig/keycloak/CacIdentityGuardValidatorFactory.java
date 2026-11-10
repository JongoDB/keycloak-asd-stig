package mil.stig.keycloak;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.userprofile.AttributeContext;
import org.keycloak.userprofile.UserProfileAttributeValidationContext;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.validate.SimpleValidator;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidationError;
import org.keycloak.validate.Validator;
import org.keycloak.validate.ValidatorConfig;
import org.keycloak.validate.ValidatorFactory;

/**
 * User-profile validator for the attribute that maps a card to an account (the x509 mapping attribute: cac_upn,
 * cac_edipi, ...). Two rules (V-222552, V-222522: one certificate identifies exactly one person):
 *
 *  1. UNIQUE: no other account in the realm may hold the same value. Keycloak's X.509 lookup needs exactly one
 *     match; a duplicate makes the card resolve ambiguously.
 *  2. REALM ADMINS ONLY: through the admin REST API (USER_API context) the value may be set or changed only by a
 *     caller holding realm-management realm-admin for this realm, or a master-realm administrator. Not manage-users:
 *     binding a card (a strong authenticator) to an account is how a user manager could make their own card open
 *     an administrator's account, so it stays with the people who already hold every right in the realm.
 *     A delegate with fine-grained admin permissions (e.g. manage-members on a group) counts as "admin" for the
 *     user profile, but must not be able to point a card at an account. Unchanged values always pass, so such a
 *     delegate can still edit names and other attributes.
 *
 * Configuration: "unique" (default "true"). Attach as {"cac-identity-guard": {}} to a card-mapping attribute, or as
 * {"cac-identity-guard": {"unique": "false"}} to other identity evidence only realm administrators (or Keycloak itself,
 * e.g. an identity-provider mapper, which does not go through the admin API) may write - such as the amr an
 * identity provider reported.
 */
public class CacIdentityGuardValidatorFactory implements ValidatorFactory, SimpleValidator {

    public static final String ID = "cac-identity-guard";
    static final String MSG_TAKEN = "cacIdentityTaken";
    static final String MSG_FORBIDDEN = "cacIdentityAdminOnly";

    @Override
    public ValidationContext validate(Object input, String inputHint, ValidationContext context, ValidatorConfig config) {
        if (!(context instanceof UserProfileAttributeValidationContext)) {
            return context;
        }
        AttributeContext ac = ((UserProfileAttributeValidationContext) context).getAttributeContext();
        KeycloakSession session = context.getSession();
        RealmModel realm = session.getContext().getRealm();
        String attr = ac.getMetadata().getName();
        UserModel user = ac.getUser();
        List<String> wanted = values(input);
        List<String> current = user == null ? List.of()
                : user.getAttributeStream(attr).filter(v -> v != null && !v.isBlank()).collect(Collectors.toList());

        // 1. uniqueness, whoever is asking
        boolean unique = config == null || !"false".equalsIgnoreCase(String.valueOf(config.getOrDefault("unique", "true")));
        for (String v : unique ? wanted : List.<String>of()) {
            boolean taken = session.users().searchForUserByUserAttributeStream(realm, attr, v)
                    .anyMatch(u -> user == null || !u.getId().equals(user.getId()));
            if (taken) {
                context.addError(new ValidationError(ID, inputHint, MSG_TAKEN, v));
                return context;
            }
        }
        // 2. only realm administrators may set or change it through the admin API
        boolean changed = !Set.copyOf(wanted).equals(Set.copyOf(current));
        if (changed && ac.getContext() == UserProfileContext.USER_API && !isRealmAdmin(session, realm)) {
            context.addError(new ValidationError(ID, inputHint, MSG_FORBIDDEN));
        }
        return context;
    }

    static List<String> values(Object input) {
        if (input instanceof Collection<?>) {
            return ((Collection<?>) input).stream().filter(Objects::nonNull).map(Object::toString)
                    .filter(s -> !s.isBlank()).collect(Collectors.toList());
        }
        return input == null || input.toString().isBlank() ? List.of() : List.of(input.toString());
    }

    /** The caller of this admin request holds realm-management realm-admin in this realm, or is a master-realm
     *  administrator (realm role admin). The caller comes
     *  from the AdminAuth that Keycloak's AdminRoot binds to the session ("AdminRoot.adminAuth"); roles are read
     *  from that account, composites and groups included (Keycloak 26 admin tokens carry neither roles nor, with
     *  lightweight tokens, a subject). Fails closed when there is no authenticated admin caller. */
    static boolean isRealmAdmin(KeycloakSession session, RealmModel realm) {
        Object a = session.getAttribute("AdminRoot.adminAuth");
        if (!(a instanceof AdminAuth)) {
            return false;
        }
        AdminAuth auth = (AdminAuth) a;
        RealmModel issuer = auth.getRealm();
        UserModel caller = auth.getUser();
        if (issuer == null || caller == null || !caller.isEnabled()) {
            return false;
        }
        // A master-realm administrator administers every realm, master included (master has no realm-management
        // client: its administrators hold the realm role admin). Checked first, so master's own users work too.
        if ("master".equals(issuer.getName())) {
            RoleModel admin = issuer.getRole("admin");
            return admin != null && caller.hasRole(admin);
        }
        if (issuer.getId().equals(realm.getId())) {
            return hasClientRole(caller, issuer.getClientByClientId("realm-management"), "realm-admin");
        }
        return false;
    }

    static boolean hasClientRole(UserModel user, ClientModel client, String... roles) {
        if (client == null) {
            return false;
        }
        for (String r : roles) {
            RoleModel role = client.getRole(r);
            if (role != null && user.hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    @Override public Validator create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }
}
