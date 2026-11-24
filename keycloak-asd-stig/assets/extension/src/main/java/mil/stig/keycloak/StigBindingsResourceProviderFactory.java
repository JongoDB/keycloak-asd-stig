package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * /admin/realms/{realm}/stig-bindings - the operator's tooling writes an account's identity bindings here, server-side,
 * instead of PUTting the whole user representation: Keycloak stores the request body of a user update in its admin
 * event, so a PUT that carries the card attribute writes the full EDIPI into the event store. This endpoint writes the
 * attributes itself and records an admin event that carries the card MASKED (last four digits) only.
 *
 *   POST /users/{id}   {"set": {name: value, ...}, "remove": [name, ...], "presentCard": "add" | "remove", "reason": "...",
 *                       "profile": {username, email, firstName, lastName, emailVerified, enabled, requiredActions}}
 *                      200 {"set": [names], "removed": [names]}
 *
 * `profile` updates those fields of the account without touching its attributes (a PUT of the representation would be
 * stored in the admin event with every attribute, the card included): username (unique, lower case), e-mail ("" clears
 * it; unique when the realm requires it), names, the two flags, and the exact list of required actions.
 * Names it may set: cac_edipi, cac_edipi_pending (exactly ten digits), stig_card_link ("<epoch-ms>" or "<epoch-ms>
 * admin"), entra_oid (an object id). It may also remove those, stig_created_by and the retired entra_amr. Nothing else (400). A card value
 * held by another account as its card or its pending card, or an entra_oid held by another account: 409, nothing
 * changed. A card is claimed atomically first (the same claim stig-accounts' card creates and the present-card step
 * take), so two writers cannot bind one card to two accounts.
 *
 * Only a realm administrator of this realm (realm-management realm-admin) or a master-realm administrator - the same
 * rule cac-identity-guard applies to these attributes through the user profile - may call it; anyone else gets 403
 * for every method and path. The admin event (UPDATE users/{id}) holds {"stig": "identity bindings", "reason",
 * "stigBindings": {name: masked card | object id | time | null (removed)}}.
 */
public class StigBindingsResourceProviderFactory implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {

    public static final String ID = "stig-bindings";
    private static final Logger LOG = Logger.getLogger("mil.stig.audit");
    static final String CARD = "cac_edipi", PENDING = "cac_edipi_pending", ENTRA = "entra_oid", CREATED_BY = "stig_created_by";
    static final Set<String> SETTABLE = Set.of(CARD, PENDING, AccountsPolicy.LINK_ATTRIBUTE, ENTRA);
    /** The retired per-user record of Entra's amr (idp-admin.py clears it: a stored "mfa" must never outlive the mapper). */
    static final String RETIRED_AMR = "entra_amr";
    static final Set<String> REMOVABLE = Set.of(CARD, PENDING, AccountsPolicy.LINK_ATTRIBUTE, ENTRA, CREATED_BY, RETIRED_AMR);
    static final String PRESENT_CARD = "stig-present-card";

    @Override public AdminRealmResourceProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        if (!CacIdentityGuardValidatorFactory.isRealmAdmin(session, realm)) {
            UserModel caller = auth.adminAuth().getUser();
            LOG.warnf("STIG-BINDINGS-REFUSED realm=%s caller=%s: not a realm administrator", realm.getName(), caller == null ? "?" : caller.getUsername());
            return new StigAccountsResourceProviderFactory.Refused();
        }
        return new Bindings(session, realm, auth, adminEvent);
    }

    /** A request, checked: (error or null, the values to set, the names to remove, the present-card change or null). */
    record Plan(String error, Map<String, String> set, List<String> remove, String presentCard, String reason, Map<String, Object> profile) {
        Plan(String error, Map<String, String> set, List<String> remove, String presentCard, String reason) {
            this(error, set, remove, presentCard, reason, Map.of());
        }
    }
    static final Set<String> PROFILE = Set.of("username", "email", "firstName", "lastName", "emailVerified", "enabled", "requiredActions");

    @SuppressWarnings("unchecked")
    static Plan plan(Map<String, Object> body) {
        if (body == null) return new Plan("a JSON object is required", null, null, null, null);
        for (String k : body.keySet())
            if (!Set.of("set", "remove", "presentCard", "reason", "profile").contains(k)) return new Plan("unknown field " + k, null, null, null, null);
        Map<String, String> set = new LinkedHashMap<>(); List<String> remove = new ArrayList<>();
        Object s = body.get("set"), r = body.get("remove"), pc = body.get("presentCard"), why = body.get("reason");
        if (s != null) {
            if (!(s instanceof Map)) return new Plan("set must be an object", null, null, null, null);
            for (Map.Entry<String, Object> e : ((Map<String, Object>) s).entrySet()) {
                String n = e.getKey(), v = e.getValue() instanceof String ? ((String) e.getValue()).trim() : null;
                if (!SETTABLE.contains(n)) return new Plan(n + " cannot be set here", null, null, null, null);
                if (v == null) return new Plan(n + " must be a string", null, null, null, null);
                boolean ok = switch (n) {
                    case CARD, PENDING -> AccountsPolicy.validEdipi(v);
                    case ENTRA -> v.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
                    default -> AccountsPolicy.linkTime(v) != null;
                };
                if (!ok) return new Plan(n + " is malformed", null, null, null, null);
                set.put(n, v);
            }
        }
        if (r != null) {
            if (!(r instanceof List)) return new Plan("remove must be a list", null, null, null, null);
            for (Object o : (List<Object>) r) {
                if (!(o instanceof String) || !REMOVABLE.contains(o)) return new Plan(o + " cannot be removed here", null, null, null, null);
                if (set.containsKey(o)) return new Plan(o + " is both set and removed", null, null, null, null);
                remove.add((String) o);
            }
        }
        if (pc != null && !"add".equals(pc) && !"remove".equals(pc)) return new Plan("presentCard must be add or remove", null, null, null, null);
        if (why != null && (!(why instanceof String) || !((String) why).matches("[a-z][a-z0-9 _-]{0,39}")))
            return new Plan("reason must be 1-40 of a-z 0-9 space _ -", null, null, null, null);
        Map<String, Object> prof = new LinkedHashMap<>();
        Object pr = body.get("profile");
        if (pr != null) {
            if (!(pr instanceof Map)) return new Plan("profile must be an object", null, null, null, null);
            for (Map.Entry<String, Object> e : ((Map<String, Object>) pr).entrySet()) {
                String n = e.getKey(); Object v = e.getValue();
                if (!PROFILE.contains(n)) return new Plan(n + " cannot be changed here", null, null, null, null);
                boolean ok = switch (n) {
                    case "emailVerified", "enabled" -> v instanceof Boolean;
                    case "requiredActions" -> v instanceof List && ((List<Object>) v).stream().allMatch(x -> x instanceof String && !((String) x).isBlank());
                    case "username" -> v instanceof String && !((String) v).isBlank() && ((String) v).trim().length() <= 255;
                    case "email" -> v instanceof String && (((String) v).isEmpty() || ((String) v).matches("[^@\\s]+@[^@\\s]+"));
                    default -> v instanceof String && ((String) v).length() <= 255;
                };
                if (!ok) return new Plan(n + " is malformed", null, null, null, null);
                prof.put(n, v);
            }
        }
        if (set.isEmpty() && remove.isEmpty() && pc == null && prof.isEmpty()) return new Plan("nothing to do", null, null, null, null);
        return new Plan(null, set, remove, (String) pc, (String) why, prof);
    }

    /** What the admin event shows for a value: a card masked, anything else as it is. */
    static Object shown(String name, String value) {
        if (value == null) return null;
        return CARD.equals(name) || PENDING.equals(name) ? AccountsPolicy.maskEdipi(value) : value;
    }

    @Produces(MediaType.APPLICATION_JSON)
    public static final class Bindings {
        private final KeycloakSession session; private final RealmModel realm; private final AdminPermissionEvaluator auth;
        private final AdminEventBuilder adminEvent;

        Bindings(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
            this.session = session; this.realm = realm; this.auth = auth; this.adminEvent = adminEvent;
        }

        private static Response err(Response.Status st, String msg) {
            return Response.status(st).entity(Map.of("error", msg)).type(MediaType.APPLICATION_JSON).build();
        }

        @POST @Path("users/{id}") @Consumes(MediaType.APPLICATION_JSON)
        public Response write(@PathParam("id") String id, Map<String, Object> body) {
            Plan p = plan(body);
            if (p.error() != null) return err(Response.Status.BAD_REQUEST, p.error());
            UserModel u = id == null ? null : session.users().getUserById(realm, id);
            if (u == null) return err(Response.Status.NOT_FOUND, "no such user");
            String caller = auth.adminAuth().getUser() == null ? "?" : auth.adminAuth().getUser().getUsername();
            return apply(u, p, caller);
        }

        private Response apply(UserModel u, Plan p, String caller) {
            for (Map.Entry<String, String> e : p.set().entrySet()) {
                String n = e.getKey(), v = e.getValue();
                if (CARD.equals(n) || PENDING.equals(n) || ENTRA.equals(n)) {   // claim first, then check: two writers cannot both pass
                    String key = (ENTRA.equals(n) ? "stig-bindings-entra:" : "stig-accounts-card:") + realm.getId() + ":" + v;
                    if (!session.singleUseObjects().putIfAbsent(key, 60)) {
                        LOG.warnf("STIG-BINDINGS-REFUSED realm=%s caller=%s user=%s: %s %s is being bound elsewhere right now",
                                realm.getName(), caller, u.getUsername(), n, shown(n, v));
                        return err(Response.Status.CONFLICT, n + " is being bound elsewhere right now");
                    }
                    AccountsPolicy.releaseAfterCompletion(session, key);      // held until this write commits or rolls back
                }
                List<String> attrs = CARD.equals(n) || PENDING.equals(n) ? List.of(CARD, PENDING) : ENTRA.equals(n) ? List.of(ENTRA) : List.of();
                for (String a : attrs) {
                    if (session.users().searchForUserByUserAttributeStream(realm, a, v).anyMatch(x -> !x.getId().equals(u.getId()))) {
                        LOG.warnf("STIG-BINDINGS-REFUSED realm=%s caller=%s user=%s: %s %s is already held by another account",
                                realm.getName(), caller, u.getUsername(), n, shown(n, v));
                        return err(Response.Status.CONFLICT, n + " is already held by another account");
                    }
                }
            }
            Map<String, Object> prof = p.profile();
            if (prof.containsKey("username")) {
                String nu = ((String) prof.get("username")).trim().toLowerCase(java.util.Locale.ROOT);
                UserModel other = session.users().getUserByUsername(realm, nu);
                if (other != null && !other.getId().equals(u.getId())) return err(Response.Status.CONFLICT, "that username is in use");
            }
            if (prof.containsKey("email") && !((String) prof.get("email")).isEmpty() && !realm.isDuplicateEmailsAllowed()) {
                UserModel other = session.users().getUserByEmail(realm, (String) prof.get("email"));
                if (other != null && !other.getId().equals(u.getId())) return err(Response.Status.CONFLICT, "that e-mail address is in use");
            }
            Map<String, Object> shownMap = new LinkedHashMap<>();
            for (String n : p.remove()) {
                u.removeAttribute(n); shownMap.put(n, null);
            }
            for (Map.Entry<String, String> e : p.set().entrySet()) {
                u.setSingleAttribute(e.getKey(), e.getValue()); shownMap.put(e.getKey(), shown(e.getKey(), e.getValue()));
            }
            if ("add".equals(p.presentCard())) u.addRequiredAction(PRESENT_CARD);
            if ("remove".equals(p.presentCard())) u.removeRequiredAction(PRESENT_CARD);
            if (prof.containsKey("username")) u.setUsername(((String) prof.get("username")).trim().toLowerCase(java.util.Locale.ROOT));
            if (prof.containsKey("email")) u.setEmail(((String) prof.get("email")).isEmpty() ? null : (String) prof.get("email"));
            if (prof.containsKey("firstName")) u.setFirstName((String) prof.get("firstName"));
            if (prof.containsKey("lastName")) u.setLastName((String) prof.get("lastName"));
            if (prof.containsKey("emailVerified")) u.setEmailVerified((Boolean) prof.get("emailVerified"));
            if (prof.containsKey("enabled")) u.setEnabled((Boolean) prof.get("enabled"));
            if (prof.containsKey("requiredActions")) {
                @SuppressWarnings("unchecked") List<String> want = (List<String>) prof.get("requiredActions");
                u.getRequiredActionsStream().filter(x -> !want.contains(x)).collect(java.util.stream.Collectors.toList()).forEach(u::removeRequiredAction);
                want.forEach(u::addRequiredAction);
            }
            Map<String, Object> rep = new LinkedHashMap<>();
            rep.put("stig", "identity bindings");
            if (p.reason() != null) rep.put("reason", p.reason());
            rep.put("stigBindings", shownMap);
            if (p.presentCard() != null) rep.put("presentCard", p.presentCard());
            if (!prof.isEmpty()) rep.put("profile", prof);
            adminEvent.operation(OperationType.UPDATE).resource(ResourceType.USER).resourcePath("users", u.getId()).representation(rep).success();
            LOG.infof("STIG-BINDINGS realm=%s caller=%s user=%s reason=%s %s", realm.getName(), caller, u.getUsername(),
                    p.reason() == null ? "-" : p.reason().replace(' ', '_'), shownMap);
            return Response.ok(Map.of("set", new ArrayList<>(p.set().keySet()), "removed", p.remove(), "profile", new ArrayList<>(prof.keySet()))).build();
        }

        // Nothing else: every other method or path is refused.
        @GET @Path("{any: .*}") public Response g() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @GET public Response g0() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @POST @Path("{any: .*}") public Response p() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @PUT @Path("{any: .*}") public Response u() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @DELETE @Path("{any: .*}") public Response d() { return err(Response.Status.FORBIDDEN, "not allowed"); }
        @PATCH @Path("{any: .*}") public Response pa() { return err(Response.Status.FORBIDDEN, "not allowed"); }
    }
}
