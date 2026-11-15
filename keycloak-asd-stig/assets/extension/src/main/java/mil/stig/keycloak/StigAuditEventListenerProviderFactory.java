package mil.stig.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Event listener id: stig-audit
 *
 * Covers ASD STIG items Keycloak does not provide out of the box:
 *  - V-222437 last successful logon: on LOGIN, copies user attribute stig_last_login to
 *    stig_previous_login and stamps stig_last_login with the current UTC time. Relying apps
 *    display stig_previous_login (exposed as a token claim by the realm generator).
 *  - V-222672 concurrent logons from different workstations: emits a WARN record tagged
 *    STIG-CONCURRENT-LOGON when a user logs in while holding a session from another IP.
 *  - Passkey realms: a failed passkey assertion's LOGIN_ERROR names no user; a WARN record tagged STIG-PASSKEY-FAILURE
 *    names the account the assertion targeted (from the posted user handle) and whether the posted credential is one
 *    of its passkeys, so the audit trail shows who was targeted (AC-7 rationale: these failures are not counted).
 *  - V-222417..V-222422 SA/ISSO notification of account create/modify/disable/remove/enable:
 *    emits WARN records tagged STIG-ACCOUNT-EVENT for SIEM alerting, and optionally emails
 *    the addresses in --spi-events-listener--stig-audit--notify-emails=a@x.mil,b@x.mil using
 *    the realm SMTP settings.
 */
public class StigAuditEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String ID = "stig-audit";
    static final Logger LOG = Logger.getLogger("mil.stig.audit");
    static final String LAST = "stig_last_login";
    static final String PREVIOUS = "stig_previous_login";

    private List<String> notifyEmails = List.of();
    private KeycloakSessionFactory factory;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new Listener(session, factory, notifyEmails);
    }

    @Override
    public void init(Config.Scope config) {
        String v = config.get("notifyEmails", config.get("notify-emails", ""));
        notifyEmails = Arrays.stream(v.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
    }

    @Override public void postInit(KeycloakSessionFactory f) { this.factory = f; }
    @Override public void close() { }
    @Override public String getId() { return ID; }

    static final class Listener implements EventListenerProvider {
        private final KeycloakSession session;
        private final KeycloakSessionFactory factory;
        private final List<String> notifyEmails;

        Listener(KeycloakSession s, KeycloakSessionFactory f, List<String> emails) {
            this.session = s; this.factory = f; this.notifyEmails = emails;
        }

        @Override
        public void onEvent(Event event) {
            if (event.getType() == EventType.LOGIN_ERROR && event.getUserId() == null) {
                try {
                    attributePasskeyFailure(event);
                } catch (RuntimeException e) {
                    LOG.errorf(e, "STIG-AUDIT passkey failure attribution failed");     // never break the request
                }
                return;
            }
            if (event.getType() != EventType.LOGIN || event.getUserId() == null) return;
            final String realmId = event.getRealmId();
            final String userId = event.getUserId();
            final String ip = event.getIpAddress();
            final String now = Instant.ofEpochMilli(event.getTime()).toString();

            // Separate transaction so a listener problem can never break the login itself.
            session.getTransactionManager().enlistAfterCompletion(new org.keycloak.models.AbstractKeycloakTransaction() {
                @Override protected void commitImpl() {
                  try {
                    KeycloakModelUtils.runJobInTransaction(factory, s -> {
                        RealmModel realm = s.realms().getRealm(realmId);
                        if (realm == null) return;
                        s.getContext().setRealm(realm); // required by the user cache / organization provider
                        UserModel user = s.users().getUserById(realm, userId);
                        if (user == null) return;
                        // a sign-in proves the account is in use: it is no longer "disabled for inactivity", so a later
                        // disable by anyone else can never be undone by stig-accounts' reactivate
                        if (user.getFirstAttribute(StigAccountsResourceProviderFactory.DISABLED_MARKER) != null) {
                            user.removeAttribute(StigAccountsResourceProviderFactory.DISABLED_MARKER);
                        }
                        String last = user.getFirstAttribute(LAST);
                        if (last != null) user.setSingleAttribute(PREVIOUS, last);
                        user.setSingleAttribute(LAST, now);

                        long otherIps = s.sessions().getUserSessionsStream(realm, user)
                                .map(us -> us.getIpAddress())
                                .filter(a -> a != null && ip != null && !a.equals(ip))
                                .distinct().count();
                        if (otherIps > 0) {
                            LOG.warnf("STIG-CONCURRENT-LOGON realm=%s user=%s userId=%s ip=%s otherSessionIps=%d",
                                    realm.getName(), user.getUsername(), userId, ip, otherIps);
                        }
                    });
                  } catch (RuntimeException e) {
                    // Audit bookkeeping must never break authentication.
                    LOG.errorf(e, "STIG-AUDIT last-login update failed for user %s", userId);
                  }
                }
                @Override protected void rollbackImpl() { }
            });
        }

        /** Any administrative UPDATE of an account withdraws its inactivity marker: an administrator who touched it -
         *  above all one who disabled it on purpose - must never see stig-accounts' reactivate undo that. */
        private void clearInactivityMarker(AdminEvent event) {
            String path = event.getResourcePath();
            if (path == null || !path.startsWith("users/") || path.indexOf('/', 6) >= 0) return;
            final String realmId = event.getRealmId(), userId = path.substring(6);
            session.getTransactionManager().enlistAfterCompletion(new org.keycloak.models.AbstractKeycloakTransaction() {
                @Override protected void commitImpl() {
                    try {
                        KeycloakModelUtils.runJobInTransaction(factory, s -> {
                            RealmModel realm = s.realms().getRealm(realmId);
                            if (realm == null) return;
                            s.getContext().setRealm(realm);
                            UserModel user = s.users().getUserById(realm, userId);
                            if (user != null && user.getFirstAttribute(StigAccountsResourceProviderFactory.DISABLED_MARKER) != null) {
                                user.removeAttribute(StigAccountsResourceProviderFactory.DISABLED_MARKER);
                                LOG.infof("STIG-INACTIVITY-MARKER-CLEARED realm=%s user=%s: changed by an administrator", realm.getName(), user.getUsername());
                            }
                        });
                    } catch (RuntimeException e) {
                        LOG.errorf(e, "STIG-AUDIT inactivity marker clearing failed for user %s", userId);
                    }
                }
                @Override protected void rollbackImpl() { }
            });
        }

        /**
         * Keycloak's LOGIN_ERROR for a failed passkey assertion names no user (userId null, no username): only
         * web_authn_authentication_error. The request still holds what the browser posted - the userHandle (the user id
         * a discoverable credential carries) and the credentialId - so name the account it targeted, and say whether the
         * posted credential is really one of that account's passkeys or only claims to be. Read-only; a log record only.
         * Without a user handle the record names no user: finding an account by credential id alone would mean
         * scanning every account's credentials, a cost anyone on the network could trigger.
         */
        private void attributePasskeyFailure(Event event) {
            java.util.Map<String, String> d = event.getDetails();
            String err = d == null ? null : d.get("web_authn_authentication_error");
            if (err == null) return;
            jakarta.ws.rs.core.MultivaluedMap<String, String> form = session.getContext().getHttpRequest() == null ? null
                    : session.getContext().getHttpRequest().getDecodedFormParameters();
            String handle = form == null ? null : form.getFirst("userHandle");
            String credId = form == null ? null : form.getFirst("credentialId");
            RealmModel realm = session.realms().getRealm(event.getRealmId());
            String uid = PasskeyAttribution.userIdFromHandle(handle);
            UserModel user = realm == null || uid == null ? null : session.users().getUserById(realm, uid);
            boolean owned = false;
            if (user != null && credId != null) {
                owned = user.credentialManager().getStoredCredentialsByTypeStream(org.keycloak.models.credential.WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                        .anyMatch(c -> {
                            try {
                                String stored = org.keycloak.util.JsonSerialization.readValue(c.getCredentialData(), java.util.Map.class)
                                        .getOrDefault("credentialId", "").toString();
                                return PasskeyAttribution.sameCredentialId(credId, stored);
                            } catch (java.io.IOException e) {
                                return false;
                            }
                        });
            }
            LOG.warnf("STIG-PASSKEY-FAILURE realm=%s user=%s userId=%s credential=%s error=%s ip=%s client=%s",
                    realm == null ? event.getRealmId() : realm.getName(), user == null ? "-" : user.getUsername(),
                    user == null ? "-" : user.getId(),
                    user == null ? "unknown(" + PasskeyAttribution.safe(credId) + ")" : (owned ? "this-account" : "not-this-account"),
                    PasskeyAttribution.safe(err, 64), event.getIpAddress(), event.getClientId());
        }

        @Override
        public void onEvent(AdminEvent event, boolean includeRepresentation) {
            if (event.getResourceType() != ResourceType.USER) return;
            OperationType op = event.getOperationType();
            if (op == OperationType.UPDATE) clearInactivityMarker(event);
            String rep = event.getRepresentation();
            String action;
            if (op == OperationType.CREATE) action = "CREATED";
            else if (op == OperationType.DELETE) action = "REMOVED";
            else if (op == OperationType.UPDATE && rep != null && rep.contains("\"enabled\":false")) action = "DISABLED_OR_MODIFIED";
            else if (op == OperationType.UPDATE && rep != null && rep.contains("\"enabled\":true")) action = "ENABLED_OR_MODIFIED";
            else action = "MODIFIED";

            String actor = event.getAuthDetails() != null ? event.getAuthDetails().getUserId() : "unknown";
            String actorIp = event.getAuthDetails() != null ? event.getAuthDetails().getIpAddress() : "unknown";
            String msg = String.format("STIG-ACCOUNT-EVENT action=%s op=%s realmId=%s resource=%s actorUserId=%s actorIp=%s time=%s",
                    action, op, event.getRealmId(), event.getResourcePath(), actor, actorIp,
                    Instant.ofEpochMilli(event.getTime()));
            LOG.warn(msg);

            if (!notifyEmails.isEmpty()) {
                RealmModel realm = session.realms().getRealm(event.getRealmId());
                if (realm == null || realm.getSmtpConfig() == null || realm.getSmtpConfig().isEmpty()) return;
                EmailSenderProvider sender = session.getProvider(EmailSenderProvider.class);
                for (String to : notifyEmails) {
                    try {
                        sender.send(realm.getSmtpConfig(), to, "[STIG] Account " + action + " in realm " + realm.getName(), msg, null);
                    } catch (EmailException e) {
                        LOG.errorf("STIG-ACCOUNT-EVENT notification to %s failed: %s", to, e.getMessage());
                    }
                }
            }
        }

        @Override public void close() { }
    }
}
