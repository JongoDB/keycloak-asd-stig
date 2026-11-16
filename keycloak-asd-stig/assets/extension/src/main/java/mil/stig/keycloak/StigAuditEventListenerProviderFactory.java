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
