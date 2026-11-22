/*
 * Derived from Keycloak 26.8.2 org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator
 * Copyright Red Hat, Inc. and/or its affiliates and other contributors, Apache License 2.0
 * (http://www.apache.org/licenses/LICENSE-2.0). Changed: the brute-force (password lockout) check is removed, and the local
 * CRL step checks only the issuing CA's CRL, whose signature is verified once per file version (IssuerCrlCheck); the chain
 * validation is a method of its own, also used by PresentCardRequiredAction; no full EDIPI reaches a log line, the login
 * event (subject DN, username) or the attempted username.
 */
package mil.stig.keycloak;

import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import org.jboss.logging.Logger;


/**
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 *
 */
/** The X.509 browser authenticator of Keycloak 26.8.2, unchanged except that password lockout does not apply and the local
 *  CRL check is scoped to the issuing CA (IssuerCrlCheck). */
public class StigX509ClientCertificateAuthenticator extends AbstractX509ClientCertificateAuthenticator {

    private final static Logger logger = Logger.getLogger(StigX509ClientCertificateAuthenticator.class);

    public StigX509ClientCertificateAuthenticator(boolean legacyCriticalBehavior) {
        super(legacyCriticalBehavior);
    }

    @Override
    public void close() {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        try {

            dumpContainerAttributes(context);

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // STIG: with a card port, no certificate on THIS connection does not mean no card: the browser asks for
                // one only in a TLS handshake, and it reuses a connection made without it. Offer "Sign in with my CAC"
                // on the card port (a new handshake there; same cookies, so the same sign-in) next to the other methods.
                if (PresentCardRequiredAction.CARD_PORT > 0) {
                    context.forceChallenge(cardSignInPage(context));
                    return;
                }
                // No x509 client cert, fall through and
                // continue processing the rest of the authentication flow
                logger.debug("[authenticate] x509 client certificate is not available for mutual SSL.");
                context.attempted();
                return;
            }

            saveX509CertificateAuditDataToAuthSession(context, certs[0]);
            String dn0 = context.getAuthenticationSession().getAuthNote(Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME);
            if (dn0 != null) context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME, AccountsPolicy.redactEdipis(dn0));
            recordX509CertificateAuditDataViaContextEvent(context); redactSubject(context);

            X509AuthenticatorConfigModel config = null;
            if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig() != null) {
                config = new X509AuthenticatorConfigModel(context.getAuthenticatorConfig());
            }
            if (config == null) {
                logger.warn("[authenticate] x509 Client Certificate Authentication configuration is not available.");
                context.challenge(createInfoResponse(context, "X509 client authentication has not been configured yet"));
                context.attempted();
                return;
            }
            if (config.getCASubjectDN().isEmpty()) {
                logger.warnf("[authenticate] Option '%s' is empty, this configuration is deprecated, please configure it for the authenticator in realm '%s'",
                        CERTIFICATE_CA_SUBJECT_DN, context.getRealm().getName());
            }

            // Validate X509 client certificate
            try {
                validate(context.getSession(), config, certs);
            } catch(Exception e) {
                // STIG: a fixed reason and the subject with any EDIPI masked - never the raw message (it may carry the DN)
                logger.errorf("STIG-CARD-REFUSED reason=certificate not valid (%s: %s) subject=%s", e.getClass().getSimpleName(),
                        AccountsPolicy.redactEdipis(String.valueOf(e.getMessage())), AccountsPolicy.redactEdipis(certs[0].getSubjectX500Principal().getName()));
                // TODO use specific locale to load error messages
                String errorMessage = "Certificate validation's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Certificate revoked or incorrect."));
                context.attempted();
                return;
            }

            Object userIdentity = getUserIdentityExtractor(config).extractUserIdentity(certs);
            if (userIdentity == null) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                logger.warnf("[authenticate] Unable to extract user identity from certificate.");
                // TODO use specific locale to load error messages
                String errorMessage = "Unable to extract user identity from specified certificate";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }

            UserModel user;
            try {
                // STIG: never the card's identity (an EDIPI) in the event (the jboss-logging listener writes LOGIN_ERROR to the
                // log and the SIEM, and the event store keeps it) nor in the attempted username the login page may echo:
                // a masked, keyed label until an account is matched, then that account's username
                String label = CardLabel.of(context.getSession(), context.getRealm(), userIdentity.toString());
                context.getEvent().detail(Details.USERNAME, label);
                context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, label);
                user = getUserIdentityToModelMapper(config).find(context, userIdentity);
                if (user != null) context.getEvent().detail(Details.USERNAME, user.getUsername());
            }
            catch(ModelDuplicateException e) {
                logger.errorf("STIG-CARD-REFUSED reason=more than one account holds this card (%s)", CardLabel.of(context.getSession(), context.getRealm(), userIdentity.toString()));
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            if (invalidUser(context, user)) {
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Invalid user"));
                context.attempted();
                return;
            }

            // STIG: NOT refused for password-failure lockout. A card cannot be guessed (AC-7 is about guessing), and
            // three bad passwords typed by anyone on the internet must not lock a card holder out - least of all the
            // sole administrator. Revocation, trust, validity and the mapping are all still checked above.
            if (StigAdministrators.unvettedAdministrator(context.getSession(), context.getRealm(), user)) {
                logger.errorf("STIG-ADMIN-NOT-ALLOWLISTED realm=%s user=%s path=card: holds administrator rights it is not vetted for (not on the allowlist, or beyond its entry)",
                        context.getRealm().getName(), user.getUsername());
                context.getEvent().user(user);
                context.getEvent().error(Errors.ACCESS_DENIED);
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        "X509 certificate authentication's failed.", "Invalid user"));
                context.attempted();
                return;
            }

            if (!userEnabled(context, user)) {
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "User is disabled"));
                context.attempted();
                return;
            }
            context.setUser(user);

            // Check whether to display the identity confirmation
            if (!config.getConfirmationPageDisallowed()) {
                // Calling forceChallenge was the only way to display
                // a form to let users either choose the user identity from certificate
                // or to ignore it and proceed to a normal login screen. Attempting
                // to call the method "challenge" results in a wrong/unexpected behavior.
                context.forceChallenge(createSuccessResponse(context, certs[0].getSubjectDN().toString()));
                // Do not set the flow status yet, we want to display a form to let users
                // choose whether to accept the identity from certificate or to specify username/password explicitly
            }
            else {
                // Bypass the confirmation page and log the user in
                context.success(UserCredentialModel.CLIENT_CERT);
            }
        }
        catch(Exception e) {
            logger.errorf("[authenticate] %s: %s", e.getClass().getName(), AccountsPolicy.redactEdipis(String.valueOf(e.getMessage())));
            context.attempted();
        }
    }

    private Response createErrorResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         String errorMessage,
                                         String ... errorParameters) {

        return createResponse(context, subjectDN, false, errorMessage, errorParameters);
    }

    private Response createSuccessResponse(AuthenticationFlowContext context,
                                           String subjectDN) {
        return createResponse(context, subjectDN, true, null, null);
    }

    private Response createResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         boolean isUserEnabled,
                                         String errorMessage,
                                         Object[] errorParameters) {

        LoginFormsProvider form = context.form();
        if (errorMessage != null && errorMessage.trim().length() > 0) {
            List<FormMessage> errors = new LinkedList<>();

            errors.add(new FormMessage(errorMessage));
            if (errorParameters != null) {

                for (Object errorParameter : errorParameters) {
                    if (errorParameter == null) continue;
                    for (String part : errorParameter.toString().split("\n")) {
                        errors.add(new FormMessage(part));
                    }
                }
            }
            form.setErrors(errors);
        }

        MultivaluedMap<String,String> formData = new MultivaluedHashMap<>();
        formData.add("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user");
        formData.add("subjectDN", subjectDN);
        formData.add("isUserEnabled", String.valueOf(isUserEnabled));

        form.setFormData(formData);

        return form.createX509ConfirmPage();
    }

    private void dumpContainerAttributes(AuthenticationFlowContext context) {

        Map<String, Object> attributeNames = context.getSession().getAttributes();
        for (String name : attributeNames.keySet()) {
            logger.tracef("[dumpContainerAttributes] \"%s\"", name);
        }
    }

    private boolean userEnabled(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            return false;
        }
        return true;
    }

    private boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            return true;
        }
        return false;
    }

    /** The certificate's subject in the login event (Keycloak records it) with any EDIPI masked: the jboss-logging
     *  listener writes events to the log and the SIEM, and the event store keeps them. */
    private static void redactSubject(AuthenticationFlowContext context) {
        String dn = context.getAuthenticationSession().getAuthNote(Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME);
        if (dn != null) context.getEvent().detail(Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME, AccountsPolicy.redactEdipis(dn));
    }

    /** The card sign-in choice: "Sign in with my CAC" re-runs THIS step on the card port (its refresh URL there),
     *  "Use another sign-in method" posts "cancel" to this step on the page's own origin. On the card port itself (the
     *  person declined the prompt, or has no card) it says no certificate was presented. */
    private Response cardSignInPage(AuthenticationFlowContext context) {
        int port = PresentCardRequiredAction.CARD_PORT;
        java.net.URI refresh = PresentCardRequiredAction.onCardPort(context.getRefreshExecutionUrl(), port);
        List<Map<String, String>> params = new java.util.ArrayList<>();
        if (refresh.getRawQuery() != null) {
            for (String kv : refresh.getRawQuery().split("&")) {
                int i = kv.indexOf('=');
                String k = java.net.URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), java.nio.charset.StandardCharsets.UTF_8);
                String v = i < 0 ? "" : java.net.URLDecoder.decode(kv.substring(i + 1), java.nio.charset.StandardCharsets.UTF_8);
                params.add(Map.of("name", k, "value", v));
            }
        }
        String action = refresh.getScheme() + "://" + refresh.getRawAuthority() + refresh.getRawPath();
        boolean onCardPort = context.getUriInfo() != null && context.getUriInfo().getRequestUri().getPort() == port;
        LoginFormsProvider form = context.form()
                .setAttribute("cardSignIn", action).setAttribute("cardSignInParams", params)
                // another method only where there is one: this step is an ALTERNATIVE (a CAC-only realm has none)
                .setAttribute("cardOther", hasOtherMethod(context))
                .setAttribute("cardProbe", refresh.getScheme() + "://" + refresh.getRawAuthority() + "/realms/" + context.getRealm().getName()
                        + "/.well-known/openid-configuration");
        if (onCardPort) {
            logger.infof("STIG-CARD-SIGNIN-NO-CERT realm=%s port=%d: the card port was reached without a client certificate",
                    context.getRealm().getName(), port);
            form.setAttribute("cardError", "stigCardSignInNoCert");
        }
        return form.createForm("stig-card-signin.ftl");
    }

    /** This step is an ALTERNATIVE and its flow holds another enabled step to go on to (a CAC-only flow has none). */
    static boolean hasOtherMethod(AuthenticationFlowContext context) {
        org.keycloak.models.AuthenticationExecutionModel me = context.getExecution();
        if (me == null || me.getRequirement() != org.keycloak.models.AuthenticationExecutionModel.Requirement.ALTERNATIVE) return false;
        return context.getRealm().getAuthenticationExecutionsStream(me.getParentFlow())
                .anyMatch(e -> !e.getId().equals(me.getId())
                        && e.getRequirement() != org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED);
    }

    /** Every check a card sign-in makes on the chain (trust, CA subject, validity, key usage, policy, revocation). */
    void validate(org.keycloak.models.KeycloakSession session, X509AuthenticatorConfigModel config, X509Certificate[] certs) throws Exception {
                // STIG: with local CRL files, the CRL step is IssuerCrlCheck (the issuing CA's CRL, signature verified once
                // per file version) instead of Keycloak's (every configured CRL re-verified on every sign-in). Keycloak's
                // validator still runs every other check, OCSP included, on a copy of the configuration with CRL off.
                boolean issuerCrl = IssuerCrlCheck.handles(config);
                X509AuthenticatorConfigModel validatorConfig = config;
                if (issuerCrl) {
                    AuthenticatorConfigModel copy = new AuthenticatorConfigModel();
                    copy.setId(config.getId());
                    copy.setAlias(config.getAlias());
                    copy.setConfig(new HashMap<>(config.getConfig()));   // never mutate the realm's cached model
                    validatorConfig = new X509AuthenticatorConfigModel(copy).setCRLEnabled(false);
                }
                CertificateValidator.CertificateValidatorBuilder builder = certificateValidationParameters(session, validatorConfig);
                CertificateValidator validator = builder.build(certs);
                validator.validateTrust()
                         .validateCASubjectDN()
                         .validateTimestamps()
                         .validateKeyUsage(isLegacyCriticalBehavior())
                         .validateExtendedKeyUsage(isLegacyCriticalBehavior())
                         .validatePolicy();
                if (issuerCrl) {
                    IssuerCrlCheck.check(session, certs, config.getCRLRelativePath(), config.getCrlAbortIfNonUpdated());
                }
        validator.checkRevocationStatus();
    }

    /** For the present-card required action (PresentCardRequiredAction): the chain validated exactly as a card sign-in
     *  validates it, and the identity the realm's mapping extracts from it (e.g. the EDIPI); throws when not valid. */
    String validatedIdentity(org.keycloak.models.KeycloakSession session, AuthenticatorConfigModel cfg, X509Certificate[] certs) throws Exception {
        X509AuthenticatorConfigModel config = new X509AuthenticatorConfigModel(cfg);
        validate(session, config, certs);
        Object id = getUserIdentityExtractor(config).extractUserIdentity(certs);
        return id == null ? null : id.toString();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.clearUser();
            context.attempted();
            return;
        }
        if (context.getUser() != null) {
            recordX509CertificateAuditDataViaContextEvent(context); redactSubject(context);
            context.success(UserCredentialModel.CLIENT_CERT);
            return;
        }
        context.attempted();
    }
}
