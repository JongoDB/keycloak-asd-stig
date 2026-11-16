package mil.stig.keycloak;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.common.util.Time;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

/**
 * The local-CRL revocation check of the card login (ASD STIG V-222551 path validation with status information,
 * V-222553 local cache of revocation data), scoped to the certificate's issuing CA.
 *
 * <p>Why it exists: Keycloak 26.8.2 caches the parsed CRLs (CrlStorageProvider), but
 * {@code CertificateValidator.checkRevocationStatusUsingCRL} then calls {@code CRLUtils.check} for EVERY configured CRL
 * on EVERY sign-in, and {@code CRLUtils.check} re-verifies each CRL's signature. Under BC-FIPS that means re-encoding
 * and hashing the whole CRL: with the 17 DoD ID/DERILITY CRLs (~140 MB) about 5.5 s per sign-in on a 2.6 GHz Xeon,
 * although only the issuing CA's CRL can ever list the certificate.
 *
 * <p>What it keeps from Keycloak, unchanged: the same {@code crl-relative-path} files under the configuration
 * directory; the CRL signer is the certificate in the presented chain named as the CRL issuer, else the truststore's
 * (the {@code CRLUtils.check} order); {@code crl-abort-if-non-updated}; {@code X509CRL.isRevoked}; any unreadable
 * configured CRL refuses the sign-in.
 *
 * <p>What it changes: only CRLs whose issuer is the certificate's issuer are consulted; a CRL's signature is verified
 * once per file version (file key, size, modification time) and signer key instead of once per sign-in, so a CRL
 * refreshed on disk is re-read and re-verified on the next sign-in; and a certificate whose issuer has NO CRL in the
 * list is refused (Keycloak lets it through with no CRL evidence at all).
 */
final class IssuerCrlCheck {
    private static final Logger log = Logger.getLogger(IssuerCrlCheck.class);

    /** CRL signature verifications performed (tests use it to prove the cache works). */
    static final AtomicLong VERIFICATIONS = new AtomicLong();

    private static final Map<Path, Loaded> CACHE = new ConcurrentHashMap<>();

    private IssuerCrlCheck() {}

    /** Where a CRL's signer is looked up when the presented chain does not carry it. */
    interface Signers {
        List<X509Certificate> named(X500Principal subject) throws GeneralSecurityException;
    }

    /** One CRL file as last read: its version on disk, the parsed CRL, and the signer keys it has verified against. */
    private static final class Loaded {
        final Object fileKey; final long size; final FileTime mtime;
        final X509CRL crl; final X500Principal issuer;
        final Set<ByteBuffer> verifiedKeys = ConcurrentHashMap.newKeySet();
        Loaded(BasicFileAttributes a, X509CRL crl) {
            this.fileKey = a.fileKey(); this.size = a.size(); this.mtime = a.lastModifiedTime();
            this.crl = crl; this.issuer = crl.getIssuerX500Principal();
        }
        boolean same(BasicFileAttributes a) {
            return Objects.equals(fileKey, a.fileKey()) && size == a.size() && mtime.equals(a.lastModifiedTime());
        }
    }

    /**
     * True when this check replaces Keycloak's local-CRL step: CRL checking on, CRL distribution points off, and every
     * configured CRL is a local file. Anything else (http/ldap CRLs, CRL DP) stays with Keycloak, unchanged.
     */
    static boolean handles(X509AuthenticatorConfigModel config) {
        if (!config.getCRLEnabled() || config.getCRLDistributionPointEnabled()) return false;
        String paths = config.getCRLRelativePath();
        if (paths == null || paths.isBlank()) return false;
        for (String p : Constants.CFG_DELIMITER_PATTERN.split(paths.trim())) {
            if (p.startsWith("http") || p.startsWith("ldap")) return false;
        }
        return true;
    }

    /** The authenticator's entry point: resolves the configured files the way Keycloak's CRLFileLoader does. */
    static void check(KeycloakSession session, X509Certificate[] certs, String crlRelativePaths, boolean abortIfNonUpdated)
            throws GeneralSecurityException {
        String configDir = System.getProperty("jboss.server.config.dir");
        if (configDir == null) throw new GeneralSecurityException("Unable to load CRL");
        Path configPath = Paths.get(configDir).toAbsolutePath().normalize();
        List<Path> files = new ArrayList<>();
        for (String rel : Constants.CFG_DELIMITER_PATTERN.split(crlRelativePaths.trim())) {
            Path p;
            try {
                p = Paths.get(configDir + File.separator + rel).toAbsolutePath().normalize();
            } catch (InvalidPathException e) {
                log.warnf("Cannot load CRL from \"%s\": %s", rel, e.getMessage());
                throw new GeneralSecurityException("Unable to load CRL");
            }
            if (!p.startsWith(configPath)) {
                log.warnf("Cannot load CRL from \"%s\" because it resolves outside of the configuration directory \"%s\"", rel, configPath);
                throw new GeneralSecurityException("Unable to load CRL");
            }
            files.add(p);
        }
        check(certs, files, truststore(session), abortIfNonUpdated, Time.currentTimeMillis());
    }

    private static Signers truststore(KeycloakSession session) {
        return subject -> {
            TruststoreProvider tp = session.getProvider(TruststoreProvider.class);
            if (tp == null || tp.getTruststore() == null) throw new GeneralSecurityException("Truststore not available");
            List<X509Certificate> found = tp.getIntermediateCertificates().get(subject);
            if (found == null) found = tp.getRootCertificates().get(subject);
            return found == null ? Collections.emptyList() : found;
        };
    }

    /** The check itself, free of Keycloak so it can be unit-tested. Throws to refuse the sign-in. */
    static void check(X509Certificate[] certs, List<Path> files, Signers truststore, boolean abortIfNonUpdated, long nowMillis)
            throws GeneralSecurityException {
        if (certs == null || certs.length < 1) throw new GeneralSecurityException("No certificate chain to check against the CRL");
        X509Certificate cert = certs[0];
        X500Principal issuer = cert.getIssuerX500Principal();
        List<Loaded> issuers = new ArrayList<>(1);
        for (Path f : files) {
            Loaded l = load(f);                       // every configured file must be readable, as in Keycloak
            if (l.issuer.equals(issuer)) issuers.add(l);
        }
        if (issuers.isEmpty()) {
            log.errorf("STIG-CRL-NO-ISSUER-CRL no configured CRL is issued by \"%s\": certificate \"%s\" refused (add that CA's CRL)",
                    issuer.getName(), cert.getSubjectX500Principal().getName());
            throw new GeneralSecurityException("No CRL available for the certificate's issuer");
        }
        for (Loaded l : issuers) {
            verifySignature(certs, l, truststore);
            Date next = l.crl.getNextUpdate();
            if (next != null && next.compareTo(new Date(nowMillis)) < 0) {
                log.warnf("CRL of \"%s\" is not refreshed. Next update is %s.", l.issuer.getName(), next);
                if (abortIfNonUpdated) throw new GeneralSecurityException("CRL is not refreshed");
            }
            if (l.crl.isRevoked(cert)) {
                log.debugf("Certificate has been revoked, certificate's subject: %s", cert.getSubjectX500Principal().getName());
                throw new GeneralSecurityException("Certificate has been revoked, certificate's subject: " + cert.getSubjectX500Principal().getName());
            }
        }
    }

    private static Loaded load(Path f) throws GeneralSecurityException {
        BasicFileAttributes a;
        try {
            a = Files.readAttributes(f, BasicFileAttributes.class);
        } catch (IOException e) {
            log.errorf("Unable to load CRL from \"%s\": %s", f, e.getMessage());
            throw new GeneralSecurityException("Unable to load CRL");
        }
        if (!a.isRegularFile()) {
            log.errorf("Unable to load CRL from \"%s\": not a file", f);
            throw new GeneralSecurityException("Unable to load CRL");
        }
        Loaded cur = CACHE.get(f);
        if (cur != null && cur.same(a)) return cur;
        synchronized (IssuerCrlCheck.class) {     // one reader per refresh, not one per concurrent sign-in
            cur = CACHE.get(f);
            if (cur != null && cur.same(a)) return cur;
            X509CRL crl;
            try (InputStream in = new BufferedInputStream(Files.newInputStream(f))) {
                crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                log.errorf("Unable to load CRL from \"%s\": %s", f, e.getMessage());
                throw new GeneralSecurityException("Unable to load CRL");
            }
            if (crl == null) {
                log.errorf("Unable to load CRL from \"%s\"", f);
                throw new GeneralSecurityException("Unable to load CRL");
            }
            Loaded l = new Loaded(a, crl);   // a file swapped between stat and read is re-read on the next sign-in
            CACHE.put(f, l);
            log.debugf("CRL \"%s\" loaded: issuer \"%s\", next update %s", f, l.issuer.getName(), crl.getNextUpdate());
            return l;
        }
    }

    /** CRLUtils.check's signer rule: the chain certificate named as the CRL issuer, else the truststore's certificates. */
    private static void verifySignature(X509Certificate[] certs, Loaded l, Signers truststore) throws GeneralSecurityException {
        for (X509Certificate c : certs) {
            if (l.issuer.equals(c.getSubjectX500Principal())) {
                verifyOnce(l, c);                     // as in Keycloak, a failure here refuses the sign-in
                return;
            }
        }
        List<X509Certificate> candidates = truststore.named(l.issuer);
        for (X509Certificate c : candidates) {
            try {
                verifyOnce(l, c);
                return;
            } catch (InvalidKeyException | SignatureException e) {
                // another certificate of that name (re-keyed CA) may have signed it
            }
        }
        throw new GeneralSecurityException("Not available certificate for CRL issuer '" + l.issuer + "' in the truststore, nor in the CA chain");
    }

    private static void verifyOnce(Loaded l, X509Certificate signer) throws GeneralSecurityException {
        ByteBuffer key = ByteBuffer.wrap(signer.getPublicKey().getEncoded());
        if (l.verifiedKeys.contains(key)) return;
        synchronized (l) {                            // a large CRL is verified by one sign-in, the others wait for it
            if (l.verifiedKeys.contains(key)) return;
            VERIFICATIONS.incrementAndGet();
            l.crl.verify(signer.getPublicKey());
            l.verifiedKeys.add(key);
        }
    }

    /** Tests only. */
    static void clearForTests() {
        CACHE.clear();
    }
}
