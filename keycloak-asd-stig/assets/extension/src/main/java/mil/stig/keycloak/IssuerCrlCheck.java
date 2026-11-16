package mil.stig.keycloak;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import javax.security.auth.x500.X500Principal;

import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.common.util.Time;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.truststore.TruststoreProvider;

/**
 * The local-CRL revocation check of the card login (ASD STIG V-222550 path validation with status information,
 * V-222553 local cache of revocation data), scoped to the certificates that matter.
 *
 * <p>Why it exists: Keycloak 26.8.2 caches the parsed CRLs, but {@code CertificateValidator.checkRevocationStatusUsingCRL}
 * runs {@code CRLUtils.check} for EVERY configured CRL on EVERY sign-in, and {@code CRLUtils.check} re-verifies each CRL's
 * signature. Under BC-FIPS that re-encodes and hashes the whole CRL: about 5.5 s per sign-in with the 17 DoD ID/DERILITY
 * CRLs (~140 MB) on a 2.6 GHz Xeon, although only the issuing CA's CRL can list the card.
 *
 * <p>What it checks, on every sign-in:
 * <ol>
 *   <li>the card against the CRL(s) of its issuing CA;</li>
 *   <li>every CA certificate on the path to a self-signed anchor, through the truststore: at each step the issuer is
 *       chosen by name and key, and EVERY truststore certificate carrying that CA key (re-issued or cross certificates)
 *       is checked against its own issuer's CRL. One revoked certificate refuses the login; a path that cannot be
 *       built refuses it too. Keycloak checks no intermediate at all.</li>
 * </ol>
 * A certificate whose issuer has no usable CRL is refused. CRL signatures are verified only against truststore
 * certificates, never against the client-supplied chain, and once per file version (file key, size, mtime, ctime)
 * and signer key. Verification happens on a throw-away parse, so the cached CRL stays lazily parsed (BC-FIPS expands a
 * CRL completely to verify it). CRLs that cannot be relied on are rejected: delta CRLs, a partitioned or indirect
 * issuingDistributionPoint, unsupported critical extensions, a thisUpdate in the future.
 *
 * <p>Availability: an unreadable or rejected CRL of ANOTHER issuer raises {@code STIG-CRL-UNREADABLE} and does not refuse
 * the sign-in; one of the card's own issuer (or of the issuing CA's root) refuses it. A background job
 * ({@link #startPrewarm}) re-reads and verifies changed files off the request path and evicts files no realm lists any
 * more. Locks are per file. A sign-in that finds a file changed waits for its re-read; only if that takes longer than
 * {@code stig.crl.reread.wait.ms} (default 2 s) does it use the previous verified version, and only while that version
 * is still before its nextUpdate.
 */
final class IssuerCrlCheck {
    private static final Logger log = Logger.getLogger(IssuerCrlCheck.class);

    /** CRL signature verifications performed, and checks run (tests use them to prove the cache and the wiring). */
    static final AtomicLong VERIFICATIONS = new AtomicLong();
    static final AtomicLong CHECKS = new AtomicLong();

    static final String IDP_OID = "2.5.29.28", DELTA_OID = "2.5.29.27";
    static final long CLOCK_SKEW_MS = 5 * 60_000L;

    private static final Map<Path, Loaded> CACHE = new ConcurrentHashMap<>();
    private static final Map<Path, ReentrantLock> LOCKS = new ConcurrentHashMap<>();
    private static final Map<Path, Long> ALARMED = new ConcurrentHashMap<>();

    private IssuerCrlCheck() {}

    /** Where CRL signers and issuing-CA certificates come from: the truststore, by subject. */
    interface Signers {
        List<X509Certificate> named(X500Principal subject) throws GeneralSecurityException;
        /** Every truststore certificate (to find all certificates of one CA key). */
        List<X509Certificate> all() throws GeneralSecurityException;
    }

    /** A file's identity on disk: replaced, rewritten or touched files all differ. */
    private record Version(Object fileKey, long size, FileTime mtime, Object ctime) {
        static Version of(Path f) throws IOException {
            BasicFileAttributes a;
            try {
                a = Files.readAttributes(f, BasicFileAttributes.class);
            } catch (java.nio.file.NoSuchFileException e) {
                throw e;                                       // not installed (yet): reported as STIG-CRL-MISSING
            } catch (IOException e) {
                return viaJavaIo(f, e);
            }
            if (!a.isRegularFile()) throw new IOException("not a regular file");
            Object ctime = null;
            try {
                ctime = Files.getAttribute(f, "unix:ctime");
            } catch (UnsupportedOperationException | IllegalArgumentException | IOException e) {
                // no usable unix view: fileKey, size and mtime still identify the version
                noteDegraded(f, e);
            }
            return new Version(a.fileKey(), a.size(), a.lastModifiedTime(), ctime);
        }

        /** NIO could not stat a file that java.io (what Keycloak's own CRL loader uses) may still read. */
        private static Version viaJavaIo(Path f, IOException nio) throws IOException {
            File file = f.toFile();
            if (!file.isFile()) throw nio;
            noteDegraded(f, nio);
            return new Version(null, file.length(), FileTime.fromMillis(file.lastModified()), null);
        }
    }

    private static volatile boolean degradedNoted;

    private static void noteDegraded(Path f, Exception e) {
        if (degradedNoted) return;
        degradedNoted = true;
        log.warnf("STIG-CRL-VERSION-DEGRADED file identity of \"%s\" uses size and mtime only (%s): an in-place rewrite that keeps both is not noticed",
                f, describe(e));
    }

    /** Exception class, message and cause chain, for log lines that must say WHY a CRL could not be used. */
    static String describe(Throwable e) {
        StringBuilder sb = new StringBuilder();
        for (Throwable t = e; t != null && sb.length() < 600; t = t.getCause()) {
            if (sb.length() > 0) sb.append(" <- caused by ");
            sb.append(t.getClass().getName());
            if (t.getMessage() != null) sb.append(": ").append(t.getMessage());
            if (t.getCause() == t) break;
        }
        return sb.toString();
    }

    /**
     * One CRL file as last read. {@code crl} is a lazy parse that is never verified (BC-FIPS expands a CRL completely to
     * verify it); the signature is checked on a separate parse of {@code der}, once, the first time the CRL is needed
     * (a sign-in of that issuer, or the pre-warm), after which {@code der} is dropped.
     */
    private static final class Loaded {
        final Version version; final X509CRL crl; final X500Principal issuer;
        final boolean onlyUserCerts, onlyCaCerts;
        final Set<ByteBuffer> verifiedKeys = ConcurrentHashMap.newKeySet();
        volatile byte[] der;
        Loaded(Version v, X509CRL crl, boolean onlyUser, boolean onlyCa, byte[] der) {
            this.version = v; this.crl = crl; this.issuer = crl.getIssuerX500Principal();
            this.onlyUserCerts = onlyUser; this.onlyCaCerts = onlyCa; this.der = der;
        }
        boolean verified() { return !verifiedKeys.isEmpty(); }
        boolean verifiedBy(Signers s) throws GeneralSecurityException {
            for (X509Certificate c : s.named(issuer)) if (verifiedKeys.contains(key(c.getPublicKey()))) return true;
            return false;
        }
    }

    /** A configured file that could not be used, and the issuer it belongs to when known. */
    private record Failure(Path path, X500Principal issuer, String reason) {}

    // ------------------------------------------------------------------ configuration and entry points

    /**
     * True when this check replaces Keycloak's local-CRL step: CRL checking on, CRL distribution points off, and every
     * configured CRL is a local file. Anything else (http/ldap CRLs, CRL DP) stays with Keycloak, unchanged.
     */
    static boolean handles(X509AuthenticatorConfigModel config) {
        if (!config.getCRLEnabled() || config.getCRLDistributionPointEnabled()) return false;
        return localPaths(config.getCRLRelativePath()) != null;
    }

    private static List<String> localPaths(String paths) {
        if (paths == null || paths.isBlank()) return null;
        List<String> out = new ArrayList<>();
        for (String p : Constants.CFG_DELIMITER_PATTERN.split(paths.trim())) {
            if (p.startsWith("http") || p.startsWith("ldap")) return null;
            if (!p.isBlank()) out.add(p);
        }
        return out.isEmpty() ? null : out;
    }

    /** Resolves configured relative paths the way Keycloak's CRLFileLoader does; a path outside conf is dropped (alarm). */
    static List<Path> resolve(Collection<String> rels) {
        String configDir = System.getProperty("jboss.server.config.dir");
        if (configDir == null) return List.of();
        Path configPath = Paths.get(configDir).toAbsolutePath().normalize();
        List<Path> files = new ArrayList<>();
        for (String rel : rels) {
            try {
                Path p = Paths.get(configDir + File.separator + rel).toAbsolutePath().normalize();
                if (p.startsWith(configPath)) {
                    files.add(p);
                    continue;
                }
                log.errorf("STIG-CRL-UNREADABLE \"%s\" resolves outside of the configuration directory \"%s\": ignored", rel, configPath);
            } catch (InvalidPathException e) {
                log.errorf("STIG-CRL-UNREADABLE \"%s\": %s", rel, e.getMessage());
            }
        }
        return files;
    }

    /** The authenticator's entry point. */
    static void check(KeycloakSession session, X509Certificate[] certs, String crlRelativePaths, boolean abortIfNonUpdated)
            throws GeneralSecurityException {
        List<String> rels = localPaths(crlRelativePaths);
        List<Path> files = rels == null ? List.of() : resolve(rels);
        check(certs, files, truststore(session), abortIfNonUpdated, Time.currentTimeMillis());
    }

    static Signers truststore(KeycloakSession session) {
        return new Signers() {
            private TruststoreProvider tp() throws GeneralSecurityException {
                TruststoreProvider tp = session.getProvider(TruststoreProvider.class);
                if (tp == null || tp.getTruststore() == null) throw new GeneralSecurityException("Truststore not available");
                return tp;
            }
            @Override public List<X509Certificate> named(X500Principal subject) throws GeneralSecurityException {
                TruststoreProvider tp = tp();
                List<X509Certificate> found = new ArrayList<>();
                List<X509Certificate> i = tp.getIntermediateCertificates().get(subject);
                List<X509Certificate> r = tp.getRootCertificates().get(subject);
                if (i != null) found.addAll(i);
                if (r != null) found.addAll(r);
                return found;
            }
            @Override public List<X509Certificate> all() throws GeneralSecurityException {
                TruststoreProvider tp = tp();
                List<X509Certificate> found = new ArrayList<>();
                tp.getIntermediateCertificates().values().forEach(found::addAll);
                tp.getRootCertificates().values().forEach(found::addAll);
                return found;
            }
        };
    }

    // ------------------------------------------------------------------ the check

    /** The check itself, free of Keycloak so it can be unit-tested. Throws to refuse the sign-in. */
    static void check(X509Certificate[] certs, List<Path> files, Signers truststore, boolean abortIfNonUpdated, long nowMillis)
            throws GeneralSecurityException {
        CHECKS.incrementAndGet();
        if (certs == null || certs.length < 1) throw new GeneralSecurityException("No certificate chain to check against the CRL");
        List<Loaded> loaded = new ArrayList<>(files.size());
        List<Failure> failed = new ArrayList<>();
        for (Path f : files) {
            try {
                loaded.add(load(f, false, nowMillis));
            } catch (GeneralSecurityException | IOException e) {
                Loaded previous = CACHE.get(f);
                X500Principal iss = e instanceof RejectedCrl rc ? rc.issuer : previous == null ? null : previous.issuer;
                failed.add(new Failure(f, iss, describe(e)));
                alarm(f, iss, e);
            }
        }
        X509Certificate leaf = certs[0];
        evaluate(leaf, false, loaded, failed, truststore, abortIfNonUpdated, nowMillis);
        checkPath(leaf, loaded, failed, truststore, abortIfNonUpdated, nowMillis);
    }

    static final int MAX_PATH = 8;

    /**
     * Walks from {@code leaf} to a self-signed anchor through the truststore. At each step the issuer is chosen by name
     * AND key (its key verifies the certificate). Every truststore certificate carrying that CA key is a certificate of
     * the same CA: each one that is not self-signed is checked against its own issuer's CRL (a revoked one refuses the
     * login) and walked further in turn. Fails closed when a step cannot be resolved or the path is too long.
     */
    private static void checkPath(X509Certificate leaf, List<Loaded> loaded, List<Failure> failed, Signers truststore,
                                  boolean abortIfNonUpdated, long now) throws GeneralSecurityException {
        List<X509Certificate> all = truststore.all();
        java.util.ArrayDeque<X509Certificate> todo = new java.util.ArrayDeque<>();
        Set<ByteBuffer> seenKeys = new HashSet<>();
        todo.add(leaf);
        int steps = 0;
        while (!todo.isEmpty()) {
            X509Certificate cert = todo.poll();
            if (++steps > MAX_PATH * 4) throw new GeneralSecurityException("Certification path too long");
            PublicKey issuerKey = null;
            for (X509Certificate c : truststore.named(cert.getIssuerX500Principal())) {
                try {
                    cert.verify(c.getPublicKey());
                    issuerKey = c.getPublicKey();
                    break;
                } catch (InvalidKeyException | SignatureException e) {
                    // another CA certificate of that name (re-keyed CA)
                }
            }
            if (issuerKey == null) {
                log.errorf("STIG-CRL-NO-PATH no truststore certificate named \"%s\" verifies \"%s\": certification path cannot be built",
                        cert.getIssuerX500Principal().getName(), cert.getSubjectX500Principal().getName());
                throw new GeneralSecurityException("Certification path cannot be built through the truststore");
            }
            if (!seenKeys.add(key(issuerKey))) continue;            // that CA was handled already (or a loop)
            if (seenKeys.size() > MAX_PATH) throw new GeneralSecurityException("Certification path too long");
            ByteBuffer k = key(issuerKey);
            for (X509Certificate ca : all) {
                if (!key(ca.getPublicKey()).equals(k)) continue;
                if (ca.getSubjectX500Principal().equals(ca.getIssuerX500Principal())) continue;   // the anchor itself
                evaluate(ca, true, loaded, failed, truststore, abortIfNonUpdated, now);         // its status at its issuer
                todo.add(ca);                                                                    // and that issuer's
            }
        }
    }

    private static void evaluate(X509Certificate cert, boolean isCa, List<Loaded> loaded, List<Failure> failed, Signers truststore,
                                 boolean abortIfNonUpdated, long now) throws GeneralSecurityException {
        X500Principal issuer = cert.getIssuerX500Principal();
        String what = isCa ? "issuing CA certificate" : "certificate";
        for (Failure f : failed) {
            if (issuer.equals(f.issuer)) {
                log.errorf("STIG-CRL-UNREADABLE the CRL of \"%s\" (%s) cannot be used: %s refused", issuer.getName(), f.path, what);
                throw new GeneralSecurityException("CRL of the certificate's issuer is not usable");
            }
        }
        List<Loaded> mine = new ArrayList<>(1);
        for (Loaded l : loaded) if (l.issuer.equals(issuer)) mine.add(l);
        if (mine.isEmpty()) {
            log.errorf("STIG-CRL-NO-ISSUER-CRL no usable CRL is issued by \"%s\": %s \"%s\" refused (add that CA's CRL)",
                    issuer.getName(), what, cert.getSubjectX500Principal().getName());
            throw new GeneralSecurityException("No CRL available for the certificate's issuer");
        }
        for (Loaded l : mine) {
            try {
                ensureVerified(l, truststore);
            } catch (GeneralSecurityException e) {
                alarm(findPath(l), issuer, e);
                throw new GeneralSecurityException("CRL of the certificate's issuer is not usable");
            }
            if (l.crl.getThisUpdate() != null && l.crl.getThisUpdate().getTime() > now + CLOCK_SKEW_MS) {
                log.errorf("STIG-CRL-REJECTED CRL of \"%s\" has thisUpdate %s in the future", issuer.getName(), l.crl.getThisUpdate());
                throw new GeneralSecurityException("CRL is not yet valid");
            }
            if ((isCa && l.onlyUserCerts) || (!isCa && l.onlyCaCerts)) {
                log.errorf("STIG-CRL-REJECTED CRL of \"%s\" does not cover %s certificates (issuingDistributionPoint)", issuer.getName(), isCa ? "CA" : "end-entity");
                throw new GeneralSecurityException("CRL scope does not cover the certificate");
            }
            Date next = l.crl.getNextUpdate();
            if (next != null && next.getTime() < now) {
                log.warnf("CRL of \"%s\" is not refreshed. Next update is %s.", issuer.getName(), next);
                if (abortIfNonUpdated) throw new GeneralSecurityException("CRL is not refreshed");
            }
            if (l.crl.isRevoked(cert)) {
                log.debugf("Certificate has been revoked, certificate's subject: %s", cert.getSubjectX500Principal().getName());
                throw new GeneralSecurityException("Certificate has been revoked, certificate's subject: " + cert.getSubjectX500Principal().getName());
            }
        }
    }

    private static void alarm(Path f, X500Principal issuer, Exception e) {
        long now = System.currentTimeMillis();
        Long last = ALARMED.get(f);
        if (last != null && now - last < 60_000L) return;             // once a minute per file, not once per sign-in
        ALARMED.put(f, now);
        String who = issuer == null ? "" : " (issuer \"" + issuer.getName() + "\")";
        if (e instanceof java.nio.file.NoSuchFileException) {
            // expected right after a start in online mode: Keycloak (and the realm's CRL list) is up before crl-fetch
            // has downloaded the files into the fresh data directory. That CA's cards fail closed until it arrives.
            log.warnf("STIG-CRL-MISSING \"%s\"%s is not installed (yet): cards of that CA are refused until it is; other cards are not affected.",
                    f, who);
            return;
        }
        log.errorf("STIG-CRL-UNREADABLE \"%s\"%s: %s. Cards of that CA are refused until it is fixed; other cards are not affected.",
                f, who, describe(e));
    }

    // ------------------------------------------------------------------ loading

    /** A CRL that parsed but must not be used; its issuer is known. */
    static final class RejectedCrl extends GeneralSecurityException {
        final X500Principal issuer;
        RejectedCrl(X500Principal issuer, String msg) { super(msg); this.issuer = issuer; }
    }

    /**
     * The CRL of file {@code f} as currently on disk (parsed, not necessarily verified yet). {@code wait=false} (a
     * sign-in): when another thread is re-reading the file and a previous verified version exists, that version is
     * returned instead of waiting, and the pre-warm is woken to finish the refresh.
     */
    private static Loaded load(Path f, boolean wait, long now) throws GeneralSecurityException, IOException {
        Version v = Version.of(f);
        Loaded cur = CACHE.get(f);
        if (cur != null && cur.version.equals(v)) return cur;
        ReentrantLock lock = LOCKS.computeIfAbsent(f, k -> new ReentrantLock());
        boolean locked;
        try {
            // the file changed: wait for the re-read (another sign-in or the pre-warm may be doing it) ...
            locked = wait ? lockNow(lock) : lock.tryLock(REREAD_WAIT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GeneralSecurityException("Interrupted while a CRL was being re-read");
        }
        if (!locked) {
            // ... and only past a short timeout fall back to the previous verified version, if still before its nextUpdate
            Date next = cur == null ? null : cur.crl.getNextUpdate();
            if (cur != null && cur.verified() && next != null && next.getTime() > now) {
                log.warnf("CRL \"%s\" is still being re-read after %d ms: this sign-in uses the previous version (next update %s)", f, REREAD_WAIT_MS, next);
                return cur;
            }
            lock.lock();
        }
        try {
            cur = CACHE.get(f);
            if (cur != null && cur.version.equals(v)) return cur;
            Loaded l = read(f, v);
            CACHE.put(f, l);
            ALARMED.remove(f);
            if (!wait) wake();                                   // let the pre-warm verify the rest off the request path
            return l;
        } finally {
            lock.unlock();
        }
    }

    /** How long a sign-in waits for a CRL being re-read before it may use the previous version ({@code stig.crl.reread.wait.ms}). */
    static volatile long REREAD_WAIT_MS = Long.getLong("stig.crl.reread.wait.ms", 2000L);

    private static boolean lockNow(ReentrantLock lock) {
        lock.lock();
        return true;
    }

    /** Tests only: the lock a re-read of {@code f} holds. */
    static ReentrantLock lockForTests(Path f) {
        return LOCKS.computeIfAbsent(f, k -> new ReentrantLock());
    }

    private static Loaded read(Path f, Version v) throws GeneralSecurityException, IOException {
        byte[] der;
        try (java.io.InputStream in = new java.io.FileInputStream(f.toFile())) {   // java.io, as Keycloak's CRL loader
            der = in.readAllBytes();
        }
        X509CRL crl;
        try {
            crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
        } catch (RuntimeException e) {
            throw new GeneralSecurityException("not a CRL: " + e.getMessage());
        }
        if (crl == null) throw new GeneralSecurityException("not a CRL");
        X500Principal issuer = crl.getIssuerX500Principal();
        boolean[] scope = structure(crl, issuer);
        log.debugf("CRL \"%s\" read: issuer \"%s\", next update %s", f, issuer.getName(), crl.getNextUpdate());
        return new Loaded(v, crl, scope[0], scope[1], der);
    }

    /** Verifies the CRL's signature against the truststore certificates of its issuer (never the client's chain), once. */
    private static void ensureVerified(Loaded l, Signers signers) throws GeneralSecurityException {
        if (l.verifiedBy(signers)) return;
        synchronized (l) {                                     // one verification per CRL version, concurrent sign-ins wait
            if (l.verifiedBy(signers)) return;
            byte[] der = l.der;
            if (der == null) {                                 // verified before, but the truststore changed since
                CACHE.values().remove(l);
                throw new GeneralSecurityException("CRL signer changed; the CRL is re-read on the next sign-in");
            }
            X509CRL probe = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
            List<X509Certificate> candidates = signers.named(l.issuer);
            for (X509Certificate c : candidates) {
                try {
                    VERIFICATIONS.incrementAndGet();
                    probe.verify(c.getPublicKey());
                    l.verifiedKeys.add(key(c.getPublicKey()));
                    l.der = null;                              // the probe (fully expanded) and the bytes go to GC
                    return;
                } catch (InvalidKeyException | SignatureException e) {
                    // another certificate of that name (re-keyed CA) may have signed it
                }
            }
            throw new RejectedCrl(l.issuer, candidates.isEmpty()
                    ? "no truststore certificate for CRL issuer '" + l.issuer + "'"
                    : "CRL signature does not verify against the truststore certificate(s) of '" + l.issuer + "'");
        }
    }

    private static Path findPath(Loaded l) {
        for (Map.Entry<Path, Loaded> e : CACHE.entrySet()) if (e.getValue() == l) return e.getKey();
        return Paths.get("?");
    }

    /**
     * Refuses CRLs this check cannot interpret correctly. Returns {onlyContainsUserCerts, onlyContainsCACerts}.
     * Entry-level certificateIssuer only occurs in indirect CRLs, which are refused here.
     */
    static boolean[] structure(X509CRL crl, X500Principal issuer) throws RejectedCrl {
        if (crl.getExtensionValue(DELTA_OID) != null) throw new RejectedCrl(issuer, "delta CRL (deltaCRLIndicator) is not supported");
        Set<String> critical = crl.getCriticalExtensionOIDs();
        if (critical != null) {
            for (String oid : critical) {
                if (!IDP_OID.equals(oid)) throw new RejectedCrl(issuer, "unsupported critical CRL extension " + oid);
            }
        }
        byte[] idp = crl.getExtensionValue(IDP_OID);
        if (idp == null) return new boolean[] {false, false};
        boolean onlyUser = false, onlyCa = false;
        try {
            Der outer = Der.read(idp, 0);                         // OCTET STRING
            if (outer.tag != 0x04) throw new RejectedCrl(issuer, "malformed issuingDistributionPoint");
            Der seq = Der.read(idp, outer.start);                 // IssuingDistributionPoint ::= SEQUENCE
            if (seq.tag != 0x30) throw new RejectedCrl(issuer, "malformed issuingDistributionPoint");
            for (int i = seq.start; i < seq.end; ) {
                Der e = Der.read(idp, i);
                boolean flag = e.end > e.start && idp[e.end - 1] != 0;
                switch (e.tag & 0xff) {
                    case 0xA0 -> throw new RejectedCrl(issuer, "partitioned CRL (issuingDistributionPoint distributionPoint)");
                    case 0x81 -> onlyUser = flag;
                    case 0x82 -> onlyCa = flag;
                    case 0x83 -> throw new RejectedCrl(issuer, "partitioned CRL (onlySomeReasons)");
                    case 0x84 -> { if (flag) throw new RejectedCrl(issuer, "indirect CRL is not supported"); }
                    case 0x85 -> { if (flag) throw new RejectedCrl(issuer, "attribute-certificate CRL"); }
                    default -> throw new RejectedCrl(issuer, "unknown issuingDistributionPoint field");
                }
                i = e.end;
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new RejectedCrl(issuer, "malformed issuingDistributionPoint");
        }
        return new boolean[] {onlyUser, onlyCa};
    }

    /** Minimal DER TLV reader (definite lengths only). */
    private record Der(int tag, int start, int end) {
        static Der read(byte[] b, int off) {
            int tag = b[off] & 0xff, i = off + 1, len = b[i++] & 0xff;
            if (len > 0x80) {
                int n = len & 0x7f;
                if (n > 4) throw new ArrayIndexOutOfBoundsException();
                len = 0;
                for (int k = 0; k < n; k++) len = (len << 8) | (b[i++] & 0xff);
            } else if (len == 0x80) {
                throw new ArrayIndexOutOfBoundsException();   // indefinite length is not DER
            }
            if (len < 0 || i + len > b.length) throw new ArrayIndexOutOfBoundsException();
            return new Der(tag, i, i + len);
        }
    }

    private static ByteBuffer key(PublicKey k) {
        return ByteBuffer.wrap(k.getEncoded());
    }

    // ------------------------------------------------------------------ off the request path

    /**
     * Re-reads and verifies every changed CRL file that a realm's X.509 authenticator lists, and evicts cached files
     * that none lists any more. Runs on the factory's background thread, never on a sign-in.
     */
    static void prewarm(Collection<String> configuredRelPaths, Signers signers) {
        Set<Path> wanted = new LinkedHashSet<>(resolve(configuredRelPaths));
        CACHE.keySet().retainAll(wanted);
        LOCKS.keySet().retainAll(wanted);
        ALARMED.keySet().retainAll(wanted);
        for (Path f : wanted) {
            try {
                ensureVerified(load(f, true, System.currentTimeMillis()), signers);
            } catch (GeneralSecurityException | IOException e) {
                Loaded previous = CACHE.get(f);
                alarm(f, e instanceof RejectedCrl rc ? rc.issuer : previous == null ? null : previous.issuer, e);
            } catch (RuntimeException e) {
                log.errorf(e, "STIG-CRL-UNREADABLE \"%s\": %s", f, describe(e));
            }
        }
    }

    private static volatile Thread prewarmThread;
    private static final java.util.concurrent.Semaphore WAKE = new java.util.concurrent.Semaphore(0);

    private static void wake() {
        if (WAKE.availablePermits() == 0) WAKE.release();
    }

    /** Starts the background pre-warm (every {@code stig.crl.prewarm.seconds}, default 30). Idempotent. */
    static synchronized void startPrewarm(KeycloakSessionFactory factory) {
        if (prewarmThread != null) return;
        long period = Long.getLong("stig.crl.prewarm.seconds", 30L) * 1000L;
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    KeycloakModelUtils.runJobInTransaction(factory, s -> prewarm(configuredPaths(s), truststore(s)));
                } catch (Throwable e) {   // incl. Error (e.g. OutOfMemoryError on a large CRL): the thread must keep running
                    log.errorf(e, "STIG-CRL-PREWARM-FAILED %s (sign-ins still re-read changed CRLs themselves)", describe(e));
                    if (e instanceof InterruptedException || Thread.currentThread().isInterrupted()) return;
                }
                try {
                    WAKE.tryAcquire(period, java.util.concurrent.TimeUnit.MILLISECONDS);   // every period, or when a sign-in saw a change
                    WAKE.drainPermits();
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "stig-crl-prewarm");
        t.setDaemon(true);
        prewarmThread = t;
        t.start();
    }

    static synchronized void stopPrewarm() {
        if (prewarmThread != null) prewarmThread.interrupt();
        prewarmThread = null;
    }

    /** Every local CRL path listed by any X.509 authenticator configuration with CRL checking on, in any realm. */
    private static Set<String> configuredPaths(KeycloakSession s) {
        Set<String> out = new HashSet<>();
        s.realms().getRealmsStream().forEach(r -> r.getAuthenticatorConfigsStream().forEach(c -> {
            Map<String, String> m = c.getConfig();
            if (m == null || !m.containsKey("x509-cert-auth.crl-relative-path")) return;
            X509AuthenticatorConfigModel x = new X509AuthenticatorConfigModel(c);
            if (handles(x)) out.addAll(Objects.requireNonNull(localPaths(x.getCRLRelativePath())));
        }));
        return out;
    }

    /** Tests only. */
    static void clearForTests() {
        CACHE.clear();
        LOCKS.clear();
        ALARMED.clear();
    }

    static int cachedForTests() {
        return CACHE.size();
    }
}
