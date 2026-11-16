package mil.stig.keycloak;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Plain-Java test (no framework); exit 1 on any failure. IssuerCrlCheck: the card's issuer's CRL and the issuing CA's
 * root CRL decide; signatures only against the truststore; once per file version (incl. ctime); unusable CRLs of OTHER
 * issuers alarm instead of refusing; structural rejections; background pre-warm and eviction.
 * Fixtures: an openssl test PKI - Test Root (RSA) issues Test CA A/B/C (RSA); EC leaves; CRL nextUpdate 2036-11-13.
 */
public final class IssuerCrlCheckTest {
    static int failed = 0;
    static final long NOW = 1_800_000_000_000L;            // 2027-01-15
    static final long AFTER_NEXT_UPDATE = 2_200_000_000_000L; // 2039-09-18

    static X509Certificate cert(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
    static byte[] der(String pem) {
        String b64 = pem.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }
    static Path write(Path dir, String name, String pem) throws Exception {   // atomic swap, as crl-fetch / crl-sync do
        Path tmp = dir.resolve("." + name + ".new");
        Files.write(tmp, der(pem));
        return Files.move(tmp, dir.resolve(name), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
    static IssuerCrlCheck.Signers signers(List<X509Certificate> trusted) {
        return new IssuerCrlCheck.Signers() {
            @Override public List<X509Certificate> named(javax.security.auth.x500.X500Principal p) {
                List<X509Certificate> out = new ArrayList<>();
                for (X509Certificate c : trusted) if (c.getSubjectX500Principal().equals(p)) out.add(c);
                return out;
            }
            @Override public List<X509Certificate> all() { return trusted; }
        };
    }
    interface Run { void run() throws Exception; }
    static long timed(Run r) throws Exception { long t = System.nanoTime(); r.run(); return (System.nanoTime() - t) / 1_000_000; }
    static void expect(String name, boolean allowed, Run r) {
        boolean got; String why = "";
        try { r.run(); got = true; } catch (GeneralSecurityException e) { got = false; why = " (" + e.getMessage() + ")"; }
        catch (Exception e) { failed++; System.out.println("FAIL " + name + " (unexpected " + e + ")"); return; }
        System.out.println((got == allowed ? "PASS " : "FAIL ") + name + (allowed ? " -> allowed" : " -> refused") + why);
        if (got != allowed) failed++;
    }
    static void expectEq(String name, long want, long got) {
        System.out.println((want == got ? "PASS " : "FAIL ") + name + " (want " + want + ", got " + got + ")");
        if (want != got) failed++;
    }

    public static void main(String[] a) throws Exception {
        X509Certificate root = cert(ROOT), caA = cert(CA_A), caB = cert(CA_B), caC = cert(CA_C), impostor = cert(CA_A_IMPOSTOR);
        X509Certificate good = cert(LEAF_A_GOOD), revoked = cert(LEAF_A_REVOKED), leafB = cert(LEAF_B), leafC = cert(LEAF_C);
        List<X509Certificate> trusted = List.of(root, caA, caB, caC);
        IssuerCrlCheck.Signers ts = signers(trusted);

        Path dir = Files.createTempDirectory("issuer-crl");
        System.setProperty("jboss.server.config.dir", dir.toString());
        Path crlA = write(dir, "a.crl", CRL_A_REVOKES_ONE), crlB = write(dir, "b.crl", CRL_B), crlR = write(dir, "root.crl", CRL_ROOT);
        List<Path> all = List.of(crlB, crlA, crlR);
        X509Certificate[] goodOnly = {good};

        IssuerCrlCheck.clearForTests();
        long v0 = IssuerCrlCheck.VERIFICATIONS.get();
        expect("valid card of CA A (CRLs of B, A and the root listed)", true, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        long first = IssuerCrlCheck.VERIFICATIONS.get() - v0;
        expectEq("the first sign-in verified only CA A's and the root's CRL (not CA B's)", 2, first);
        for (int i = 0; i < 5; i++) IssuerCrlCheck.check(goodOnly, all, ts, true, NOW);
        expectEq("five more sign-ins verified no CRL signature again", first, IssuerCrlCheck.VERIFICATIONS.get() - v0);
        expect("revoked card of CA A", false, () -> IssuerCrlCheck.check(new X509Certificate[] {revoked}, all, ts, true, NOW));
        expect("valid card of CA B", true, () -> IssuerCrlCheck.check(new X509Certificate[] {leafB}, all, ts, true, NOW));
        expect("card of CA C, which has no CRL (fail closed)", false, () -> IssuerCrlCheck.check(new X509Certificate[] {leafC}, all, ts, true, NOW));
        expect("CA A's CRL past nextUpdate, abort-if-non-updated on", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, AFTER_NEXT_UPDATE));
        expect("CA A's CRL past nextUpdate, abort-if-non-updated off (Keycloak's semantics)", true, () -> IssuerCrlCheck.check(goodOnly, all, ts, false, AFTER_NEXT_UPDATE));
        expect("no truststore certificates at all", false, () -> IssuerCrlCheck.check(goodOnly, all, signers(List.of()), true, NOW));

        // intermediate revocation: the issuing CA against the root's CRL
        expect("root CRL not listed: the issuing CA's status is unknown (fail closed)", false, () -> IssuerCrlCheck.check(goodOnly, List.of(crlB, crlA), ts, true, NOW));
        write(dir, "root.crl", CRL_ROOT_REVOKES_A);
        expect("root CRL revokes CA A: CA A's valid card", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        expect("root CRL revokes CA A: CA B's card is unaffected", true, () -> IssuerCrlCheck.check(new X509Certificate[] {leafB}, all, ts, true, NOW));
        write(dir, "root.crl", CRL_ROOT);

        // signer source: truststore only, never the presented chain
        expect("valid card, impostor 'Test CA A' in the presented chain, genuine CRL", true, () -> IssuerCrlCheck.check(new X509Certificate[] {good, impostor}, all, ts, true, NOW));
        write(dir, "a.crl", CRL_A_BY_IMPOSTOR);
        expect("CRL signed by an impostor 'Test CA A' that the client presents in its chain", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good, impostor}, all, ts, true, NOW));
        expect("... and with the genuine CA in the chain", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good, caA}, all, ts, true, NOW));
        expect("... a card of CA B is not affected by CA A's bad CRL (alarm only)", true, () -> IssuerCrlCheck.check(new X509Certificate[] {leafB}, all, ts, true, NOW));

        // availability: unusable CRLs of OTHER issuers alarm, own issuer refuses
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        Path junk = dir.resolve("junk.crl"); Files.writeString(junk, "not a crl");
        expect("an unreadable CRL of an unknown issuer does not refuse a card whose issuer's CRL is fine", true, () -> IssuerCrlCheck.check(goodOnly, List.of(crlB, crlA, crlR, junk), ts, true, NOW));
        expect("a listed CRL file is missing (another issuer's): alarm, card allowed", true, () -> IssuerCrlCheck.check(goodOnly, List.of(crlB, crlA, crlR, dir.resolve("gone.crl")), ts, true, NOW));
        Files.write(crlA, "corrupt".getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
        expect("the card's own issuer's CRL becomes unreadable", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        expect("... cards of other issuers are not affected", true, () -> IssuerCrlCheck.check(new X509Certificate[] {leafB}, all, ts, true, NOW));
        write(dir, "a.crl", CRL_A_REVOKES_ONE);

        // CRL hardening
        write(dir, "b.crl", CRL_B_DELTA);
        expect("delta CRL for CA B: CA B's card", false, () -> IssuerCrlCheck.check(new X509Certificate[] {leafB}, all, ts, true, NOW));
        expect("delta CRL for CA B: CA A's card is unaffected", true, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        write(dir, "b.crl", CRL_B);
        write(dir, "a.crl", CRL_A_CRITICAL_UNKNOWN);
        expect("unsupported critical CRL extension", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        write(dir, "a.crl", CRL_A_IDP_SOME_REASONS);
        expect("partitioned CRL (IDP onlySomeReasons)", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        write(dir, "a.crl", CRL_A_IDP_ONLY_CA);
        expect("CRL scoped to CA certificates (IDP onlyContainsCACerts) for a card", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        write(dir, "a.crl", CRL_A_IDP_ONLY_USER);
        expect("CRL scoped to end-entity certificates (IDP onlyContainsUserCerts) for a card", true, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        write(dir, "a.crl", CRL_A_FUTURE);
        expect("CRL with thisUpdate in the future", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));

        // refresh: atomic swap, and an in-place rewrite that only changes ctime
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        IssuerCrlCheck.check(goodOnly, all, ts, true, NOW);
        long v1 = IssuerCrlCheck.VERIFICATIONS.get();
        write(dir, "a.crl", CRL_A_REVOKES_BOTH);
        expect("after an atomic swap that revokes it, the formerly valid card", false, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        expectEq("the swapped CRL was verified once", 1, IssuerCrlCheck.VERIFICATIONS.get() - v1);
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        IssuerCrlCheck.check(goodOnly, all, ts, true, NOW);
        byte[] onlyGood = der(CRL_A_REVOKES_ONLY_GOOD);
        if (onlyGood.length != Files.size(crlA)) { failed++; System.out.println("FAIL fixture: same-size CRL pair differs in size"); }
        FileTime mtime = Files.getLastModifiedTime(crlA);
        Object key = Files.readAttributes(crlA, java.nio.file.attribute.BasicFileAttributes.class).fileKey();
        Thread.sleep(1100);
        Files.write(crlA, onlyGood, StandardOpenOption.TRUNCATE_EXISTING);   // same inode, same size ...
        Files.setLastModifiedTime(crlA, mtime);                               // ... same mtime: only ctime differs
        boolean sameKey = key == null || key.equals(Files.readAttributes(crlA, java.nio.file.attribute.BasicFileAttributes.class).fileKey());
        expect("in-place rewrite with the same inode, size and mtime (ctime only) is re-read" + (sameKey ? "" : " [fileKey changed]"), false,
                () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));

        // the full path: leaf <- Test Issuing CA I <- Test Sub CA S <- Test Root
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        X509Certificate caS = cert(CA_S), caI = cert(CA_I), leafI = cert(LEAF_I);
        IssuerCrlCheck.Signers ts3 = signers(List.of(root, caA, caB, caS, caI));
        Path crlI = write(dir, "i.crl", CRL_I), crlS = write(dir, "s.crl", CRL_S);
        List<Path> chainFiles = List.of(crlI, crlS, crlR);
        X509Certificate[] leafIOnly = {leafI};
        expect("three-level path, every CA unrevoked", true, () -> IssuerCrlCheck.check(leafIOnly, chainFiles, ts3, true, NOW));
        write(dir, "s.crl", CRL_S_REVOKES_I);
        expect("the sub CA's CRL revokes the issuing CA", false, () -> IssuerCrlCheck.check(leafIOnly, chainFiles, ts3, true, NOW));
        write(dir, "s.crl", CRL_S);
        write(dir, "root.crl", CRL_ROOT_REVOKES_S);
        expect("the root's CRL revokes the sub CA (two levels above the card)", false, () -> IssuerCrlCheck.check(leafIOnly, chainFiles, ts3, true, NOW));
        expect("... a card under CA A (also issued by the root) is unaffected", true, () -> IssuerCrlCheck.check(goodOnly, all, ts3, true, NOW));
        write(dir, "root.crl", CRL_ROOT);
        expect("the sub CA's CRL is not listed: the issuing CA's status is unknown", false, () -> IssuerCrlCheck.check(leafIOnly, List.of(crlI, crlR), ts3, true, NOW));
        expect("the sub CA is not in the truststore: the path cannot be built", false, () -> IssuerCrlCheck.check(leafIOnly, chainFiles, signers(List.of(root, caI)), true, NOW));
        expect("the root is not in the truststore: the path cannot be built", false, () -> IssuerCrlCheck.check(goodOnly, all, signers(List.of(caA, caB)), true, NOW));
        // a second truststore certificate for CA A's key (re-issued by the root): revoking it refuses CA A's cards
        X509Certificate caA2 = cert(CA_A_SECOND_CERT);
        IssuerCrlCheck.Signers tsA2 = signers(List.of(root, caA, caA2, caB));
        expect("CA A's key has two certificates, neither revoked", true, () -> IssuerCrlCheck.check(goodOnly, all, tsA2, true, NOW));
        write(dir, "root.crl", CRL_ROOT_REVOKES_A_SECOND);
        expect("the root revokes CA A's SECOND certificate only: CA A's card", false, () -> IssuerCrlCheck.check(goodOnly, all, tsA2, true, NOW));
        expect("... the same revocation does not matter when that certificate is not trusted", true, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        write(dir, "root.crl", CRL_ROOT);

        // a re-read in progress: wait for it; fall back to the previous version only after the timeout and before nextUpdate
        IssuerCrlCheck.REREAD_WAIT_MS = 400;
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        IssuerCrlCheck.check(goodOnly, all, ts, true, NOW);
        java.util.concurrent.locks.ReentrantLock lockA = IssuerCrlCheck.lockForTests(crlA);
        write(dir, "a.crl", CRL_A_REVOKES_BOTH);
        hold(lockA, 200);
        long waited = timed(() -> expect("re-read in progress for 200 ms: the sign-in waits and sees the new CRL", false,
                () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW)));
        expectEq("... it waited for the re-read (>= 150 ms)", 1, waited >= 150 ? 1 : 0);
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        IssuerCrlCheck.check(goodOnly, all, ts, true, NOW);
        write(dir, "a.crl", CRL_A_REVOKES_BOTH);
        hold(lockA, 1500);
        waited = timed(() -> expect("re-read takes longer than the 400 ms wait, previous CRL before nextUpdate: previous version used", true,
                () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW)));
        expectEq("... after waiting the timeout, not the whole re-read (400-1400 ms)", 1, waited >= 380 && waited < 1400 ? 1 : 0);
        Thread.sleep(1600);
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        IssuerCrlCheck.check(goodOnly, all, ts, false, NOW);
        write(dir, "a.crl", CRL_A_REVOKES_BOTH);
        hold(lockA, 1200);
        waited = timed(() -> expect("previous CRL past nextUpdate: the sign-in waits for the re-read and sees the new CRL", false,
                () -> IssuerCrlCheck.check(goodOnly, all, ts, false, AFTER_NEXT_UPDATE)));
        expectEq("... it waited the whole re-read (>= 1100 ms)", 1, waited >= 1100 ? 1 : 0);
        IssuerCrlCheck.REREAD_WAIT_MS = 2000;

        // pre-warm off the request path, and eviction of files no longer configured
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        IssuerCrlCheck.prewarm(List.of("a.crl", "b.crl", "root.crl"), ts);
        long v2 = IssuerCrlCheck.VERIFICATIONS.get();
        expect("valid card after pre-warm", true, () -> IssuerCrlCheck.check(goodOnly, all, ts, true, NOW));
        expectEq("the sign-in after pre-warm verified nothing", 0, IssuerCrlCheck.VERIFICATIONS.get() - v2);
        IssuerCrlCheck.prewarm(List.of("a.crl", "root.crl"), ts);
        expectEq("pre-warm evicts b.crl, which no realm lists any more", 2, IssuerCrlCheck.cachedForTests());

        // the structure parser on its own
        X509CRL plain = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der(CRL_A_REVOKES_ONE)));
        boolean[] s = IssuerCrlCheck.structure(plain, plain.getIssuerX500Principal());
        expectEq("plain CRL has no IDP scope", 0, (s[0] ? 1 : 0) + (s[1] ? 2 : 0));

        System.out.println(failed == 0 ? "all passed" : failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Holds {@code lock} on another thread for {@code ms}, as a slow re-read would; returns once it is held. */
    static void hold(java.util.concurrent.locks.ReentrantLock lock, long ms) throws InterruptedException {
        java.util.concurrent.CountDownLatch held = new java.util.concurrent.CountDownLatch(1);
        Thread t = new Thread(() -> { lock.lock(); held.countDown(); try { Thread.sleep(ms); } catch (InterruptedException e) { } finally { lock.unlock(); } });
        t.setDaemon(true); t.start(); held.await();
    }

    // ---- fixtures (openssl, see the class comment)
    static final String ROOT =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC+jCCAeKgAwIBAgIUaxjqiLD6X/XCHlCrZE/9tjqR7towDQYJKoZIhvcNAQEL\n" +
        "BQAwFDESMBAGA1UEAwwJVGVzdCBSb290MCAXDTI2MTExNjAzMjk0OFoYDzIxMjYx\n" +
        "MDIzMDMyOTQ4WjAUMRIwEAYDVQQDDAlUZXN0IFJvb3QwggEiMA0GCSqGSIb3DQEB\n" +
        "AQUAA4IBDwAwggEKAoIBAQDeBhY1mhb+NPFYmtpiYNGcGsRUuWFrIz4x7zK/PDIq\n" +
        "epc8LyAWJnkZZz5ppdOzTZ5slXA1+qohglX2GUJoZbU0AP9pBb6lT1fu3b788YQX\n" +
        "FS4cbGz79GHukBAh29/jYTdORom5fs09okwLEPxN6R0StYMSpBhKF9E3a1d78FEx\n" +
        "nGaDJwkUT0kAcNMug5cmcZRH8YfJxI/NV921ZvMc7q6stXCJ3H8mBHpwghZVazwe\n" +
        "7Up0Iyupu7FW3ZAPXggQYufknWGyldtiyop4vyWfENsVNEC2co7T+06G45gpC2SH\n" +
        "17RbbTJxhLKpFKsshl60yNBkmt17K43huB3wy2mpcOEZAgMBAAGjQjBAMA8GA1Ud\n" +
        "EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQHfEKYuGxcdtcI\n" +
        "+Wqy66NiK2C3RDANBgkqhkiG9w0BAQsFAAOCAQEAgWxnE8whhiw2S4RDUCuXj/q8\n" +
        "yk3g+W3zzHzCmXPQ5qlZaAQ9cn+XG+o/3GOGmlQ+fOppm6L+/SYOZ7cJ71ZN03cI\n" +
        "d8ACS7A1BmyGmpITGhYZh8JiIjX4kJv03ycnf7BNm3fxsYH3XCejqTuL46wYlWAD\n" +
        "iNpfQUXiPx2THgWVNwTsSHYkeMa0yHAfvhP3OSGtnpdPXLE0CpJEr3MFJS4ClpnW\n" +
        "GydZMSeIge7H19i1a94rQ+WJmK/VDTYnVkhCULFVDbD+5nykoCE1EukehxtBdylH\n" +
        "pVlP4aVFu91NcFr41dbVOplF0rO5NtjtSR7394ZGk7sZnYuxc430W8XOMPkWSw==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_A =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC6DCCAdCgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVz\n" +
        "dCBSb290MCAXDTI2MTExNjAzMjk0OFoYDzIxMjYxMDIzMDMyOTQ4WjAUMRIwEAYD\n" +
        "VQQDDAlUZXN0IENBIEEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4\n" +
        "NMXgFO60ZAzuItU77bV5p8BpLDW8X+0ieE3N6QU4HGCa/u5vgoex3JEuvVWTD9z6\n" +
        "if98Gu8bDuQLjSL7prv+l6DBfRd8sNXMPG4bMmb+OEy2SHEW4Gxgy1VHpvq/KnQU\n" +
        "30z51dySJ0xowFTZthK3giaQSWO1X3Zrb0boALaj3U0jrvbDerhZhdqTLbd+RRw6\n" +
        "eDHP+TId1QZ/9GMGBXUOof8WQQdrOtNQieBuoQ+aI2gIX5TCgHjMx4nbpibFWrUi\n" +
        "Kqdnqx/8bvYeVXkf4W/UAiZL+SuBijnoad8OF1s/BocEeIv00BmRVPhYjrEMRufk\n" +
        "lT1cyeKKU8RF/aLCVcD3AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n" +
        "AQH/BAQDAgEGMB0GA1UdDgQWBBSHge6zO1VSgjLXs12IuwUTVuwx/TANBgkqhkiG\n" +
        "9w0BAQsFAAOCAQEAXEG1dgILIMJk9wRIvAJjOwyTYIn74OrGI2of01dZv05FC/4W\n" +
        "gGJDi7nd4Qd15EhQF1WjUgS0sDIw6+sqbsz6Hh0eMAl1BGMt+mYyaLvHg/WuOF04\n" +
        "yIoC964M518V/PjBiOmMyqXuYkTDp8U6oQBZW4bf7kGcNQZ00bSOxYOP13kf2/Qu\n" +
        "N8gSF9n9j5Hk3CkOZ81GrkxcVJRC3M7Eginl8WCyaUqDLcVwLftY8pHcnzMcnPop\n" +
        "nTgJ4+RH1Q/kY1qQmNoGN7tbN3HEGOWCORm/PEfArLSuDwomU/xxgHaKtfh7zxeE\n" +
        "edxmzlOYSld8ibXFRZrRiFpIciD6br/syASQtw==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_B =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC6DCCAdCgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVz\n" +
        "dCBSb290MCAXDTI2MTExNjAzMjk0OFoYDzIxMjYxMDIzMDMyOTQ4WjAUMRIwEAYD\n" +
        "VQQDDAlUZXN0IENBIEIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5\n" +
        "isuVh0WI/7J8KIBFY5iFLAPe9Mu3Fy/5lER6/7E+zUE9Pex5otkwe7O5TmtKUopx\n" +
        "vM842cvKtPh0mhnhqil5lbuOSvn20lmb8Uyk8KRlaWCOpycdNLox09j0LImhTf8M\n" +
        "mJRVI8skbJHOq8B8eBHJc7gKJjA/PSBI33TjjqQbbNQBnD7MaxyiPa9Y4utlQGj1\n" +
        "tjySaW/TM47j9u/LJlIeVqN6YYZIqs77EIoQ7DMW7I/jz5rLhDVmM6NE3Q7X/4Ta\n" +
        "45qqXbpL0w4fORgwi8+7mFmpIYEJUQpow8Mfj74Lj48PhEJwtFX2/Lp0gIIh5BIh\n" +
        "iPHVkI+WGekvB4KQS0dXAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n" +
        "AQH/BAQDAgEGMB0GA1UdDgQWBBRLq4YGPphpFijTImyYx34qs6DGmjANBgkqhkiG\n" +
        "9w0BAQsFAAOCAQEAbRO/e5NGZnkCIPHdDuER1sqI9LFeTHdclLkBsRHIG0GIz1Cw\n" +
        "NivxFyXDqB922/IlsgPcxUuk+KsRnAeaRWAYHfDwUjztzkB8guAKCUgB3bN9o9qi\n" +
        "GHa+IbJ/h/EEY2xv8WNzj1kfJV27KGQCJXPpcd+ofg7gfC6V0LFFoF25wY86pSyG\n" +
        "vp8RuKygW3qjdOKivhYZIuQkun2rI56eGjW3HGV8YWkpjGm923qGKlkbEBIKlD4z\n" +
        "mxKLh9LdfWnaxTenH68bnDFne/Ey6vEUNssKrKEPrzpa/O/hG8c0xnT5rtS9YCuI\n" +
        "Qpkw9Lc/sE7XLd4je+km+QfMBI9Y15JU2ADAsQ==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_C =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC6DCCAdCgAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVz\n" +
        "dCBSb290MCAXDTI2MTExNjAzMjk0OFoYDzIxMjYxMDIzMDMyOTQ4WjAUMRIwEAYD\n" +
        "VQQDDAlUZXN0IENBIEMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr\n" +
        "vBoOtb4hdA5j4mww2ZUZLEJLrxsOoOSgdIAnV3SbrSwhBUYkpMPwgYHr9RS0xUJu\n" +
        "p6gqdG27MjQjhjF+q//+wDPTAYTl7tDHXtiFFhxoiEwBnptM91H1t/Jtj7cID5jn\n" +
        "FUJKPmPZwQP5XuMioBRapt8wvLmNOp28rxAAPF+T5ApltIJCIsmUnoOdx3wmtRqx\n" +
        "5w88kVzq/gOsH2thyPKGGGVgsLz/XU0ynIgy3KSP7LXcbFsoqtsJjsgbeuVpgrzA\n" +
        "Deih0SG4S+/TVavBOWahSNbrI42YXSh9YfvQhlugXbdOUYKBx0C+KkhBMiug9tdk\n" +
        "7zvY18DW+nxT140bZ3yZAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n" +
        "AQH/BAQDAgEGMB0GA1UdDgQWBBR1azppFJ7knH0LMzbWI2TNY2o8RTANBgkqhkiG\n" +
        "9w0BAQsFAAOCAQEA3cYPcBkJPfo2AG/Kwt2aixNiCeHifJ+ss9rd+0qfoT9u9EzW\n" +
        "yejJp2nogAdOQGwQ969dFEs3J8jGUO9CIk7BMARmNUSVwuE5os4Df9GMO7oL4plp\n" +
        "TT0jcvCBgIq/DAGPqmO3URYC/esFVVe5TdZFVkuxxJApULzjuIpuj0MpvmVa0j/7\n" +
        "rNv7YAdaTGKBU7+Ka2hsqA8QYNwG8J0UhJoKXFdBHfjGHkqZd0f/DTd9GDVNwi5e\n" +
        "4A6CmfMiSMYb4AECWvgQqmUS0U0dywVFtYUUYgLgiXiGrVcxW3+u81kFFkNt1jGl\n" +
        "NJ2wwlwcuR6z6emoB77wS9RTA+8MrsdN/3npug==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_A_IMPOSTOR =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC+jCCAeKgAwIBAgIUTs9AtOri59crzlZ07i2SFroLYZgwDQYJKoZIhvcNAQEL\n" +
        "BQAwFDESMBAGA1UEAwwJVGVzdCBDQSBBMCAXDTI2MTExNjAzMjk0OFoYDzIxMjYx\n" +
        "MDIzMDMyOTQ4WjAUMRIwEAYDVQQDDAlUZXN0IENBIEEwggEiMA0GCSqGSIb3DQEB\n" +
        "AQUAA4IBDwAwggEKAoIBAQC4OiPxYIXa5W4YQClEB+t/0Q31z5+atqpux5Py1404\n" +
        "Ebl5H6gn0DOkCXUzSY9uXft6dR+CxDn7hjaGbbSa3eCHujLEOMRybI9MHsS8ujVO\n" +
        "7ZTRe5w2taB82w3USMv4zw2n6oCWqwrT802wXr6NuohZXThNJ740ezThcNTmhqV6\n" +
        "4DHcFOfkirbNxC3s5pZAV5R4zYH6UD61422xKE8YRG7xhp1XUOeVMDMyaG/7qMaw\n" +
        "D5jjUMECpH2T5tJPZLkVxrn3PaXlTaRnsluGS989/otgwFHt9GxXoP44J/VUdKBY\n" +
        "w6fvmdZROwQipw1WQCGA1AlAiLyL9ARDzTggQjpaEM5DAgMBAAGjQjBAMA8GA1Ud\n" +
        "EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSRLnyiOe1/rjEp\n" +
        "AbwTQy1OSOtWTzANBgkqhkiG9w0BAQsFAAOCAQEAFdTIdwX1lXQVwlKmobLSB6YW\n" +
        "FnS3eO6Vy5CF2qjSzlBibPL+YEkA+lLt1I3gVor1EhaKXSPvwRqVy6+QTRe/GG1n\n" +
        "+tBsB9X73vuO/2Up18OQzB7qfMhlaEEW0GPhKDSZAqaOC5be+BMFBkxa6uqrB6FZ\n" +
        "HcfDeUYc4siAgI/iWN/Eu2YXwN+9ke56UJvHHsvx750isi4upGqq7l/GrRsEV0Jr\n" +
        "UcEMSc8nJLPXpSA6UDuuVdudMmFqGdxyWCD3PScy/LmOIJeuwAF7suaMx0CycqCW\n" +
        "6LcCw6em1f/Du8DUXHO8O5OCN+pGWekvuGbdkqQYG64ZgMuiz63432TD/B4tGg==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_A_GOOD =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIB8jCB26ADAgECAgIQADANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0\n" +
        "IENBIEEwIBcNMjYxMTE2MDMyOTQ4WhgPMjEyNjEwMjMwMzI5NDhaMA8xDTALBgNV\n" +
        "BAMMBGdvb2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAYxb/MtUdipGt4Wz3\n" +
        "DBWWevzYhg+UAqhR6ncqCy1flz3KvPS+G4wk56MuA3EilRKyzaPibg8vJn43pUqw\n" +
        "Lo1Tox0wGzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF\n" +
        "AAOCAQEAXA990zBx9kYlr0ZR1eL/LmfaP/RlZGeGtnG1pfcmt+zltf/oQE41tMJF\n" +
        "W/qWzuZXzPOkUqjyR28gVy0iF5PhTnJHR36o0U/1PbJhCJlTFTqFlmli6vUyDIBm\n" +
        "rBnxwXhWfcc58ojbx54k9JgtKQzHuth2l6FbXubj7QYFdoJP6ELal89YjURbkRWA\n" +
        "+n1cIQw3s8SUMXYrqx/q1jvgNZGEdRP895SB3209JE3TAZZHJHlJ0pUTGxDNt/3Q\n" +
        "b7eJc4z+lk+XL/PeMrVc2q2VOfAfVkcK3B01CJ7UMtKApOEl2qr2lzPRqf2DRajg\n" +
        "orlPYI9KEJctIaCm0y8aMCzZr6iGLQ==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_A_REVOKED =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIB9TCB3qADAgECAgIQATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0\n" +
        "IENBIEEwIBcNMjYxMTE2MDMyOTQ5WhgPMjEyNjEwMjMwMzI5NDlaMBIxEDAOBgNV\n" +
        "BAMMB3Jldm9rZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQDCJpnASLIargN\n" +
        "m9B5SdJnk0n4soxSVqXWQO+H4O5MkVcHCfpgjpJtQQRaO/rVXRc7f4Ll4x/3cNNs\n" +
        "9vNq+Tocox0wGzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B\n" +
        "AQsFAAOCAQEAd22+AkiKxTnH8XANvjd0fFeQ2oKWEAh6BgSyGxzAAvmsTzinJg2O\n" +
        "XIyWozMq0FZsTnUEEwRVokc2IoNVq4ONngm71P0QIk9QlHKsVXGibiWr4TcY6WKv\n" +
        "usksMgzHx2bkHVqtE0dSWt78vWoED9N6C2Xm/cPrgfM99y3vkKvhXGQ4OWaJxqJE\n" +
        "wkwpb8jBHYkhICR2BmaAETehfPoPd3M5/BpkxhP/WU+n/MS2qc2e9ozNaevxKCli\n" +
        "IQRKFuCACJwhfvfIBAwcZ8/TACBKs9dAECiPD4g8FB+TGHOTZji2Gh+7i2Gm2z9R\n" +
        "Zu/oAtDMDa2mNiZGpNMlPDlNLJy1AaBycQ==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_B =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIB8zCB3KADAgECAgIQADANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0\n" +
        "IENBIEIwIBcNMjYxMTE2MDMyOTQ5WhgPMjEyNjEwMjMwMzI5NDlaMBAxDjAMBgNV\n" +
        "BAMMBWJnb29kMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHnyhIw0F/WAw4X/p\n" +
        "EWiSZsqyMFH33Wu1QLEpBSP8rVgL8ufoYHdmaonMcGnLhUdVfiBlEWfu4BnoNWcQ\n" +
        "3PzoxKMdMBswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL\n" +
        "BQADggEBAB/9EdNZHKgBhCyOmPvYoFm9LzUGIYUne6hy4QFpqHuPxHOwl8ZpDn/A\n" +
        "rvMEPfqHmFCGms3NkF+Pf0ICPkPuxRzJl8hJcJtQePnXd5UDo+EfqdT89toa/StH\n" +
        "rHsIb2+tNF8X2krf186GJhz05NrS7tTtKwSR5LV4Jos7ukTZqOzGbGpiKRg97oae\n" +
        "Caw3sPcIxm94DxttbqwfoCBbXWRotoJg7sRB38cCCoz5Otg9+0tNidTA0DPmrXCY\n" +
        "aOtA1ffrrCl8kl3GJdQFg+U09IMkyLYbDHKSiYZ55YN+chLxeDLeuqUZVQnEwFyw\n" +
        "DIJhqourtprjlMQJVLSNKTFTYcC64Tg=\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_C =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIB8zCB3KADAgECAgIQADANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0\n" +
        "IENBIEMwIBcNMjYxMTE2MDMyOTQ5WhgPMjEyNjEwMjMwMzI5NDlaMBAxDjAMBgNV\n" +
        "BAMMBWNnb29kMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMYI9TTwxXVlpmUrT\n" +
        "PPndS0imUntCw39czzioqWvsWbqILuJytbUIDuG3G9xXEmTklfhk5/GOUMv08/O/\n" +
        "3cATcaMdMBswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL\n" +
        "BQADggEBAGbPv7wR1+TnldHhftRbey6/hK86tQfYCisudRSuvgo69PXzg9ufnmFg\n" +
        "2opYiC+wDiO3Hz/5pOIO008wDWv2K0IlUbwjJhJKwLGMhwy/GOzi9GlU9T79Ofjy\n" +
        "KXUtV2n/UKFqbPbY+3mZERBYqhchBNoZcRij1WgL4nadvcdF1rwjX4MzGkroIW7V\n" +
        "RprrlUglRp3C6AQKRFOJq4DWxj+28q6lC0z0oSS4QogyIkg/+Khcpm4U94tocEup\n" +
        "tBQtYw9oDBbjUoJS9BdRAk5CQQ7dYANOYbW2dJZJPIA1aP+z/gfwiM2qotKhO0oV\n" +
        "Sgkj5Z6qi0lGYGCcvM8J35cafvbkSWc=\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CRL_ROOT =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBjTB3AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgUm9vdBcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WqAvMC0wHwYDVR0jBBgwFoAUB3xC\n" +
        "mLhsXHbXCPlqsuujYitgt0QwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADggEB\n" +
        "ADc34kpkKpsYRM0/re1WKKrIdeiZRFxc04LtnGUhKodMDHFNwxCi071ViGW8VZdI\n" +
        "jDwmKxqd4w2XMGrr0lFqHAuiy5POKS+/jpnjlbOV2hSXDEp9QGqwCDvBF4dzvW0G\n" +
        "E4wL8tqiyHb/NjU1WCTe3b6RibpC+gVMXQo8jWVm9LwVyBn6BHQExRrQfLKrLPjD\n" +
        "1Y4O9ynHNFcJXi3zrGdWGlGtbS4NuH9SQtS9dWGEeu1FEFDDEppDeQhtKQc8XoxB\n" +
        "W/TS7x9WyRtJidblvZmTSBkiov7oilzc8C6eqz/IgKnVwrsrg/N4xitE/Qq7g1F+\n" +
        "vOYutmholRR+xYGhPUnWhQg=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_ROOT_REVOKES_A =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0IFJvb3QX\n" +
        "DTI2MTExNjAzMjk0OVoXDTM2MTExMzAzMjk0OVowFTATAgIQABcNMjYxMTE2MDMy\n" +
        "OTQ5WqAvMC0wHwYDVR0jBBgwFoAUB3xCmLhsXHbXCPlqsuujYitgt0QwCgYDVR0U\n" +
        "BAMCAQIwDQYJKoZIhvcNAQELBQADggEBACa8+FD9AJXMrEmtwfuwNvFYQ/kPNxRc\n" +
        "mkCSCJp9nUQ/wKU3LECpKnT6tb/mP8OkAS1xFgn1960vqr1Oh23WRhjX2xOVaYvW\n" +
        "mOPwl7MQUu8sozDd/o55QyqQ0bfydVEsf59R+Q03TRuIY34piGt15GsYodlDQiC+\n" +
        "47jyKfYdsojwZ+q6teRWexizK0PwEXtctSOELlgCVH23LBiWKorEFjuGXHMK37BB\n" +
        "ox10jyw6dKCGa4Gv4BrVvemWNQonwghl6zGBJH/hpIsDoPIinvTcZv8EqQ2TP8xW\n" +
        "3qYp+U7eQp9tA69caU6ZW6bgHvnbswVJ/fgvRZMexo7y9LfzlIrO5S4=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_REVOKES_ONE =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0IENBIEEX\n" +
        "DTI2MTExNjAzMjk0OVoXDTM2MTExMzAzMjk0OVowFTATAgIQARcNMjYxMTE2MDMy\n" +
        "OTQ5WqAvMC0wHwYDVR0jBBgwFoAUh4HusztVUoIy17NdiLsFE1bsMf0wCgYDVR0U\n" +
        "BAMCAQEwDQYJKoZIhvcNAQELBQADggEBAKT8ifl0DRWw0VMf5XoJBpJDb5CgJbGm\n" +
        "v5pX3Hj8INfVJAlisBZA+FN/Zri2sc4hPOF7g4yNw/G7vjT0FFB5LTvAxkN2OrCz\n" +
        "Yd08e5ItXxU2+un1LAVySgVkyaSSec3f9mgnKnt1vSDft4MUn8P5rKPH/6zDY7Ss\n" +
        "pLevu2Rs5Gd2JeWIf8O8teIDvH2kYe74r+w+v3/fR9Q7qIeSCuPI+9YD96nEOdE8\n" +
        "NQQ7a8onjWE76U8g57DqZaans6V6Xo5t0cPnV3cx99RkkENHAJaabID39TlHX+2l\n" +
        "IkKf6zN7vM8jiwoMJ448/+AFdESp7ZKlomm6S+ftSeIJlGO9p0utuU0=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_REVOKES_ONLY_GOOD =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0IENBIEEX\n" +
        "DTI2MTExNjAzMjk0OVoXDTM2MTExMzAzMjk0OVowFTATAgIQABcNMjYxMTE2MDMy\n" +
        "OTQ5WqAvMC0wHwYDVR0jBBgwFoAUh4HusztVUoIy17NdiLsFE1bsMf0wCgYDVR0U\n" +
        "BAMCAQEwDQYJKoZIhvcNAQELBQADggEBAALjRSu+wPEdA+ET7fUUIgK3NpMo15gc\n" +
        "Dp5jhKwuG40LeNMMArNgHd+faFGsaDJmzGt8WTH9UuGg5oSXDIu3+t7MHTP6FE9C\n" +
        "U0gEPfRnpGo1gc+ultP3xk+M0peRZD4mmKvFI6szPtPP4F8XHQzpM7FWq+ltkM2O\n" +
        "KniphddhyidNmsY+bhKG4CRgCI7EXQfD+aoFCWCse8Aq50T6RsnMfjVxtL1rstf0\n" +
        "taRN1GIuKrD7wog0SZ6/BrMtByDiYzAy5L1B3kGGAwQ0+1sPnkmnHVFyLtK4/2Hv\n" +
        "9VeZB6XtavsfBI32MSxqCWLtsXPFwwms8FXoVXSPTGb9w5ZrnpWyI5Y=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_REVOKES_BOTH =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBujCBowIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0IENBIEEX\n" +
        "DTI2MTExNjAzMjk0OVoXDTM2MTExMzAzMjk0OVowKjATAgIQABcNMjYxMTE2MDMy\n" +
        "OTQ5WjATAgIQARcNMjYxMTE2MDMyOTQ5WqAvMC0wHwYDVR0jBBgwFoAUh4HusztV\n" +
        "UoIy17NdiLsFE1bsMf0wCgYDVR0UBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAEgo\n" +
        "8zgc3yiVGjieWKZBuUuH+djm/352cQ0EAkqzR2nPgpoHbgPn1Vd13d3nStDJevlQ\n" +
        "OhQFjZPCyeTIFATv0D8E4qfXtEb4YimKgQtyLg34fXZrlWBTeq6EowkkxmtpTNis\n" +
        "d/Is1OjvBUKfTF1Q4k8eTjv+yjT5ws71UGTUbjKH207FK/fXfNt+83jUIrzCid69\n" +
        "z+DMRMw4wntYdjs+u1DQWTIyY3BqybIgOauvHLR9EcTUk+0IxYSWjafc+kzmOwr7\n" +
        "ZTFbAVK2Cf9NK3RUr22Jn9kerkqp2p9VgjLXt5E4+/6IGehx4gvHakJ400CUPhEh\n" +
        "x8pQj+pAZnLaj827Pq4=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_B =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBjTB3AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQhcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WqAvMC0wHwYDVR0jBBgwFoAUS6uG\n" +
        "Bj6YaRYo0yJsmMd+KrOgxpowCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADggEB\n" +
        "AClNo1bqKHNbgJQ6+BfsDh8VWKVvIy2DV7odFVjoCdOdzzhmvoUEORlZjtAZrfe5\n" +
        "QBiKXih55v4jXWVcUoAoSSiuyoSLbiyAdlOtpfXO2rNuW+3z2oCUhDOKrpEGao+4\n" +
        "+DoyTGOFqWHBt5zdyaJoxPQ98ClfH9pPkVzmd81JK1k0enuUMcZZvs93wj8KQ3/3\n" +
        "15PslYtd4FQ6B6HnIGKptfZbbvJIBDI+66mgGHOYWIYuTlscoHP5Kr/wBoRR3aqw\n" +
        "R5uey2tkGrzHev0T67ghMKyIHpLHM5uxkrQYwCnTVVfAlbUPvPsYTCOGZqhnAIUl\n" +
        "OaHfIbHIcRxLSXugdJl3PbY=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_BY_IMPOSTOR =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBjTB3AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQRcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WqAvMC0wHwYDVR0jBBgwFoAUkS58\n" +
        "ojntf64xKQG8E0MtTkjrVk8wCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADggEB\n" +
        "AG2OcAiode2C+Tqc9ewdyvRtI/TQd9oW5YuBOJzPE1bi1bAYmQlvoOlCJ8F38JhY\n" +
        "M4enPzUMEWZfkcKmDBb1IZeitZXcX3mU4W8ZJO+wQqYh3AaT9NNqxObvDEgx2/oU\n" +
        "DgjDqb0EUJX+9Y5Ob9ErC4IDRmyXSWaOOUYUy5Kne3Q0woaD2qkGYqZ2wk/FLIHv\n" +
        "fJO21Ku+g0T4n/XpAjNqwAUw6IPx/+ChvqFy7q61oBw65VszmTj8f1FWzUEqPBf8\n" +
        "UwLnoPW39LR000vrXRxUmnU+uD74bRWpUGcQ8QDcchgVBgR/HnfCsh0r+la7mKRj\n" +
        "HE6R195IA01RC1JoFeec8io=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_CRITICAL_UNKNOWN =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBkjB8AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQRcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WjAVMBMCAhABFw0yNjExMTYwMzI5\n" +
        "NDlaoB0wGzANBgQqAwQFAQH/BAIFADAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsF\n" +
        "AAOCAQEAJcrVbedGiY+Z5yWsWuJHIboBQky2qhiiqnPwsQ1AtuMmfRcveqoEzrNT\n" +
        "t2KeeZL+sbOmHpdJToyY43V1q7CSAYy9ggkgh6r/OsNVS7+U73MB1b8LhJtWgAZJ\n" +
        "rY502GYO4zcyBo2i/EF+hVm01F27tLdZygKY4Pi1wnICvkEIZJMNB4FxFC7o4dBV\n" +
        "p/xSPqTxWHwLrenfi82i2FBpPfw/CsmaFY2SOYQLc+mGnEuClly5+Pc1CK5ZK27b\n" +
        "a+gnbDost40oPFLphKqQMsBLVejGeBPr/wU9ZlAtlSVwY57K2hzthSY09sdiR1DD\n" +
        "AxSHd3Zlh0K6BfjWbzM5aYV4pGQV4A==\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_IDP_ONLY_CA =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBlDB+AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQRcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WjAVMBMCAhABFw0yNjExMTYwMzI5\n" +
        "NDlaoB8wHTAPBgNVHRwBAf8EBTADggH/MAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEB\n" +
        "CwUAA4IBAQBYjYSMXDIGR4g7DZzLsI/eVLZtTd7SJVfikN3Y49srwSoKbyGS6giK\n" +
        "migT2TlCSKdoFYLg40yiqZ6PhBGrx0IbODikJ2WszwrncBy85zSWf4rsltKTOtfU\n" +
        "6JN/wgnYjSnhjrh+NdLo1BTAyfZYnuDrSwVU1S6RrB0OegvrSAXfjdfo0Nf2Nxdz\n" +
        "sCM2NgIcbHmKeelGRGAliS0CIRJn2Zb3Wo3DUBKdIv7llIdk5/J7mgbuQJ6bMhzB\n" +
        "78MxQ6Nax+5IvTaZohBAOKJVVNgrcUUcbgF76GSd+SVkeI1eiFDwRlDziGseTuUK\n" +
        "MGlvyUsDZy8X6oGmHdo3KChFcuj0uMBa\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_IDP_ONLY_USER =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBlDB+AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQRcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WjAVMBMCAhABFw0yNjExMTYwMzI5\n" +
        "NDlaoB8wHTAPBgNVHRwBAf8EBTADgQH/MAoGA1UdFAQDAgEEMA0GCSqGSIb3DQEB\n" +
        "CwUAA4IBAQB/hQYHGzRsB95ScTKP8A76kaOSRDE+r1unz5cVKUTpoZjT3UVaHSoV\n" +
        "YE45Yqy8kaU94KcIdiExa+bOXp0QYIakyAL4ss+P/rBz37g5JkmjMUQK9MG+8JOV\n" +
        "h0+BBe7CDGwzGnG7WK3D8Rs9G8AvXUCSetri2BgX9zW+IIMM3H4kZyhWfYrVF4ZN\n" +
        "WX2AObnJAWPSElmMmK8f+TupqPwJPb1JgTGY+G4cSMOXd28oIDRqm52BTJ6nl3XR\n" +
        "tg+46WiQEIFgZZmAlqBSe1HUCRIRWeGRTfdP8NgxhrmD6rQx6WCs0Rq6jIM12Ket\n" +
        "KxBd5NCDqXOfAqe6K7kYVt0HtSkmo077\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_IDP_SOME_REASONS =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBlTB/AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQRcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WjAVMBMCAhABFw0yNjExMTYwMzI5\n" +
        "NDlaoCAwHjAQBgNVHRwBAf8EBjAEgwIGQDAKBgNVHRQEAwIBBTANBgkqhkiG9w0B\n" +
        "AQsFAAOCAQEAcV+CkUsMO/reUb2XcP3qCDcwdWy52XY+ujKpzWDZYfOLp6hpyZhF\n" +
        "RXJxcw0ZrybSuWKjFN18g5DbPKGsXu5i+s3REn0CODrJ296OxoI1S+cNpIlKxfd0\n" +
        "U0CcI2brJVTf5X9gm4vFkbN929CG2WjNsGvOKxU87jijPS7I67cMSkckFP8kmorc\n" +
        "tuauSktRa/KDsKiOuSnCFs/qZm+v2cEn7vpPS57xJczp1vnxsNuHmGNvqWErAedf\n" +
        "9Xemm9JdGcQ8k+aEyRTsdOyg0OYbgKUrlgH/+WwuQX0F11/4sWv1CCPqef4qFDv5\n" +
        "RC/USdSZtgWHrjDG2yWviIFJS4vn3YEHgA==\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_FUTURE =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBkTB7AgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQRgP\n" +
        "MjEwMDAxMDEwMDAwMDBaGA8yMTEwMDEwMTAwMDAwMFqgLzAtMB8GA1UdIwQYMBaA\n" +
        "FIeB7rM7VVKCMtezXYi7BRNW7DH9MAoGA1UdFAQDAgEHMA0GCSqGSIb3DQEBCwUA\n" +
        "A4IBAQAqaI6kB2Pn9HnChkE7m3joBkGLW6lQL266ro5pvN/lzS7sT54QDW28CSP5\n" +
        "ZqfMs9Iq0jf/cL34QFUT86rqk/c97X9k+lXhsjxGPL5nuo4nm9QABKMfyzNEIrAw\n" +
        "3LEsZZ8wqUhGHdtWqpFP+w9ik16XpVD1m4ZYBiVuR5bR5qVr3sTbGb64qCdF5DuJ\n" +
        "OFJae/9+A8PVWG4AUXJZnhTSxUcWKwxrV4YNaJeCVfINGh/vriZ1fOxjfTUVew8X\n" +
        "H4besXqXefIjC4he5SGEJAvclXxGI9mkANRS82mqbp3F9y1nQtJmm3AOp/tN0CcE\n" +
        "zGYitR8j705KhhoAy6Byn/51JLHw\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_B_DELTA =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBezBlAgEBMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCVRlc3QgQ0EgQhcN\n" +
        "MjYxMTE2MDMyOTQ5WhcNMzYxMTEzMDMyOTQ5WqAdMBswDQYDVR0bAQH/BAMCAQEw\n" +
        "CgYDVR0UBAMCAQIwDQYJKoZIhvcNAQELBQADggEBAB8OOwTEBJCTs9OVX6RGVh5p\n" +
        "NPck1snSeLIxeRVJfCZTgdiV3YiJnKl+ssyyWG85/LvYPWNOnKsN/JaQuiSuF3rx\n" +
        "QNbnHBXxOnSmAdJ01QNRy/GLXlTzLboap8Aq2lL+DUlTGoVO2G8eUlb9UefyXL3V\n" +
        "dGHlQfLKuTjV1TL3sON/WdDcd8N4uM+vWlKYq5DZFwB1t0AKIN3Q6dSNdCtGjsHF\n" +
        "c/IKZOVRZVbJZR5BikgDv/K33yaMf65zHTCFEdAqC/6kjdSlglV4N2vx73SamGmf\n" +
        "b3iYl8iV5WIR61jTk1Pe+QICUn1fwgH0DLu6iw3QQz0g/kpDOF645SPEzxcRtp0=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CA_S =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC7DCCAdSgAwIBAgICEAMwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVz\n" +
        "dCBSb290MCAXDTI2MTExNjAzNTU0OFoYDzIxMjYxMDIzMDM1NTQ4WjAYMRYwFAYD\n" +
        "VQQDDA1UZXN0IFN1YiBDQSBTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
        "AQEA32Fut2fcdY6a5HZ/x1U0fko6iomZGbzvd5ZKp9zGQxIfETC4Jn+zByugF7hO\n" +
        "hjdbnWaynRYhYDnU6yorb5CJaQds7WOmzAXy4NqkdL/S+ZgVng3am6YkGcWklEPJ\n" +
        "JrF4puzJQXtD/oFCizI2sO/+3kCLNLTyTQrIDw4HdXQp7V9kW5JqHMWt3YcsSIm5\n" +
        "HXaJ7EDBKeXYMCb4p8qBTEL93n5xLO+WRhoSGU8rQPbXPsjHtiFszUPxCXv2fiv2\n" +
        "BN0hE7Td7FwSUvMuwgTuhherLuIrxTLWYtJTIH2Vteczv8h/5VOlb5fYQjNthheh\n" +
        "ADGmPahs0ilHqy8OXZg2WLUoSQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
        "A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUTAv14oLk3EToqy5+WfEHzeua26wwDQYJ\n" +
        "KoZIhvcNAQELBQADggEBAHkh8cMjG3A3319Wl6QvYADepX2D775/cJUBfpb3jZTQ\n" +
        "0++9IaeIPQZVo5fk9JlJdRR5DkC13qxRhEgxoX7yffnuF909jNz5RyxN3jfLfCtS\n" +
        "RSbnNpdQYYE4shFtX6oOrlE/eGnmQla4HHSSI8GvI2HnaBqStAvPXHugIV0uKSGU\n" +
        "pKmjdEINCqczolr6Wbk42R+IZ4w+lzWk13ZmzbE9HXcmEVPx87y0t3P20nTVaPNV\n" +
        "s+zOlZnHiXecaUmNmDtnXjNL2BCN8hYaIj6k3KrcmRao35LaqLLG5HIkbvyE+r8R\n" +
        "cgpOjoEtjfQ6UJbOaZaeawEpgENimALc+0l5MugQ61k=\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_I =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC9DCCAdygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAwwNVGVz\n" +
        "dCBTdWIgQ0EgUzAgFw0yNjExMTYwMzU1NDhaGA8yMTI2MTAyMzAzNTU0OFowHDEa\n" +
        "MBgGA1UEAwwRVGVzdCBJc3N1aW5nIENBIEkwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
        "DwAwggEKAoIBAQClkNjFt/O8CRX3LBv/UrSKLHYQ2eoYrB4lAY/szARU0Uc86FPR\n" +
        "aJZsQTV0f2gu5IhT2xu0vK3RX0v3U9qlT98Nx5vRxLeY9ElBizaOK/Oh0YcdwS72\n" +
        "2K9I2/elxM/QodrO/bP2Viwn1u/5Cn7ZGpjhRXTzy29fCeITdofdQBUP//PKmmr3\n" +
        "PogF4cEDs9jVaaEpivD6RdO/zBX48chq/MX03TXg2MUgq9XBNNtoxer7LTQk2Bf+\n" +
        "wbuvHXw1HphvVtlhffrb9H2kqHfX7AJl2Y6ywyiP0Ex23QQRd2/0BWjCGrdf6f6w\n" +
        "TxVQ2XUIuzZWIYvZQpPHZS19JKiTpqLMbIZPAgMBAAGjQjBAMA8GA1UdEwEB/wQF\n" +
        "MAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSrFKMZdTgYh9yA/nxHfZHd\n" +
        "vSVLLjANBgkqhkiG9w0BAQsFAAOCAQEAWp8OyVIIZQ/1R0Ywr3LX//7SkZ938DAK\n" +
        "Zfivwa+cYWt8DcJLW0ZnleU2u5oKL9Qb4SXL5LakNiMqWn1jdN8Tp+WmY27EuPHk\n" +
        "fQcRVeObLZ522swLfIHD4Gek3TuO7rrDJQGscbmFowyzS6tC3JLbzqu3blda5sr6\n" +
        "6TYwEAIaU59z5keewQmGitD9f/KqVQY6hFWN4P1MefDArWbQq2ulz+OKfN0C6j4V\n" +
        "XDzYDbSJ0wLqRFEwPBS8NxUG4BowDI6tQqIfNaOUpx0Pi87VPao/fN7G3MWg3CVe\n" +
        "0SXkBGW58cz7V6edtAMpewOP/Q26uBKI2ejqUTyxhzBbEShr19M2vg==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_I =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIB+zCB5KADAgECAgIQADANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFUZXN0\n" +
        "IElzc3VpbmcgQ0EgSTAgFw0yNjExMTYwMzU1NDhaGA8yMTI2MTAyMzAzNTU0OFow\n" +
        "EDEOMAwGA1UEAwwFaWxlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYUgXU\n" +
        "tiZyOYJj2wKXvKmZcgVB0kn0Yn2WBiXIfANsBKJfSIw0OzccxGzWOOzxB8TMyEtR\n" +
        "LmNblmnblicGLTQ5ox0wGzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDANBgkq\n" +
        "hkiG9w0BAQsFAAOCAQEAjPBSXomrPTceFCCkioSYOJlLPxSL+z+r1tNtpH2l7f1Q\n" +
        "6r2aJVQu6QKFQ58gWM6xnWxOG/C+wxtvqHVwC+JKzZSQ/R+vzmhq5Uy8t94vvr3H\n" +
        "2f+SBiWwFtF6x/bUXZIIimEvM09DzGYSMPajvDf+6au1RysqRveuE8WILUARnhAO\n" +
        "oA5Tri4gBOuh8eVWxThSaj9gmnv1cjmCATVMRjvLQjeQCIst3EqkPk9tJrTjv04I\n" +
        "Wb55tmg+g+OOXeBUlkk2TsPwWStAbR9o2A43WKtWanTa+Fl1Olco3LXrP0ghfnvD\n" +
        "k0x4jfn+QtXnPoRZeeu1d2eyN5zfm8JmjHRXEBv8bQ==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_A_SECOND_CERT =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIC6DCCAdCgAwIBAgICEAQwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVGVz\n" +
        "dCBSb290MCAXDTI2MTExNjAzNTU0OFoYDzIxMjYxMDIzMDM1NTQ4WjAUMRIwEAYD\n" +
        "VQQDDAlUZXN0IENBIEEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4\n" +
        "NMXgFO60ZAzuItU77bV5p8BpLDW8X+0ieE3N6QU4HGCa/u5vgoex3JEuvVWTD9z6\n" +
        "if98Gu8bDuQLjSL7prv+l6DBfRd8sNXMPG4bMmb+OEy2SHEW4Gxgy1VHpvq/KnQU\n" +
        "30z51dySJ0xowFTZthK3giaQSWO1X3Zrb0boALaj3U0jrvbDerhZhdqTLbd+RRw6\n" +
        "eDHP+TId1QZ/9GMGBXUOof8WQQdrOtNQieBuoQ+aI2gIX5TCgHjMx4nbpibFWrUi\n" +
        "Kqdnqx/8bvYeVXkf4W/UAiZL+SuBijnoad8OF1s/BocEeIv00BmRVPhYjrEMRufk\n" +
        "lT1cyeKKU8RF/aLCVcD3AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n" +
        "AQH/BAQDAgEGMB0GA1UdDgQWBBSHge6zO1VSgjLXs12IuwUTVuwx/TANBgkqhkiG\n" +
        "9w0BAQsFAAOCAQEAVL2YRm/iuo2cqqAFwxfwpsjZqVm8iu3KF3cDJPjy3GAgE/3r\n" +
        "tNbCksb9lwoExt7jrC/Q7sdAP5SgMkxigNiTsCRGK/iF3Dv9mYtGoDU5wvvW9G0B\n" +
        "i36RlZvrza+SHV7akXY7lzcmZezr1AomHKKhYFVZcu0BosecP1RU1KLl3ZiECKTU\n" +
        "CExhcFHM/tzffQdpu8qStUBJCGo6ppNwf1TE0B1FMWw01tTrodmkjJ6oMpDUccUN\n" +
        "hDOg/r5v1dLzXejJ6a7+bZRWmTjug1cH/TUlrbRI1t0WI8F/RGrNWWi5dUCvNNUw\n" +
        "i5ZntAiWr0a+aiYolf1Sf41CmklvBpVivYGYpg==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CRL_I =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBlTB/AgEBMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNVBAMMEVRlc3QgSXNzdWlu\n" +
        "ZyBDQSBJFw0yNjExMTYwMzU1NDhaFw0zNjExMTMwMzU1NDhaoC8wLTAfBgNVHSME\n" +
        "GDAWgBSrFKMZdTgYh9yA/nxHfZHdvSVLLjAKBgNVHRQEAwIBATANBgkqhkiG9w0B\n" +
        "AQsFAAOCAQEAJ2lqYqLIGMmPKKCvlDfz0kCq9T+WQZOxHaOlJMjOlwF7gJaCoYQe\n" +
        "kkOCGQ3Rujb6ZUbZE7LLxFZaQZwMfyu3O00mo+lBNeubwCBunxIkq6fR0Df9hTnK\n" +
        "2Bh/65iouedoF9BuH8OH3/7AhQISoZrsADcSvGP6HrKGrhK4xNkXZqbD7bC0RITG\n" +
        "MFjWHnbT/dco3tmfb3EwdNWrwhrQg4IkJCVEEc33EwsIpVv07VG87Pa3cfkFm7tk\n" +
        "o27s0cQT2l4hOx1w+gAHgIsikx5NyIiAyp8dmet7xtfPMQ7T4rCjWGKlbrevh1Ra\n" +
        "N0USlvJXclOpVlDhcFJPKVCHR2E/pa3QaQ==\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_S =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBkTB7AgEBMA0GCSqGSIb3DQEBCwUAMBgxFjAUBgNVBAMMDVRlc3QgU3ViIENB\n" +
        "IFMXDTI2MTExNjAzNTU0OFoXDTM2MTExMzAzNTU0OFqgLzAtMB8GA1UdIwQYMBaA\n" +
        "FEwL9eKC5NxE6KsuflnxB83rmtusMAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEBCwUA\n" +
        "A4IBAQBcVuLomkP7ENSeaXK3k8KSkPM3Y22ab02MRcFZo130+msFDwUss9OkoLNb\n" +
        "fa6iIDMxlLBL8prk8zUMYdjQPH0mETMF4CngJOs1uTl014w02JtuJg9mS10q7A73\n" +
        "NZEbJbbKvJrABSLOVADu67thaqwfAnu8TlAMeHeMFDdqytln9e8E2cQ9jAnTGA9t\n" +
        "C+KqPjdVQYu1Fb+L0LRMSOcvYDPQYSNffoNDvQ6/zCQw/ryyJ0HL1jjia+5usNyq\n" +
        "3OEVO3sNIA3csAtafoylfWKnpYGtpqSXzp7Z5SVRC9q6g/lmxymNMFGjErwOnTLi\n" +
        "wgNgviVXKz03COPIlZJSJyhJmIHN\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_S_REVOKES_I =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBqTCBkgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1UZXN0IFN1YiBD\n" +
        "QSBTFw0yNjExMTYwMzU1NDhaFw0zNjExMTMwMzU1NDhaMBUwEwICEAAXDTI2MTEx\n" +
        "NjAzNTU0OFqgLzAtMB8GA1UdIwQYMBaAFEwL9eKC5NxE6KsuflnxB83rmtusMAoG\n" +
        "A1UdFAQDAgECMA0GCSqGSIb3DQEBCwUAA4IBAQBgAOnQxXr7Pfx8yeJh98nPnckG\n" +
        "RhAPxBpIIA4pmMmsKIgzZW+lEWZ9QO8v4OWTJWolzU7vqEcLXv3/1TG1bhGOTZpb\n" +
        "uHXGCJBXojQQ4b3PPP7hPgE8flAlOEnWy8UM0l0R675fXkuJizjs37iDUkn8b7k0\n" +
        "ORxXaQ6uqSQry6OkxkSDSvpTEfYXL2IoKuIyTXPzPO5bZ0fgmtXBvPK4YbjjTa+w\n" +
        "UIrh9plxa97znZuB9+c0iO0hhyZ8YApYlRL/DXtKy+qfgHeWUyFYAu0QTY4RJwki\n" +
        "6PC4DjomElzjSzsqI/aoC0dARuF4TLNI3Z1UPGSeWEqPMsKH/8cmXYx50w1F\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_ROOT_REVOKES_S =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0IFJvb3QX\n" +
        "DTI2MTExNjAzNTU0OFoXDTM2MTExMzAzNTU0OFowFTATAgIQAxcNMjYxMTE2MDM1\n" +
        "NTQ4WqAvMC0wHwYDVR0jBBgwFoAUB3xCmLhsXHbXCPlqsuujYitgt0QwCgYDVR0U\n" +
        "BAMCAQQwDQYJKoZIhvcNAQELBQADggEBAH0pmF1BgnF48n+kv+uXXDNjyG+Ne2f3\n" +
        "4W158LzFWVsKIlnbc/4sv1W0XB8oYPstjSlCPvovJcgvwHUzxB9p8wEPZn+RPfgQ\n" +
        "/S4qEEFiJGXi8NewYFLjrU5BeT9YAQO7inx3YkwfOpFHwAffKp41YjREbHnVAHxr\n" +
        "+wbzkyuuuSvW84LAI81cdjjCm8DubR6qcOEa3SpudoLO2EBTBTcfasD5n6cof1yE\n" +
        "OUP8GmcbF5V+V2FbFEk7Fn8tzlC2Xt8JHm2yhvGdQr/uPifkCUiXZDrKNeiPMPRc\n" +
        "5ZfHE6xwcklc9CwtI03y3k/eXrYZnoHlsp53HJlIWFxZSU7/MDpNC6Q=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_ROOT_REVOKES_A_SECOND =
        "-----BEGIN X509 CRL-----\n" +
        "MIIBpTCBjgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlUZXN0IFJvb3QX\n" +
        "DTI2MTExNjAzNTU0OFoXDTM2MTExMzAzNTU0OFowFTATAgIQBBcNMjYxMTE2MDM1\n" +
        "NTQ4WqAvMC0wHwYDVR0jBBgwFoAUB3xCmLhsXHbXCPlqsuujYitgt0QwCgYDVR0U\n" +
        "BAMCAQUwDQYJKoZIhvcNAQELBQADggEBAKU0iWQMp6usqrJcXcChgBlc5ef9DjnC\n" +
        "1mEC/9pTaPM37RIIHm30Nx6AY2Q6sU8QCOL7GmeApHghhfGkzsgNY6iCdwWtMOik\n" +
        "VNqhkCARItBEwsZ20rQmNdfjbpw4yHTOITgp1YW9fqUUok25UDncl+zanrsojo4/\n" +
        "aizLIcTBsL2sAbemRRvfnyocetxXvYMRfOXG1Ah5zIHUxItdMPscnt9t7pU37r+u\n" +
        "VK08rXk0Cm7IqxBQ8FAuq8inXu4qObTOKtciqPcdh5hzteSn8pDWHtdaQ5x6P4AL\n" +
        "7CE0RIAhOm662MfJ4/w8sxehP5lXvmfMKU6xQg8I7dV16vMckOarJt8=\n" +
        "-----END X509 CRL-----\n" +
        "";
}
