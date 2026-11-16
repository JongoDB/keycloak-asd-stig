package mil.stig.keycloak;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Plain-Java test (no framework); exit 1 on any failure. IssuerCrlCheck: only the issuing CA's CRL decides, its signature is
 * verified once per file version, a refreshed file is re-read, and every failure refuses (fail closed).
 * Fixtures: an openssl test PKI (EC P-256, CAs valid 100 years, CRL nextUpdate 2036-11-13).
 */
public final class IssuerCrlCheckTest {
    static int failed = 0;
    static final long NOW = 1_800_000_000_000L;            // 2027-01-15, before every fixture CRL's nextUpdate
    static final long AFTER_NEXT_UPDATE = 2_200_000_000_000L; // 2039-09-18, after it

    static X509Certificate cert(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
    static Path write(Path dir, String name, String pem) throws Exception {
        Path tmp = dir.resolve("." + name + ".new");
        Files.writeString(tmp, pem);
        return Files.move(tmp, dir.resolve(name), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); // as crl-fetch swaps
    }
    interface Run { void run() throws Exception; }
    static void expect(String name, boolean allowed, Run r) {
        boolean got;
        String why = "";
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
        X509Certificate caA = cert(CA_A), caB = cert(CA_B), caC = cert(CA_C);
        X509Certificate good = cert(LEAF_A_GOOD), revoked = cert(LEAF_A_REVOKED), leafB = cert(LEAF_B), leafC = cert(LEAF_C);
        Map<String, X509Certificate> ts = Map.of(caA.getSubjectX500Principal().getName(), caA,
                caB.getSubjectX500Principal().getName(), caB, caC.getSubjectX500Principal().getName(), caC);
        IssuerCrlCheck.Signers truststore = p -> ts.containsKey(p.getName()) ? List.of(ts.get(p.getName())) : Collections.emptyList();

        Path dir = Files.createTempDirectory("issuer-crl");
        Path crlA = write(dir, "a.crl", CRL_A_REVOKES_ONE), crlB = write(dir, "b.crl", CRL_B);
        List<Path> both = List.of(crlB, crlA);

        IssuerCrlCheck.clearForTests();
        long v0 = IssuerCrlCheck.VERIFICATIONS.get();
        expect("valid card of CA A (CRLs of B and A listed)", true, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, both, truststore, true, NOW));
        expectEq("only CA A's CRL was signature-checked", 1, IssuerCrlCheck.VERIFICATIONS.get() - v0);
        for (int i = 0; i < 5; i++) IssuerCrlCheck.check(new X509Certificate[] {good}, both, truststore, true, NOW);
        expectEq("five more sign-ins verified no CRL signature again", 1, IssuerCrlCheck.VERIFICATIONS.get() - v0);
        expect("revoked card of CA A", false, () -> IssuerCrlCheck.check(new X509Certificate[] {revoked}, both, truststore, true, NOW));
        expect("revoked card of CA A, CA in the presented chain", false, () -> IssuerCrlCheck.check(new X509Certificate[] {revoked, caA}, both, truststore, true, NOW));
        expect("valid card of CA A, CA in the presented chain", true, () -> IssuerCrlCheck.check(new X509Certificate[] {good, caA}, both, truststore, true, NOW));
        expect("valid card of CA B", true, () -> IssuerCrlCheck.check(new X509Certificate[] {leafB}, both, truststore, true, NOW));
        expect("card of CA C, which has no CRL in the list (fail closed)", false, () -> IssuerCrlCheck.check(new X509Certificate[] {leafC}, both, truststore, true, NOW));
        expect("CA A's CRL past nextUpdate, abort-if-non-updated on", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, both, truststore, true, AFTER_NEXT_UPDATE));
        expect("CA A's CRL past nextUpdate, abort-if-non-updated off (Keycloak's semantics)", true, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, both, truststore, false, AFTER_NEXT_UPDATE));
        expect("a configured CRL file is missing", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, List.of(crlB, crlA, dir.resolve("gone.crl")), truststore, true, NOW));
        expect("a configured CRL file is not a CRL", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, List.of(crlB, crlA, write(dir, "junk.crl", "not a crl")), truststore, true, NOW));
        expect("no CRL signer certificate anywhere", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, both, p -> Collections.emptyList(), true, NOW));

        // CRL refreshed on disk: the next sign-in reads and verifies the new file (no cache clear needed)
        long v1 = IssuerCrlCheck.VERIFICATIONS.get();
        write(dir, "a.crl", CRL_A_REVOKES_BOTH);
        expect("after the refresh that revokes it, the formerly valid card", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, both, truststore, true, NOW));
        expectEq("the refreshed CRL was verified once", 1, IssuerCrlCheck.VERIFICATIONS.get() - v1);

        // a CRL named as CA A but signed by another key (impostor CA of the same name)
        write(dir, "a.crl", CRL_A_BY_IMPOSTOR);
        expect("CRL with CA A's name but a foreign signature (truststore signer)", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, both, truststore, true, NOW));
        expect("CRL with CA A's name but a foreign signature (chain signer)", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good, caA}, both, truststore, true, NOW));

        // two CRLs of the issuer listed: both must pass
        write(dir, "a.crl", CRL_A_REVOKES_ONE);
        Path a2 = write(dir, "a2.crl", CRL_A_REVOKES_BOTH);
        expect("two CRLs of CA A listed, the newer revokes the card", false, () -> IssuerCrlCheck.check(new X509Certificate[] {good}, List.of(crlA, a2, crlB), truststore, true, NOW));

        System.out.println(failed == 0 ? "all passed" : failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---- fixtures (openssl, see the class comment)
    static final String CA_A =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBbzCCARSgAwIBAgIUQRSPW9tbmFTaLDWKf0FN2VsKf0wwCgYIKoZIzj0EAwIw\n" +
        "FDESMBAGA1UEAwwJVGVzdCBDQSBBMCAXDTI2MTExNjAyMzMxNloYDzIxMjYxMDIz\n" +
        "MDIzMzE2WjAUMRIwEAYDVQQDDAlUZXN0IENBIEEwWTATBgcqhkjOPQIBBggqhkjO\n" +
        "PQMBBwNCAASFH8g6e/hy+5LcmHopamw8dQ2spMcAgLIF+vEEi23DMdADLKNtn3Nv\n" +
        "Ar81BOk3Jx+d6eR9z/ohThzZeBGbKqZho0IwQDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
        "A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUK8QKpc7CT11gmuQCK/iXhYw5HGEwCgYI\n" +
        "KoZIzj0EAwIDSQAwRgIhAOU5WtPhPaf4GV1IAuzfHbYH32Z0bFlubD1XP8+jMXuX\n" +
        "AiEA8zaX2GrojH31Wi+aJzEXZUbyB0UO7sB2wdfgqFlU6b0=\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_B =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBbTCCARSgAwIBAgIUXwFRxXXJo3vBkN1V+lELtwZRuBowCgYIKoZIzj0EAwIw\n" +
        "FDESMBAGA1UEAwwJVGVzdCBDQSBCMCAXDTI2MTExNjAyMzMxNloYDzIxMjYxMDIz\n" +
        "MDIzMzE2WjAUMRIwEAYDVQQDDAlUZXN0IENBIEIwWTATBgcqhkjOPQIBBggqhkjO\n" +
        "PQMBBwNCAASAvMlEfNK1wWduYe5A97+GsyD8U95WXsqyNmXDiEHwzLNGYe15rVCy\n" +
        "+8MoiOS7oY6H8NYwtwL6IBk4t9PSyVz3o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
        "A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU118kftS+A52IOHM8mrrgAiU0CMswCgYI\n" +
        "KoZIzj0EAwIDRwAwRAIgcQ5weFG/aFudeBJRu6G1w93tTPh/f00tffqYMJX0EOoC\n" +
        "IA6lv4VTz3qIo6a5pBgX1IjXH/8300aS9QYxv+36vmel\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_C =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBbzCCARSgAwIBAgIUOk6WnY7IyJBHvSwMGyCPDOj84oswCgYIKoZIzj0EAwIw\n" +
        "FDESMBAGA1UEAwwJVGVzdCBDQSBDMCAXDTI2MTExNjAyMzMxNloYDzIxMjYxMDIz\n" +
        "MDIzMzE2WjAUMRIwEAYDVQQDDAlUZXN0IENBIEMwWTATBgcqhkjOPQIBBggqhkjO\n" +
        "PQMBBwNCAARNMjSKQHPEx4Gg/voYejB5130Xd2ztzHhFBTGXGsAlwnwzlSpmrZzb\n" +
        "ixjCaa/cLF24IS2159SohBW3tadLPT5Jo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
        "A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUx7OMvWTKU4G+BISzHthSm/oytmwwCgYI\n" +
        "KoZIzj0EAwIDSQAwRgIhAKn415/KHEdOd3oDIS52JiP2gqIqAExHzi1YQK0h3+PV\n" +
        "AiEA9ZZQBQY9lO/muwNn6RnZghP5+v5WkS4sKbg90NJgEBk=\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CA_A_IMPOSTOR =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBbjCCARSgAwIBAgIUZxr8l8NpQkfwaQXegVExYUAbvvUwCgYIKoZIzj0EAwIw\n" +
        "FDESMBAGA1UEAwwJVGVzdCBDQSBBMCAXDTI2MTExNjAyMzMxNloYDzIxMjYxMDIz\n" +
        "MDIzMzE2WjAUMRIwEAYDVQQDDAlUZXN0IENBIEEwWTATBgcqhkjOPQIBBggqhkjO\n" +
        "PQMBBwNCAAQbo3Ucxo+Xovf/ALkjEGpL1VPaytg+99XoKjO5mR2RTu/BsRerLZj9\n" +
        "et0OX7CfnZRqsdcgwZGFHVgMMSGP6wRIo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4G\n" +
        "A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUvJxbJBDNI/oEKiXjiro1Z2tFkgUwCgYI\n" +
        "KoZIzj0EAwIDSAAwRQIhAL7i7FB0Pk1ZbNTAmrPJpHZMUZdV/46yVhVqNohMmQ6G\n" +
        "AiBEfoB69AtzQT2Opp9n7q/ZTTpAQUACAuYvWxDFrvwW7A==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_A_GOOD =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBMjCB2KADAgECAgIQADAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IENB\n" +
        "IEEwIBcNMjYxMTE2MDIzMzE2WhgPMjEyNjEwMjMwMjMzMTZaMA8xDTALBgNVBAMM\n" +
        "BGdvb2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASCv8Ybf9y/QvRyxbv0Hcbh\n" +
        "0Ao5K4xRtxeOhfVZ//0Kz2EKeoDrsKauADBRQRvKEj1ThZcxWlIJje1qhD8OTlap\n" +
        "ox0wGzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNJADBG\n" +
        "AiEAkYpJQF3VXZM+9P1gcJzHrRSqWAup84nDO5MXiYdy+wACIQCjIqEPRbIXaDIT\n" +
        "V1QCXVa5gMO+9UPmhQ/T0pWbhQsJeg==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_A_REVOKED =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBNDCB26ADAgECAgIQATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IENB\n" +
        "IEEwIBcNMjYxMTE2MDIzMzE2WhgPMjEyNjEwMjMwMjMzMTZaMBIxEDAOBgNVBAMM\n" +
        "B3Jldm9rZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ2e9f4yYL8f2WpG9Ma\n" +
        "RT6regAG71+oAlxbyn0R+YeJSnuR2MG0wO4UaXUpGpuER0R91qIMrbD2CelfW3/j\n" +
        "7FKqox0wGzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNI\n" +
        "ADBFAiB6QpCbGQ9Sszxh1Y3WXvW+fpadoAjg5ZapBgkaK4vlRgIhANh5Zi/QeeWW\n" +
        "ZPecwObzk6FWKqa7O70B/ad53CCgOArS\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_B =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBMzCB2aADAgECAgIQADAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IENB\n" +
        "IEIwIBcNMjYxMTE2MDIzMzE2WhgPMjEyNjEwMjMwMjMzMTZaMBAxDjAMBgNVBAMM\n" +
        "BWJnb29kMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq8w0S3N5+uXJXLvY68Lw\n" +
        "RFn4cwklYsE8G/FbeofFCXVLxwTxbg98m91bAywAx2VZOWKcfA1h6lmr0oJ69aP8\n" +
        "sKMdMBswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSQAw\n" +
        "RgIhAIBRBJx79xmjzTtMrpyXmezVDcJOhjq81+Pcwh1jFCwdAiEAolIfGfhi1DQr\n" +
        "O+Fq0eJcDkX3mkfPMnSyVcBSWSgGfIw=\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String LEAF_C =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBMjCB2aADAgECAgIQADAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlUZXN0IENB\n" +
        "IEMwIBcNMjYxMTE2MDIzMzE2WhgPMjEyNjEwMjMwMjMzMTZaMBAxDjAMBgNVBAMM\n" +
        "BWNnb29kMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElmHfxQi0Zk1c/gpcpM4N\n" +
        "22skGTexL8na+7Pk4FAzdZIjdQyF9dsfRPck0QOgoUibZ2qNnH/Dic4v9MOLdm9G\n" +
        "T6MdMBswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAw\n" +
        "RQIgDP5ejbeVS5cmeUze3GD/9zYPRRGZbTeUsX5jcrPyGHwCIQDKMVRqAk1c9iV8\n" +
        "SGu+czplXdh4FgX2eXMOA7ng7O0QYg==\n" +
        "-----END CERTIFICATE-----\n" +
        "";
    static final String CRL_A_REVOKES_ONE =
        "-----BEGIN X509 CRL-----\n" +
        "MIHCMGoCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBDQSBBFw0yNjEx\n" +
        "MTYwMjMzMTZaFw0zNjExMTMwMjMzMTZaMBUwEwICEAEXDTI2MTExNjAyMzMxNlqg\n" +
        "DjAMMAoGA1UdFAQDAgEBMAoGCCqGSM49BAMCA0gAMEUCIHBGRzMRLbNgOmGNL7yY\n" +
        "y7D7PA5Enu07PB4Ag/Jep+fNAiEAwwu2CJYcPQ0ppkr2gemob925PZiXfK4Va+Dx\n" +
        "DacfTfU=\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_REVOKES_BOTH =
        "-----BEGIN X509 CRL-----\n" +
        "MIHWMH8CAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBDQSBBFw0yNjEx\n" +
        "MTYwMjMzMTZaFw0zNjExMTMwMjMzMTZaMCowEwICEAAXDTI2MTExNjAyMzMxNlow\n" +
        "EwICEAEXDTI2MTExNjAyMzMxNlqgDjAMMAoGA1UdFAQDAgECMAoGCCqGSM49BAMC\n" +
        "A0cAMEQCIErQy3Nd1B36FiGxuG/EBDB7Sj378Utekn24sMqf4690AiBmt+k7Ca/7\n" +
        "/GJypyoI4+bpLNPlQWb+RfvhchIFoJGEVg==\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_B =
        "-----BEGIN X509 CRL-----\n" +
        "MIGsMFMCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBDQSBCFw0yNjEx\n" +
        "MTYwMjMzMTZaFw0zNjExMTMwMjMzMTZaoA4wDDAKBgNVHRQEAwIBATAKBggqhkjO\n" +
        "PQQDAgNJADBGAiEAm4ONZWzF9mJz47zxFI0k7MZapQ0K+5WqkJpWQnrmM9ICIQCY\n" +
        "gGFlCZLOkuxPUXusIggiiQRI6JV61ovDTd+XSOVV1A==\n" +
        "-----END X509 CRL-----\n" +
        "";
    static final String CRL_A_BY_IMPOSTOR =
        "-----BEGIN X509 CRL-----\n" +
        "MIGrMFMCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBDQSBBFw0yNjEx\n" +
        "MTYwMjMzMTZaFw0zNjExMTMwMjMzMTZaoA4wDDAKBgNVHRQEAwIBATAKBggqhkjO\n" +
        "PQQDAgNIADBFAiAk8x99qShlpp/8tK3RCVVAQuX8IloXG8ZMdRYvtZcfJgIhALfr\n" +
        "xYjqlxPmXNiBnTKQeMuzN4U/FBSi/rtkVGjTTYun\n" +
        "-----END X509 CRL-----\n" +
        "";
}
