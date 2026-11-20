package mil.stig.keycloak;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/**
 * No full EDIPI in the audit output: a card refused as revoked, or for an issuer the truststore does not know, must leave
 * no run of ten digits in the log lines or the exception message (the subject is CN=LAST.FIRST.MI.<EDIPI>). Fixtures: an
 * openssl test CA whose CRL revokes DOE.JOHN.Q.1234567890, and a self-issued ROE.JANE.A.2345678901 (no path). Run by build.sh.
 */
public final class EdipiRedactionTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean ok, String d) {
        run++; if (!ok) failed++;
        System.out.println((ok ? "PASS  " : "FAIL  ") + n + (ok ? "" : "  " + d));
    }
    static X509Certificate cert(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
    static final Pattern TEN = Pattern.compile("\\d{10}");

    public static void main(String[] a) throws Exception {
        // capture everything the logging backend writes (bound to these streams at its first use)
        PrintStream out0 = System.out, err0 = System.err;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        PrintStream cap = new PrintStream(buf, true, StandardCharsets.UTF_8);
        java.util.logging.Logger root = java.util.logging.Logger.getLogger("");
        List<String> jul = new ArrayList<>();
        root.addHandler(new java.util.logging.Handler() {
            @Override public void publish(java.util.logging.LogRecord r) { jul.add(new java.util.logging.SimpleFormatter().formatMessage(r)); }
            @Override public void flush() { }
            @Override public void close() { }
        });
        System.setOut(cap); System.setErr(cap);
        List<String> msgs = new ArrayList<>();
        X509Certificate ca = cert(CA), revoked = cert(REVOKED), stranger = cert(STRANGER);
        Path dir = Files.createTempDirectory("edipi-redaction");
        System.setProperty("jboss.server.config.dir", dir.toString());
        Path crl = Files.write(dir.resolve("ca.crl"), Base64.getDecoder().decode(CRL.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", "")));
        IssuerCrlCheck.Signers ts = new IssuerCrlCheck.Signers() {
            @Override public List<X509Certificate> named(javax.security.auth.x500.X500Principal p) {
                return ca.getSubjectX500Principal().equals(p) ? List.of(ca) : List.of();
            }
            @Override public List<X509Certificate> all() { return List.of(ca); }
        };
        boolean refusedRevoked = false, refusedStranger = false;
        try { IssuerCrlCheck.check(new X509Certificate[] {revoked}, List.of(crl), ts, true, 1_800_000_000_000L); }
        catch (GeneralSecurityException e) { refusedRevoked = true; msgs.add(e.getMessage()); }
        try { IssuerCrlCheck.check(new X509Certificate[] {stranger}, List.of(crl), ts, true, 1_800_000_000_000L); }
        catch (GeneralSecurityException e) { refusedStranger = true; msgs.add(e.getMessage()); }
        System.out.flush(); System.err.flush();
        System.setOut(out0); System.setErr(err0);
        String logged = buf.toString(StandardCharsets.UTF_8) + String.join("\n", jul);

        t("the revoked card is refused", refusedRevoked, "");
        t("the card of an unknown issuer is refused", refusedStranger, "");
        t("something was logged for them (the capture works)", logged.contains("STIG-CRL-"), logged);
        t("no ten-digit run in the log output", !TEN.matcher(logged).find(), logged);
        t("no ten-digit run in the exception messages", msgs.stream().noneMatch(m -> TEN.matcher(String.valueOf(m)).find()), msgs.toString());
        t("... while the last four digits stay, for the operator", logged.contains("******8901") || msgs.stream().anyMatch(m -> m.contains("******7890")),
                logged + msgs);
        t("redactEdipis: CN=DOE.JOHN.Q.1234567890 -> ******7890",
                AccountsPolicy.redactEdipis("CN=DOE.JOHN.Q.1234567890,OU=x").equals("CN=DOE.JOHN.Q.******7890,OU=x"), AccountsPolicy.redactEdipis("CN=DOE.JOHN.Q.1234567890"));
        t("redactEdipis: short numbers untouched", AccountsPolicy.redactEdipis("CA-99 serial 1000").equals("CA-99 serial 1000"), "");
        System.out.printf("EdipiRedactionTest: %d/%d passed%n", run - failed, run);
        if (failed > 0) System.exit(1);
    }

    static final String CA = """
-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIUfdTeGAeIfHzAhuJYIH33p53LV70wDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNVGVzdCBFRElQSSBDQTAeFw0yNjExMjAxNzU5NDZaFw00
NjExMTUxNzU5NDZaMBgxFjAUBgNVBAMMDVRlc3QgRURJUEkgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDDP88IekgTQy+PJd6CtuZLgCD3a/eE6BPc
bpWqXWnctwd612vM+rGf/gogejqqG5sla5dGlkqmGnhTq6KyBVxyG3zhtC+vWYtR
w7K8jBQvkM+LfeUgDCqbhAGK5qxpT9jiwp4hPlULjwRvYOucG94qUgf749KSOJVl
aIn7bTaJXgHR20Mycsj7vcW3SXC9+maC3H8QLdB9bGSHEf6x8JGpz51ePk8kwh7E
MrOOQ46bIS9xE+LE5mQrvUi6fv2IJkhvGDFTm+9S+AGkfyq3go8kye6opzzZo/L7
zp0M1thKjLBx9tCYJWeWtZVt9zYDRBqATmcGaxEMCbixWj8v4vAhAgMBAAGjQjBA
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBT6RZ6P
eCGs+JQq16d3qQYrvYJvzDANBgkqhkiG9w0BAQsFAAOCAQEABeDbhzPvZyp2sYll
ROamCAy8c9y0hvZRc6kBvmXmVAm9Lb+U1/oO87FJ0JhiVMSb0WMSdSRgVnM2JPSG
lczvEHc/NJrevoRqDZYCQPzTT7EdUgGJ4q+yB+yR0OEDaR3D/ypc7JxJB7ToI/uD
GarkO4JS7HwUFk84Ilda3BT8WzNals/nkX1F55p9CQOeMp5pWQX0XAHkzl6RRZRp
/1/tQ/88fUiXQZEuDtB2UkjE4wG9u/ivf/lxLoKgIawgm6iWW42+MY/Vdp2DblgC
j3PYlnH4vF2AQcMlO8mUvpHTbLYaM8yYs/EmmgIHawE4rn6KEyMpHxKhwTTJxPrB
zku9/Q==
-----END CERTIFICATE-----
""";
    static final String REVOKED = """
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4096 (0x1000)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Test EDIPI CA
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Jan  1 00:00:00 2045 GMT
        Subject: CN=DOE.JOHN.Q.1234567890
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit field, 128 bit security level)
                pub:
                    04:56:60:73:1e:73:81:62:c6:c7:7f:e1:b2:05:6b:5d:
                    e2:a1:4d:7a:68:1f:d5:5a:dd:4c:25:c5:d9:e7:ae:8d:
                    a2:ad:3e:44:08:cf:9c:42:31:ce:88:47:56:b7:44:15:
                    ea:56:59:5b:2b:77:a6:29:67:42:bb:7c:7e:75:8a:0a:
                    c4
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        16:82:79:54:e3:b3:92:8e:3a:fe:c1:84:0d:59:4e:cf:ae:20:db:c7:fa:26:29:ab:
        21:72:f4:5a:13:fd:a2:48:9b:c8:59:3b:71:7a:05:43:40:4f:94:0d:b8:96:72:d6:
        5a:7c:c7:a1:f8:a4:3a:a5:c4:05:16:89:01:2a:c6:76:0e:54:ec:ac:d9:d2:9a:a2:
        a4:92:77:60:ec:8a:c8:2c:61:c9:c0:16:70:b4:ff:4a:33:b7:86:f2:41:ae:63:a0:
        ed:d4:2b:f9:86:e9:a7:8c:a9:ff:fa:b2:9e:d6:fa:93:d9:4d:8d:c9:f9:8f:c9:79:
        3d:f6:7e:c7:3f:1e:d7:9f:db:6b:c8:53:45:db:64:5d:8e:ec:66:82:9f:64:11:20:
        97:19:9a:ad:e9:35:82:6c:67:14:0b:aa:1f:f1:02:6f:d4:0d:96:87:07:c9:ce:91:
        e5:07:60:64:85:64:3b:59:c0:36:f6:cc:73:4c:a4:5f:07:1b:e9:71:9b:3f:57:25:
        af:57:a8:e9:44:9d:61:09:9a:f9:a0:53:d0:d3:86:0c:4e:c6:4b:00:db:81:4b:b2:
        a1:cd:83:d9:2a:51:bd:f7:69:6b:fc:bc:95:4c:48:8f:be:25:e2:5c:a8:8b:a5:41:
        09:ab:0a:f5:49:bc:e7:33:87:a7:88:81:e9:37:46:8d
-----BEGIN CERTIFICATE-----
MIICDzCB+KADAgECAgIQADANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1UZXN0
IEVESVBJIENBMB4XDTI1MDEwMTAwMDAwMFoXDTQ1MDEwMTAwMDAwMFowIDEeMBwG
A1UEAwwVRE9FLkpPSE4uUS4xMjM0NTY3ODkwMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEVmBzHnOBYsbHf+GyBWtd4qFNemgf1VrdTCXF2eeujaKtPkQIz5xCMc6I
R1a3RBXqVllbK3emKWdCu3x+dYoKxKMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
JQQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAWgnlU47OSjjr+wYQN
WU7PriDbx/omKashcvRaE/2iSJvIWTtxegVDQE+UDbiWctZafMeh+KQ6pcQFFokB
KsZ2DlTsrNnSmqKkkndg7IrILGHJwBZwtP9KM7eG8kGuY6Dt1Cv5humnjKn/+rKe
1vqT2U2NyfmPyXk99n7HPx7Xn9tryFNF22Rdjuxmgp9kESCXGZqt6TWCbGcUC6of
8QJv1A2WhwfJzpHlB2BkhWQ7WcA29sxzTKRfBxvpcZs/VyWvV6jpRJ1hCZr5oFPQ
04YMTsZLANuBS7KhzYPZKlG992lr/LyVTEiPviXiXKiLpUEJqwr1SbznM4eniIHp
N0aN
-----END CERTIFICATE-----
""";
    static final String STRANGER = """
-----BEGIN CERTIFICATE-----
MIIBczCCARqgAwIBAgIURdmfqCovjRZhwxOooUbJZcS96X0wCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVUk9FLkpBTkUuQS4yMzQ1Njc4OTAxMB4XDTI2MTEyMDE3NTk0
NloXDTQ2MTExNTE3NTk0NlowIDEeMBwGA1UEAwwVUk9FLkpBTkUuQS4yMzQ1Njc4
OTAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEindZH+L6XjsAsIYqS2s02Wkf
oOSYfjsv9AWP1gvHfizrsmWJz2wQ22MdHoUX4pflyAQWP9N3NYi1eHQ9EGwWOKMy
MDAwHQYDVR0OBBYEFG8ry3XVvNj406odvRZgvJgQhv85MA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDRwAwRAIgeEqa5Lmtnt8HAznxA1BUi66zwDiIFRyXFGq9
tesyi0QCIFOk8KVWkpamPoZoS2d15/k2P9Lkm+XcTtUxZ1mHQUGu
-----END CERTIFICATE-----
""";
    static final String CRL = """
-----BEGIN X509 CRL-----
MIIBiDByAgEBMA0GCSqGSIb3DQEBCwUAMBgxFjAUBgNVBAMMDVRlc3QgRURJUEkg
Q0EXDTI2MTEyMDE3NTk0NloXDTM2MTExNzE3NTk0NlowFTATAgIQABcNMjYxMTIw
MTc1OTQ2WqAPMA0wCwYDVR0UBAQCAhAAMA0GCSqGSIb3DQEBCwUAA4IBAQALM2LJ
7TrfHZ6WxBkU9Mkmjd6SBtZCZAe7DxM7UQ/Z6vE0kCoX3mY8ocEUaysSKd4VpOVn
vStcFPfBHZbQzuyewTt6OKe3fVhhNBLdW8Km+5rDOJPQaMZZk5ke3kqOpafVxlJ2
Sng4naX2nMQjRcm9dsYW8u/ptR09L0Ctvny5i1UlzW5xWWm3TSC1/obqRu656dmU
bwTS75PzRt8FAf7x4bvBIisNZbuZ9wvTAjs8qekQAp7ID3Vo+7d8tWn93aVr4JkW
5DZyjKkZwu27WQZ51D/OP9hZMr15tdv606LDmbSkJxE7mPnPLwUWzN0bkLym9F11
klBucdu5K41WjLQg
-----END X509 CRL-----
""";
}
