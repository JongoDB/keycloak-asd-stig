package mil.stig.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Unit tests of the failed-passkey attribution helpers. Run by build.sh. */
public final class PasskeyAttributionTest {
    static int run = 0, failed = 0;
    static void t(String n, boolean ok) { run++; if (!ok) failed++; System.out.printf("%s  %-60s%n", ok ? "PASS" : "FAIL", n); }
    public static void main(String[] a) {
        String id = "aebfa4a6-ef07-45ac-bac4-c9e1e06ef6ac";
        String h = Base64.getUrlEncoder().withoutPadding().encodeToString(id.getBytes(StandardCharsets.UTF_8));
        t("user handle -> user id", id.equals(PasskeyAttribution.userIdFromHandle(h)));
        t("padded handle accepted", id.equals(PasskeyAttribution.userIdFromHandle(Base64.getUrlEncoder().encodeToString(id.getBytes(StandardCharsets.UTF_8)))));
        t("empty handle -> null", PasskeyAttribution.userIdFromHandle("") == null);
        t("not base64 -> null", PasskeyAttribution.userIdFromHandle("!!!") == null);
        t("a handle naming markup -> null", PasskeyAttribution.userIdFromHandle(
                Base64.getUrlEncoder().encodeToString("<script>".getBytes(StandardCharsets.UTF_8))) == null);
        t("an oversized handle -> null", PasskeyAttribution.userIdFromHandle("A".repeat(300)) == null);
        byte[] cid = new byte[32]; for (int i = 0; i < cid.length; i++) cid[i] = (byte) (i * 7 + 250);
        String posted = Base64.getUrlEncoder().withoutPadding().encodeToString(cid);
        String stored = Base64.getEncoder().encodeToString(cid);
        t("same credential id across base64url/base64", PasskeyAttribution.sameCredentialId(posted, stored));
        cid[0] ^= 1;
        t("a different credential id", !PasskeyAttribution.sameCredentialId(posted, Base64.getEncoder().encodeToString(cid)));
        t("null credential ids", !PasskeyAttribution.sameCredentialId(null, stored));
        t("garbage credential id", !PasskeyAttribution.sameCredentialId("%%%", stored));
        t("log-safe value", PasskeyAttribution.safe("a\nb<c>defghijklmnopqrstuvwxyz").equals("a?b?c?defghijklm..."));
        System.out.printf("%n%d/%d passed%n", run - failed, run);
        System.exit(failed == 0 ? 0 : 1);
    }
}
