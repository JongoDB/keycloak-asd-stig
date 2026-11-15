package mil.stig.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/** Pure helpers for naming the account a failed passkey assertion targeted (unit-tested without Keycloak). */
final class PasskeyAttribution {
    private PasskeyAttribution() { }
    private static final Pattern UUIDISH = Pattern.compile("^[A-Za-z0-9-]{1,64}$");

    /** The user id a WebAuthn userHandle (base64url, as the browser posts it) names, or null. Keycloak's user handle
     *  is the user id's UTF-8 bytes. Anything that is not a plausible id is ignored - it is attacker-supplied. */
    static String userIdFromHandle(String handle) {
        if (handle == null || handle.isBlank() || handle.length() > 200) return null;
        try {
            String id = new String(Base64.getUrlDecoder().decode(handle.trim()), StandardCharsets.UTF_8);
            return UUIDISH.matcher(id).matches() ? id : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Whether the credential id the browser posted (base64url) is the stored one (Keycloak stores standard base64). */
    static boolean sameCredentialId(String posted, String stored) {
        if (posted == null || stored == null || posted.isBlank() || stored.isBlank()) return false;
        try {
            byte[] a = Base64.getUrlDecoder().decode(posted.trim().replace('+', '-').replace('/', '_').replace("=", ""));
            byte[] b = Base64.getUrlDecoder().decode(stored.trim().replace('+', '-').replace('/', '_').replace("=", ""));
            return java.security.MessageDigest.isEqual(a, b);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** A short, log-safe prefix of an attacker-supplied value. */
    static String safe(String v) { return safe(v, 16); }
    static String safe(String v, int max) {
        if (v == null) return "-";
        String s = v.replaceAll("[^A-Za-z0-9_=+/-]", "?");
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
