package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.List;

/**
 * Strict allowlist for paths served to untrusted (network) clients. Works on the RAW request path, before any
 * decoding, and fails closed:
 *  1. refuse any raw path containing '%', ';', '\', "//", a "." or ".." segment, a control character, whitespace,
 *     or any byte outside printable ASCII;
 *  2. then allow only exact entries and prefixes from the configured list (an entry ending in '/' is a prefix,
 *     anything else must match exactly), compared byte for byte;
 *  3. everything else is refused.
 * With the list naming one realm (e.g. /realms/example/, /admin/example/, /admin/realms/example/, /resources/),
 * the master realm and any realm added later are unreachable from the network by construction.
 */
public final class PublicPathPolicy {

    private final List<String> exact = new ArrayList<>();
    private final List<String> prefixes = new ArrayList<>();

    public PublicPathPolicy(List<String> entries) {
        for (String e : entries) {
            String s = e.trim();
            if (s.isEmpty() || !s.startsWith("/") || !wellFormed(s)) {
                continue;                     // a malformed entry allows nothing
            }
            if (s.endsWith("/")) prefixes.add(s); else exact.add(s);
        }
    }

    public boolean isEmpty() {
        return exact.isEmpty() && prefixes.isEmpty();
    }

    /** True if a network client may request this raw (undecoded) path. */
    public boolean allows(String rawPath) {
        if (rawPath == null || rawPath.isEmpty() || rawPath.charAt(0) != '/' || !wellFormed(rawPath)) {
            return false;
        }
        if (exact.contains(rawPath)) {
            return true;
        }
        for (String p : prefixes) {
            if (rawPath.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    /** Printable ASCII only, none of % ; \ or space, no empty / "." / ".." segment. */
    static boolean wellFormed(String raw) {
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c <= 0x20 || c >= 0x7f || c == '%' || c == ';' || c == '\\') {
                return false;
            }
        }
        if (raw.contains("//")) {
            return false;
        }
        for (String seg : raw.split("/", -1)) {
            if (seg.equals(".") || seg.equals("..")) {
                return false;
            }
        }
        return true;
    }

    /** For logs: control characters and non-ASCII replaced, at most 200 characters. */
    public static String printable(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < raw.length() && b.length() < 200; i++) {
            char c = raw.charAt(i);
            b.append(c < 0x20 || c >= 0x7f ? '?' : c);
        }
        return b.toString();
    }
}
