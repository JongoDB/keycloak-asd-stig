package mil.stig.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Decides whether a request path addresses the admin (master) realm, robustly: it works on the DECODED path segments
 * (matrix parameters already removed by JAX-RS), splits any segment that decoded to contain '/' or '\' (%2F, %5C),
 * drops empty and "." segments, resolves "..", and compares realm names case-insensitively. Anything it cannot
 * read confidently (a NUL or control character, a segment still containing '%', ".." above the root) counts as
 * guarded: default deny. Pure Java, no Keycloak types, so it is unit-tested on its own.
 */
public final class AdminRealmPathMatcher {

    private AdminRealmPathMatcher() { }

    /** @param decodedSegments JAX-RS getPathSegments(true) paths (matrix parameters excluded), in order */
    public static boolean guarded(List<String> decodedSegments, String adminRealm) {
        String realm = adminRealm.toLowerCase(Locale.ROOT);
        List<String> segs = new ArrayList<>();
        for (String raw : decodedSegments) {
            if (raw == null) {
                return true;
            }
            for (String part : raw.split("[/\\\\]", -1)) {
                if (part.isEmpty() || part.equals(".")) {
                    continue;
                }
                if (part.equals("..")) {
                    if (segs.isEmpty()) {
                        return true;               // climbing above the root: refuse
                    }
                    segs.remove(segs.size() - 1);
                    continue;
                }
                for (int i = 0; i < part.length(); i++) {
                    char c = part.charAt(i);
                    if (c < 0x20 || c == 0x7f || c == '%' || c == ';') {
                        return true;               // undecoded or unexpected form: refuse rather than guess
                    }
                }
                segs.add(part.toLowerCase(Locale.ROOT));
            }
        }
        int n = segs.size();
        if (n >= 2 && segs.get(0).equals("realms") && segs.get(1).equals(realm)) {
            return true;
        }
        if (n >= 2 && segs.get(0).equals("admin") && segs.get(1).equals(realm)) {
            return true;
        }
        return n >= 3 && segs.get(0).equals("admin") && segs.get(1).equals("realms") && segs.get(2).equals(realm);
    }

    /** For logs: the raw path with control characters replaced, at most 200 characters. */
    public static String printable(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < raw.length() && b.length() < 200; i++) {
            char c = raw.charAt(i);
            b.append(c < 0x20 || c == 0x7f ? '?' : c);
        }
        return b.toString();
    }
}
