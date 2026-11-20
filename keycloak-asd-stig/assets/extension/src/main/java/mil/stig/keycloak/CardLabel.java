package mil.stig.keycloak;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * What an audit record shows for a card whose identity is an EDIPI: "card:******7890#1a2b3c4d" - the last four digits and
 * an 8-hex keyed hash, so repeated attempts by the same card can be correlated across events without the number ever
 * being written. The key is a DEDICATED subkey, HMAC-SHA-256(realm's active HMAC key, "stig-card-label-v1"), so the
 * realm's token-signing key is never used directly for this. Activating a new HMAC key in the realm changes every tag:
 * correlation holds within one key's lifetime only. Without an HMAC key in the realm: the masked part only. The hash is
 * short on purpose: it correlates, it does not identify (2^32 values over a 10^10 space).
 */
final class CardLabel {
    private CardLabel() { }

    static String of(KeycloakSession session, RealmModel realm, String identity) {
        String masked = "card:" + AccountsPolicy.redactEdipis(identity == null ? "?" : identity);
        byte[] key = key(session, realm);
        return key == null ? masked : masked + "#" + tag(subkey(key), identity);
    }

    static final String SUBKEY_LABEL = "stig-card-label-v1";

    /** The dedicated subkey: HMAC-SHA-256(realm key, "stig-card-label-v1"). */
    static byte[] subkey(byte[] realmKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(realmKey, "HmacSHA256"));
            return mac.doFinal(SUBKEY_LABEL.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The first 4 bytes of HMAC-SHA-256(key, "stig-card:" + identity), hex. */
    static String tag(byte[] key, String identity) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] d = mac.doFinal(("stig-card:" + identity).getBytes(StandardCharsets.UTF_8));
            return String.format("%02x%02x%02x%02x", d[0], d[1], d[2], d[3]);
        } catch (Exception e) {
            return "nohash";
        }
    }

    private static byte[] key(KeycloakSession session, RealmModel realm) {
        try {
            for (String alg : new String[] {Algorithm.HS512, Algorithm.HS256}) {
                KeyWrapper k = session.keys().getActiveKey(realm, KeyUse.SIG, alg);
                SecretKey sk = k == null ? null : (SecretKey) k.getSecretKey();
                if (sk != null && sk.getEncoded() != null) return sk.getEncoded();
            }
        } catch (RuntimeException e) {
            // no HMAC key: masked only
        }
        return null;
    }
}
