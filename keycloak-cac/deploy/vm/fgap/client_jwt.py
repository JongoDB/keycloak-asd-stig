"""Client authentication with a signed JWT (private_key_jwt, RFC 7523), for the tests that sign in as a delegate that
uses client-jwt. ES256 (EC P-256) or RS256. The key id is the key's RFC 7638 thumbprint, so a JWKS built with jwk() and
an assertion built with assertion() always agree. Needs the `cryptography` package (only when a test uses it).

  form = {"grant_type": "client_credentials", "client_id": cid, **client_jwt.form_fields(key_file, cid, issuer)}
"""
import base64, hashlib, json, time, uuid


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _key(key_file):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(open(key_file, "rb").read(), None)


def jwk(key_file):
    """The public JWK (with kid = RFC 7638 thumbprint, alg and use) of the PEM private key in key_file."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    k = _key(key_file).public_key()
    if isinstance(k, ec.EllipticCurvePublicKey):
        n = k.public_numbers()
        core = {"crv": "P-256", "kty": "EC", "x": _b64(n.x.to_bytes(32, "big")), "y": _b64(n.y.to_bytes(32, "big"))}
        alg = "ES256"
    elif isinstance(k, rsa.RSAPublicKey):
        n = k.public_numbers()
        core = {"e": _b64(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big")), "kty": "RSA",
                "n": _b64(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big"))}
        alg = "RS256"
    else:
        raise ValueError("an EC P-256 or RSA key is required")
    kid = _b64(hashlib.sha256(json.dumps(core, separators=(",", ":"), sort_keys=True).encode()).digest())
    return dict(core, kid=kid, alg=alg, use="sig")


def assertion(key_file, client_id, audience, lifetime=60):
    """A fresh client assertion (unique jti, so it can never be replayed) for client_id, audience = the realm's issuer."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    pub = jwk(key_file); key = _key(key_file); now = int(time.time())
    head = {"alg": pub["alg"], "typ": "JWT", "kid": pub["kid"]}
    body = {"iss": client_id, "sub": client_id, "aud": audience, "jti": uuid.uuid4().hex, "iat": now, "exp": now + lifetime}
    si = (_b64(json.dumps(head).encode()) + "." + _b64(json.dumps(body).encode())).encode()
    if pub["alg"] == "ES256":
        r, s = decode_dss_signature(key.sign(si, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = key.sign(si, padding.PKCS1v15(), hashes.SHA256())
    return si.decode() + "." + _b64(sig)


def form_fields(key_file, client_id, audience):
    return {"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(key_file, client_id, audience)}
