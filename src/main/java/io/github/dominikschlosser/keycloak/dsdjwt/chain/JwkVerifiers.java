/*
 * Copyright 2026 Dominik Schlosser
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.dominikschlosser.keycloak.dsdjwt.chain;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

/** Turns a JWK into a signature verifier for one JWS algorithm. */
public final class JwkVerifiers {

    /** The JWS algorithms the extension accepts. RFC 9901 §7.1 step 2 forbids none. */
    public static final Set<String> ALGORITHMS =
            Set.of("ES256", "ES384", "ES512", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    private static final String THUMBPRINT_URI = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
    private static final int MIN_RSA_BITS = 2048;

    private JwkVerifiers() {}

    /**
     * Builds a verifier for a JWS with the given header alg. Keycloak's own converter leaves the
     * algorithm empty when the JWK has no alg member, and its JWS check then fails. A cnf key often
     * has no alg, so the algorithm comes from the curve or, for RSA, from the header.
     */
    public static SignatureVerifierContext forKey(JWK jwk, String headerAlg) throws ChainException {
        if (headerAlg == null || !ALGORITHMS.contains(headerAlg)) {
            throw new ChainException("the JWS algorithm " + headerAlg + " is not accepted");
        }
        String alg = algorithmOf(jwk, headerAlg);
        if (!alg.equals(headerAlg)
                || (jwk.getAlgorithm() != null && !jwk.getAlgorithm().equals(headerAlg))) {
            throw new ChainException("the key cannot verify the JWS algorithm " + headerAlg);
        }
        if (jwk.getPublicKeyUse() != null && !JWK.Use.SIG.asString().equals(jwk.getPublicKeyUse())) {
            throw new ChainException("the key is not a signing key");
        }
        KeyWrapper key;
        try {
            key = JWKSUtils.getKeyWrapper(jwk);
        } catch (RuntimeException e) {
            throw new ChainException("the key cannot be read", e);
        }
        if (key == null || key.getPublicKey() == null) {
            throw new ChainException("the key type " + jwk.getKeyType() + " is not supported");
        }
        if (key.getPublicKey() instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new ChainException("the RSA key is shorter than " + MIN_RSA_BITS + " bits");
        }
        key.setAlgorithm(alg);
        return KeyWrapperUtil.createSignatureVerifierContext(key);
    }

    /** Reads the jwk member of a cnf claim (RFC 7800 §3.2). */
    public static JWK confirmationKey(JsonNode claims, String owner) throws ChainException {
        JsonNode jwk = claims.path("cnf").path("jwk");
        if (!jwk.isObject()) {
            throw new ChainException(owner + " has no cnf claim with a jwk");
        }
        if (jwk.has("d")) {
            throw new ChainException(owner + " has a private key in its cnf claim");
        }
        try {
            return JsonSerialization.mapper.convertValue(jwk, JWK.class);
        } catch (IllegalArgumentException e) {
            throw new ChainException(owner + " has an unreadable cnf key", e);
        }
    }

    /** The JWK thumbprint URI of RFC 9278 with SHA-256. */
    public static String thumbprintUri(JWK jwk) {
        return THUMBPRINT_URI + JWKSUtils.computeThumbprint(jwk);
    }

    private static String algorithmOf(JWK jwk, String headerAlg) throws ChainException {
        String curve = jwk.getOtherClaim("crv", String.class);
        String alg =
                switch (String.valueOf(jwk.getKeyType())) {
                    case KeyType.EC ->
                        switch (String.valueOf(curve)) {
                            case "P-256" -> "ES256";
                            case "P-384" -> "ES384";
                            case "P-521" -> "ES512";
                            default -> null;
                        };
                    case KeyType.OKP -> "Ed25519".equals(curve) ? "EdDSA" : null;
                    case KeyType.RSA -> headerAlg.startsWith("RS") || headerAlg.startsWith("PS") ? headerAlg : null;
                    default -> null;
                };
        if (alg == null) {
            throw new ChainException("the key type " + jwk.getKeyType() + " with curve " + curve + " is not supported");
        }
        return alg;
    }
}
