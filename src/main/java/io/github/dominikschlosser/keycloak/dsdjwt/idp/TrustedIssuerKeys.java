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

package io.github.dominikschlosser.keycloak.dsdjwt.idp;

import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.IssuerKeyResolver;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.JwkVerifiers;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.crypto.X509CertificateChainValidator;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;

/**
 * Resolves issuer keys through Keycloak trust material, the way the OID4VP identity provider does
 * in TrustMaterialSdJwtIssuerResolver.
 */
public final class TrustedIssuerKeys implements IssuerKeyResolver {

    /** GeneralName tags of RFC 5280 §4.2.1.6, as X509Certificate.getSubjectAlternativeNames returns them. */
    private static final int DNS_NAME = 2;

    private static final int URI_NAME = 6;

    private final TrustMaterialIdentityProvider<?> trust;

    public TrustedIssuerKeys(TrustMaterialIdentityProvider<?> trust) {
        this.trust = trust;
    }

    @Override
    public List<SignatureVerifierContext> resolve(JWSHeader header, String issuer) throws ChainException {
        String algorithm = header.getRawAlgorithm();
        TrustMaterialRequest request = TrustMaterialRequest.builder()
                .kid(header.getKeyId())
                .algorithm(algorithm)
                .issuer(issuer)
                .build();
        // HAIP 1.0 §6.1.1: with X.509 trust anchors the x5c chain decides, and a key lookup must
        // not stand in for a chain that fails.
        JWK leaf;
        try {
            leaf = trust.validateX509Chain(request, header.getX5c(), algorithm);
        } catch (VerificationException e) {
            throw new ChainException("the x5c certificate chain of the issuer is not trusted: " + e.getMessage(), e);
        }
        if (leaf != null) {
            checkIssuerName(header.getX5c(), issuer);
            return List.of(JwkVerifiers.forKey(leaf, algorithm));
        }
        List<SignatureVerifierContext> verifiers = new ArrayList<>();
        for (JWK key : trust.resolveKeys(request).toList()) {
            try {
                verifiers.add(JwkVerifiers.forKey(key, algorithm));
            } catch (ChainException e) {
                // This trusted key cannot verify the algorithm of the header.
            }
        }
        return verifiers;
    }

    /**
     * draft-ietf-oauth-sd-jwt-vc-19 §2.5: with x5c "the Issuer of the Verifiable Digital Credential
     * is the subject of the end-entity certificate", and a key that cannot be shown to belong to the
     * Issuer MUST be rejected. Draft 19 does not say how iss names that subject. The rule here builds
     * on draft 09 §3.5: iss matches a uniformResourceIdentifier SAN, or iss is a bare https host that
     * matches a dNSName SAN. Several issuers can share a host under different paths or ports, and a
     * certificate for the host must not sign for all of them, so such an iss needs the URI SAN.
     */
    private static void checkIssuerName(List<String> x5c, String issuer) throws ChainException {
        Collection<List<?>> names;
        try {
            X509Certificate leaf =
                    X509CertificateChainValidator.decodeCertificateChain(x5c).get(0);
            names = leaf.getSubjectAlternativeNames();
        } catch (VerificationException | CertificateParsingException e) {
            throw new ChainException("the certificate of the issuer has no readable subject alternative names", e);
        }
        String host = bareHttpsHost(issuer);
        if (names != null) {
            for (List<?> name : names) {
                Object type = name.get(0);
                Object value = name.get(1);
                if (Integer.valueOf(URI_NAME).equals(type) && issuer.equals(value)) {
                    return;
                }
                if (host != null
                        && Integer.valueOf(DNS_NAME).equals(type)
                        && value instanceof String dnsName
                        && host.equalsIgnoreCase(withoutTrailingDot(dnsName))) {
                    return;
                }
            }
        }
        throw new ChainException(
                "the certificate of the issuer names no subject alternative name that matches the iss " + issuer);
    }

    /**
     * The host of an iss such as https://register.example or https://register.example/, without one
     * trailing dot. Null when the iss has another scheme, user info, a port, a path, a query or a
     * fragment.
     */
    private static String bareHttpsHost(String issuer) {
        URI uri;
        try {
            uri = new URI(issuer);
        } catch (URISyntaxException e) {
            return null;
        }
        String host = uri.getHost();
        String path = uri.getRawPath();
        // Comparing the authority with the host also catches user info and an empty port.
        boolean bare = "https".equalsIgnoreCase(uri.getScheme())
                && host != null
                && host.equals(uri.getRawAuthority())
                && (path == null || path.isEmpty() || path.equals("/"))
                && uri.getRawQuery() == null
                && uri.getRawFragment() == null;
        return bare ? withoutTrailingDot(host) : null;
    }

    /** RFC 1034 §3.1 writes an absolute name with a trailing dot. A dNSName SAN is absolute without it. */
    private static String withoutTrailingDot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }
}
