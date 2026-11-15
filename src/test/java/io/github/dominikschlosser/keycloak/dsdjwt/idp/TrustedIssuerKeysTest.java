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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import io.github.dominikschlosser.keycloak.dsdjwt.Stubs;
import io.github.dominikschlosser.keycloak.dsdjwt.TestCertificates;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.util.JsonSerialization;

class TrustedIssuerKeysTest {

    private static final String ACME = "https://register.acme.example";
    private static final String BOLT = "https://register.bolt.example";
    /** A hosted issuance service runs the issuers of Acme and Bolt on 1 host. */
    private static final String ACME_TENANT = "https://issue.example/acme";

    private static final String BOLT_TENANT = "https://issue.example/bolt";

    private static TestCertificates ca;
    private static KeyWrapper acmeKey;

    private final List<String> calls = new ArrayList<>();

    @BeforeAll
    static void crypto() {
        CryptoIntegration.init(TrustedIssuerKeysTest.class.getClassLoader());
        ca = new TestCertificates("Acme Test CA");
        acmeKey = ChainBuilder.ecKey();
    }

    @Test
    void acceptsLeafWhoseUriNameIsTheIssuer() throws Exception {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", acmeKey, TestCertificates.uri(ACME));

        assertEquals(1, keys().resolve(header(leaf), ACME).size());
    }

    @Test
    void acceptsLeafWhoseDnsNameIsTheHostOfTheIssuer() throws Exception {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", acmeKey, TestCertificates.dns("register.acme.example"));

        assertEquals(1, keys().resolve(header(leaf), ACME).size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://register.acme.example/", "https://register.acme.example."})
    void acceptsDnsNameForABareHostWithASlashOrATrailingDot(String issuer) throws Exception {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", acmeKey, TestCertificates.dns("register.acme.example"));

        assertEquals(1, keys().resolve(header(leaf), issuer).size());
    }

    @Test
    void acceptsUriNameForAnIssuerWithAPath() throws Exception {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", acmeKey, TestCertificates.uri(ACME_TENANT));

        assertEquals(1, keys().resolve(header(leaf), ACME_TENANT).size());
    }

    @Test
    void refusesUriNameOfAnotherIssuerOnTheSameHost() throws Exception {
        X509Certificate leaf = ca.issue("Bolt Supplies B.V.", acmeKey, TestCertificates.uri(BOLT_TENANT));

        ChainException e = assertThrows(ChainException.class, () -> keys().resolve(header(leaf), ACME_TENANT));

        assertEquals(
                "the certificate of the issuer names no subject alternative name that matches the iss " + ACME_TENANT,
                e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                ACME_TENANT,
                "https://issue.example:8443",
                "https://issue.example:",
                "https://acme@issue.example",
                "https://issue.example?tenant=acme",
                "https://issue.example#acme"
            })
    void refusesDnsNameForAnIssuerThatIsNotABareHost(String issuer) throws Exception {
        X509Certificate leaf = ca.issue("Bolt Supplies B.V.", acmeKey, TestCertificates.dns("issue.example"));

        ChainException e = assertThrows(ChainException.class, () -> keys().resolve(header(leaf), issuer));

        assertEquals(
                "the certificate of the issuer names no subject alternative name that matches the iss " + issuer,
                e.getMessage());
    }

    @Test
    void refusesLeafOfAnotherIssuerUnderTheSameCa() throws Exception {
        X509Certificate leaf = ca.issue("Bolt Supplies B.V.", acmeKey, TestCertificates.uri(BOLT));

        ChainException e = assertThrows(ChainException.class, () -> keys().resolve(header(leaf), ACME));

        assertEquals(
                "the certificate of the issuer names no subject alternative name that matches the iss " + ACME,
                e.getMessage());
    }

    @Test
    void refusesDnsNameForAnIssuerWithoutHttps() throws Exception {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", acmeKey, TestCertificates.dns("register.acme.example"));

        ChainException e =
                assertThrows(ChainException.class, () -> keys().resolve(header(leaf), "http://register.acme.example"));

        assertEquals(
                "the certificate of the issuer names no subject alternative name that matches the iss"
                        + " http://register.acme.example",
                e.getMessage());
    }

    @Test
    void refusesLeafWithoutAlternativeNames() throws Exception {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", acmeKey);

        assertThrows(ChainException.class, () -> keys().resolve(header(leaf), ACME));
    }

    @Test
    void refusesAnUntrustedX5cWithoutFallingBackToKeys() throws Exception {
        JWSHeader header = JsonSerialization.readValue("{\"alg\":\"ES256\",\"x5c\":[\"MIIB\"]}", JWSHeader.class);

        ChainException e = assertThrows(
                ChainException.class, () -> new TrustedIssuerKeys(trust()).resolve(header, "https://register.example"));

        assertEquals(
                "the x5c certificate chain of the issuer is not trusted: the chain does not end at a trust anchor",
                e.getMessage());
        assertEquals(List.of("validateX509Chain"), calls);
    }

    private static TrustedIssuerKeys keys() {
        return new TrustedIssuerKeys(ca.trustMaterial());
    }

    private static JWSHeader header(X509Certificate leaf) throws Exception {
        return JsonSerialization.mapper.convertValue(Map.of("alg", "ES256", "x5c", x5c(leaf)), JWSHeader.class);
    }

    private static List<String> x5c(X509Certificate leaf) throws Exception {
        return List.of(Base64.getEncoder().encodeToString(leaf.getEncoded()));
    }

    private TrustMaterialIdentityProvider<?> trust() {
        return Stubs.stub(TrustMaterialIdentityProvider.class, (method, args) -> {
            calls.add(method);
            return switch (method) {
                case "validateX509Chain" -> throw new VerificationException("the chain does not end at a trust anchor");
                case "resolveKeys" -> Stream.of(ChainBuilder.publicJwk(ChainBuilder.ecKey()));
                default -> throw new UnsupportedOperationException(method);
            };
        });
    }
}
