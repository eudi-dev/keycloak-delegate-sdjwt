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

package io.github.dominikschlosser.keycloak.dsdjwt.status;

import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.NOW;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import io.github.dominikschlosser.keycloak.dsdjwt.TestCertificates;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.IssuerKeyResolver;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.JwkVerifiers;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.TrustedIssuerKeys;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyWrapper;

class StatusListCheckerTest {

    @AfterEach
    void resetTime() {
        Time.setOffset(0);
    }

    private static final String URI = "https://register.example/status/7";
    private static final String ISSUER = "https://register.example";

    private static KeyWrapper issuer;
    private static TestCertificates ca;

    private final Map<String, String> tokens = new HashMap<>();
    private final List<String> resolvedIssuers = new ArrayList<>();

    @BeforeAll
    static void crypto() {
        CryptoIntegration.init(StatusListCheckerTest.class.getClassLoader());
        issuer = ChainBuilder.ecKey();
        ca = new TestCertificates("Register Test CA");
    }

    @Test
    void passesCredentialWithoutStatus() {
        assertDoesNotThrow(() -> checker().check(ChainBuilder.object()));
    }

    @Test
    void passesValidEntry() {
        tokens.put(URI, token(statusList(1, 0b10)));

        assertDoesNotThrow(() -> checker().check(credential(URI, 0)));
    }

    @Test
    void refusesInvalidEntry() {
        tokens.put(URI, token(statusList(1, 0b10)));

        assertRefused("the credential is invalid (status 1)", credential(URI, 1));
    }

    @Test
    void refusesSuspendedEntry() {
        tokens.put(URI, token(statusList(2, 0b1110)));

        assertRefused("the issuer has suspended the credential (status 2)", credential(URI, 0));
    }

    @Test
    void refusesOtherStatusValues() {
        tokens.put(URI, token(statusList(2, 0b1110)));

        assertRefused("the status list gives the credential the status 3", credential(URI, 1));
    }

    @Test
    void refusesIndexOutsideTheList() {
        tokens.put(URI, token(statusList(1, 0)));

        assertRefused("the status list has no entry 8", credential(URI, 8));
    }

    @Test
    void refusesHttpUri() {
        assertRefused(
                "the status list URI http://register.example/status/7 does not use https",
                credential("http://register.example/status/7", 0));
    }

    @Test
    void refusesStatusWithoutIndex() {
        ObjectNode credential = credential(URI, 0);
        ((ObjectNode) credential.get("status").get("status_list")).remove("idx");

        assertRefused("the status_list of the credential needs a uri and a whole number idx", credential);
    }

    @Test
    void refusesWrongTokenType() {
        tokens.put(URI, ChainBuilder.sign(issuer, "JWT", statusList(1, 0)));

        assertRefused("the status list token has typ JWT, expected statuslist+jwt", credential(URI, 0));
    }

    @Test
    void refusesTokenForAnotherList() {
        ObjectNode claims = statusList(1, 0);
        claims.put("sub", "https://register.example/status/8");
        tokens.put(URI, token(claims));

        assertRefused(
                "the status list token is for \"https://register.example/status/8\", not " + URI, credential(URI, 0));
    }

    @Test
    void refusesExpiredToken() {
        ObjectNode claims = statusList(1, 0);
        claims.put("exp", NOW - 61);
        tokens.put(URI, token(claims));

        assertRefused("the status list token: Token has expired by exp", credential(URI, 0));
    }

    @Test
    void refusesTokenWithoutIat() {
        ObjectNode claims = statusList(1, 0);
        claims.remove("iat");
        tokens.put(URI, token(claims));

        assertRefused("the status list token: Missing required claim 'iat'", credential(URI, 0));
    }

    @Test
    void refusesIatInTheFuture() {
        ObjectNode claims = statusList(1, 0);
        claims.put("iat", NOW + 65);
        tokens.put(URI, token(claims));

        assertRefused("the status list token: Token was issued in the future", credential(URI, 0));
    }

    @Test
    void refusesTokenOfAnotherSigner() {
        tokens.put(URI, ChainBuilder.sign(ChainBuilder.ecKey(), "statuslist+jwt", statusList(1, 0)));

        assertRefused(
                "the signature of the status list token does not verify with a trusted issuer key", credential(URI, 0));
    }

    @Test
    void passesTokenWithoutIss() {
        ObjectNode claims = statusList(1, 0);
        claims.remove("iss");
        tokens.put(URI, token(claims));

        assertDoesNotThrow(() -> checker().check(credential(URI, 0)));
        assertEquals(List.of(ISSUER), resolvedIssuers);
    }

    @Test
    void refusesTokenOfAnotherIssuer() {
        ObjectNode claims = statusList(1, 0);
        claims.put("iss", "https://register.bolt.example");
        tokens.put(URI, token(claims));

        assertRefused(
                "the status list token has iss \"https://register.bolt.example\", but the credential has iss " + ISSUER,
                credential(URI, 0));
        assertEquals(List.of(), resolvedIssuers);
    }

    @Test
    void refusesUnsupportedBitSize() {
        ObjectNode claims = statusList(1, 0);
        ((ObjectNode) claims.get("status_list")).put("bits", 3);
        tokens.put(URI, token(claims));

        assertRefused("the status list has an unsupported size of 3 bits", credential(URI, 0));
    }

    @Test
    void refusesListLargerThan16Megabytes() {
        ObjectNode claims = statusList(1, 0);
        ((ObjectNode) claims.get("status_list")).put("lst", Base64Url.encode(deflate(new byte[16 * 1024 * 1024 + 1])));
        tokens.put(URI, token(claims));

        assertRefused("the status list is larger than 16777216 bytes", credential(URI, 0));
    }

    @Test
    void refusesListThatIsNotZlib() {
        ObjectNode claims = statusList(1, 0);
        ((ObjectNode) claims.get("status_list")).put("lst", Base64Url.encode(new byte[] {1, 2, 3}));
        tokens.put(URI, token(claims));

        assertRefused("the status list is not ZLIB data", credential(URI, 0));
    }

    @Test
    void acceptsAListSignerWhoseCertificateNamesTheIssuer() {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", issuer, TestCertificates.uri(ISSUER));
        tokens.put(URI, ChainBuilder.sign(issuer, "statuslist+jwt", statusList(1, 0), List.of(leaf)));

        assertDoesNotThrow(() -> checker(x509Trust()).check(credential(URI, 0)));
    }

    @Test
    void refusesAListSignerUnderTheSameCaThatNamesAnotherIssuer() {
        X509Certificate leaf =
                ca.issue("Bolt Supplies B.V.", issuer, TestCertificates.uri("https://register.bolt.example"));
        tokens.put(URI, ChainBuilder.sign(issuer, "statuslist+jwt", statusList(1, 0), List.of(leaf)));

        ChainException e =
                assertThrows(ChainException.class, () -> checker(x509Trust()).check(credential(URI, 0)));

        assertEquals(
                "the certificate of the issuer names no subject alternative name that matches the iss " + ISSUER,
                e.getMessage());
    }

    @Test
    void refusesAListWithoutX5cUnderX509Trust() {
        tokens.put(URI, token(statusList(1, 0)));

        ChainException e =
                assertThrows(ChainException.class, () -> checker(x509Trust()).check(credential(URI, 0)));

        assertTrue(e.getMessage().startsWith("the x5c certificate chain of the issuer is not trusted"), e.getMessage());
    }

    private void assertRefused(String message, ObjectNode credential) {
        ChainException e = assertThrows(ChainException.class, () -> checker().check(credential));
        assertTrue(e.getMessage().startsWith(message), e.getMessage());
    }

    private StatusListChecker checker() {
        return checker((header, iss) -> {
            resolvedIssuers.add(iss);
            return List.of(JwkVerifiers.forKey(ChainBuilder.publicJwk(issuer), header.getRawAlgorithm()));
        });
    }

    private static IssuerKeyResolver x509Trust() {
        return new TrustedIssuerKeys(ca.trustMaterial());
    }

    private StatusListChecker checker(IssuerKeyResolver trust) {
        StatusListFetcher fetcher = uri -> {
            String token = tokens.get(uri);
            if (token == null) {
                throw new ChainException("no status list at " + uri);
            }
            return token;
        };
        Time.setOffset((int) (NOW - System.currentTimeMillis() / 1000));
        return new StatusListChecker(fetcher, trust);
    }

    private static ObjectNode credential(String uri, int index) {
        ObjectNode credential = ChainBuilder.object();
        credential.put("iss", ISSUER);
        ObjectNode reference = credential.putObject("status").putObject("status_list");
        reference.put("idx", index);
        reference.put("uri", uri);
        return credential;
    }

    private static ObjectNode statusList(int bits, int firstByte) {
        ObjectNode claims = ChainBuilder.object();
        claims.put("iss", ISSUER);
        claims.put("sub", URI);
        claims.put("iat", NOW - 600);
        claims.put("exp", NOW + 3600);
        ObjectNode list = claims.putObject("status_list");
        list.put("bits", bits);
        list.put("lst", Base64Url.encode(deflate(new byte[] {(byte) firstByte})));
        return claims;
    }

    private static String token(ObjectNode claims) {
        return ChainBuilder.sign(issuer, "statuslist+jwt", claims);
    }

    private static byte[] deflate(byte[] data) {
        Deflater deflater = new Deflater();
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[256];
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer));
        }
        deflater.end();
        return out.toByteArray();
    }
}
