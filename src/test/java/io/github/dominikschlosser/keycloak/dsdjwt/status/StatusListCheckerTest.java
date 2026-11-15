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
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import io.github.dominikschlosser.keycloak.dsdjwt.TestCertificates;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.IssuerKeyResolver;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.TrustedIssuerKeys;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.Deflater;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyWrapper;

class StatusListCheckerTest {

    private static final String ISSUER = ChainBuilder.ISSUER;
    private static final Map<String, String> TOKENS = new ConcurrentHashMap<>();

    private static KeyWrapper issuer;
    private static TestCertificates ca;
    private static HttpsServer server;
    private static CloseableHttpClient client;
    private static String statusUri;

    @BeforeAll
    static void start() throws Exception {
        CryptoIntegration.init(StatusListCheckerTest.class.getClassLoader());
        issuer = ChainBuilder.ecKey();
        ca = new TestCertificates("Register Test CA");

        KeyWrapper tls = ChainBuilder.ecKey();
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("tls", tls.getPrivateKey(), new char[0], new X509Certificate[] {
            ca.issue("localhost", tls, TestCertificates.dns("localhost")), ca.certificate
        });
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, new char[0]);
        SSLContext serverTls = SSLContext.getInstance("TLS");
        serverTls.init(keyManagers.getKeyManagers(), null, null);
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverTls));
        server.createContext("/", exchange -> {
            String token = TOKENS.get(url(exchange.getRequestURI().getPath()));
            byte[] body = token == null ? new byte[0] : token.getBytes(StandardCharsets.US_ASCII);
            exchange.sendResponseHeaders(token == null ? 404 : 200, body.length == 0 ? -1 : body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        statusUri = url("/status/7");

        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("ca", ca.certificate);
        client = HttpClients.custom()
                .setSSLContext(
                        SSLContexts.custom().loadTrustMaterial(anchors, null).build())
                .build();
    }

    @AfterAll
    static void stop() throws Exception {
        client.close();
        server.stop(0);
    }

    @AfterEach
    void reset() {
        TOKENS.clear();
        Time.setOffset(0);
    }

    @Test
    void passesCredentialWithoutStatus() {
        assertDoesNotThrow(() -> checker().check(ChainBuilder.object()));
    }

    @Test
    void passesValidEntry() {
        TOKENS.put(statusUri, token(statusList(1, 0b10)));

        assertDoesNotThrow(() -> checker().check(credential(statusUri, 0)));
    }

    @Test
    void refusesInvalidEntry() {
        TOKENS.put(statusUri, token(statusList(1, 0b10)));

        assertRefused("the credential is invalid (status 1)", credential(statusUri, 1));
    }

    @Test
    void refusesSuspendedEntry() {
        TOKENS.put(statusUri, token(statusList(2, 0b1110)));

        assertRefused("the issuer has suspended the credential (status 2)", credential(statusUri, 0));
    }

    @Test
    void refusesOtherStatusValues() {
        TOKENS.put(statusUri, token(statusList(2, 0b1110)));

        assertRefused("the status list gives the credential the status 3", credential(statusUri, 1));
    }

    @Test
    void refusesIndexOutsideTheList() {
        TOKENS.put(statusUri, token(statusList(1, 0)));

        assertRefused("the status list has no entry 8", credential(statusUri, 8));
    }

    @Test
    void refusesHttpUri() {
        assertRefused(
                "the status list URI http://register.example/status/7 does not use https",
                credential("http://register.example/status/7", 0));
    }

    @Test
    void refusesStatusWithoutIndex() {
        ObjectNode credential = credential(statusUri, 0);
        ((ObjectNode) credential.get("status").get("status_list")).remove("idx");

        assertRefused("the status_list of the credential needs a uri and a whole number idx", credential);
    }

    @Test
    void refusesWrongTokenType() {
        TOKENS.put(statusUri, ChainBuilder.sign(issuer, "JWT", statusList(1, 0)));

        assertRefused("the status list token has typ JWT, expected statuslist+jwt", credential(statusUri, 0));
    }

    @Test
    void refusesTokenForAnotherList() {
        ObjectNode claims = statusList(1, 0);
        claims.put("sub", "https://register.example/status/8");
        TOKENS.put(statusUri, token(claims));

        assertRefused(
                "the status list token is for \"https://register.example/status/8\", not " + statusUri,
                credential(statusUri, 0));
    }

    @Test
    void refusesExpiredToken() {
        ObjectNode claims = statusList(1, 0);
        claims.put("exp", NOW - 61);
        TOKENS.put(statusUri, token(claims));

        assertRefused("the status list token: Token has expired by exp", credential(statusUri, 0));
    }

    @Test
    void refusesTokenWithoutIat() {
        ObjectNode claims = statusList(1, 0);
        claims.remove("iat");
        TOKENS.put(statusUri, token(claims));

        assertRefused("the status list token: Missing required claim 'iat'", credential(statusUri, 0));
    }

    @Test
    void refusesIatInTheFuture() {
        ObjectNode claims = statusList(1, 0);
        claims.put("iat", NOW + 65);
        TOKENS.put(statusUri, token(claims));

        assertRefused("the status list token: Token was issued in the future", credential(statusUri, 0));
    }

    @Test
    void refusesTokenOfAnotherSigner() {
        TOKENS.put(statusUri, ChainBuilder.sign(ChainBuilder.ecKey(), "statuslist+jwt", statusList(1, 0)));

        assertRefused(
                "the signature of the status list token does not verify with a trusted issuer key",
                credential(statusUri, 0));
    }

    @Test
    void passesTokenWithoutIss() {
        ObjectNode claims = statusList(1, 0);
        claims.remove("iss");
        TOKENS.put(statusUri, token(claims));

        assertDoesNotThrow(() -> checker().check(credential(statusUri, 0)));
    }

    @Test
    void refusesTokenOfAnotherIssuer() {
        ObjectNode claims = statusList(1, 0);
        claims.put("iss", "https://register.supplier.example");
        TOKENS.put(statusUri, token(claims));

        assertRefused(
                "the status list token has iss \"https://register.supplier.example\", but the credential has iss "
                        + ISSUER,
                credential(statusUri, 0));
    }

    @Test
    void refusesUnsupportedBitSize() {
        ObjectNode claims = statusList(1, 0);
        ((ObjectNode) claims.get("status_list")).put("bits", 3);
        TOKENS.put(statusUri, token(claims));

        assertRefused("the status list has an unsupported size of 3 bits", credential(statusUri, 0));
    }

    @Test
    void refusesListLargerThan16Megabytes() {
        ObjectNode claims = statusList(1, 0);
        ((ObjectNode) claims.get("status_list")).put("lst", Base64Url.encode(deflate(new byte[16 * 1024 * 1024 + 1])));
        TOKENS.put(statusUri, token(claims));

        assertRefused("the status list is larger than 16777216 bytes", credential(statusUri, 0));
    }

    @Test
    void refusesListThatIsNotZlib() {
        ObjectNode claims = statusList(1, 0);
        ((ObjectNode) claims.get("status_list")).put("lst", Base64Url.encode(new byte[] {1, 2, 3}));
        TOKENS.put(statusUri, token(claims));

        assertRefused("the status list is not ZLIB data", credential(statusUri, 0));
    }

    @Test
    void acceptsAListSignerWhoseCertificateNamesTheIssuer() {
        X509Certificate leaf = ca.issue("Acme Logistics GmbH", issuer, TestCertificates.uri(ISSUER));
        TOKENS.put(statusUri, ChainBuilder.sign(issuer, "statuslist+jwt", statusList(1, 0), List.of(leaf)));

        assertDoesNotThrow(() -> checker(x509Trust()).check(credential(statusUri, 0)));
    }

    @Test
    void refusesAListSignerUnderTheSameCaThatNamesAnotherIssuer() {
        X509Certificate leaf =
                ca.issue("Bolt Supplies B.V.", issuer, TestCertificates.uri("https://register.supplier.example"));
        TOKENS.put(statusUri, ChainBuilder.sign(issuer, "statuslist+jwt", statusList(1, 0), List.of(leaf)));

        ChainException e =
                assertThrows(ChainException.class, () -> checker(x509Trust()).check(credential(statusUri, 0)));

        assertEquals(
                "the certificate of the issuer names no subject alternative name that matches the iss " + ISSUER,
                e.getMessage());
    }

    @Test
    void refusesAListWithoutX5cUnderX509Trust() {
        TOKENS.put(statusUri, token(statusList(1, 0)));

        ChainException e =
                assertThrows(ChainException.class, () -> checker(x509Trust()).check(credential(statusUri, 0)));

        assertTrue(e.getMessage().startsWith("the x5c certificate chain of the issuer is not trusted"), e.getMessage());
    }

    private void assertRefused(String message, ObjectNode credential) {
        ChainException e = assertThrows(ChainException.class, () -> checker().check(credential));
        assertTrue(e.getMessage().startsWith(message), e.getMessage());
    }

    private StatusListChecker checker() {
        return checker(ChainBuilder.trust(ISSUER, ChainBuilder.publicJwk(issuer)));
    }

    private static IssuerKeyResolver x509Trust() {
        return new TrustedIssuerKeys(ca.trustMaterial());
    }

    private StatusListChecker checker(IssuerKeyResolver trust) {
        Time.setOffset((int) (NOW - System.currentTimeMillis() / 1000));
        return new StatusListChecker(
                new HttpStatusListFetcher(
                        client, HttpStatusListFetcher.DEFAULT_TIMEOUT, HttpStatusListFetcher.DEFAULT_DEADLINE),
                trust);
    }

    private static String url(String path) {
        return "https://localhost:" + server.getAddress().getPort() + path;
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
        claims.put("sub", statusUri);
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
