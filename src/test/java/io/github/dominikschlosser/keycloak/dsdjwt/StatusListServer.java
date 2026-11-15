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

package io.github.dominikschlosser.keycloak.dsdjwt;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.zip.Deflater;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyWrapper;

/**
 * Serves a Status List Token over https with a self-signed certificate for a host name. The list has
 * 1 bit per credential, and only index {@link #INVALID_INDEX} is set.
 */
public final class StatusListServer implements AutoCloseable {

    public static final int INVALID_INDEX = 7;
    public static final int VALID_INDEX = 3;
    private static final String PATH = "/status/1";

    private final HttpsServer server;
    private final X509Certificate certificate;
    private final String uri;

    /**
     * @param host the name clients use to reach this computer, which the certificate holds
     * @param issuer the key that signs the Status List Token
     */
    public StatusListServer(String host, KeyWrapper issuer) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys = generator.generateKeyPair();
        certificate = certificate(host, keys);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        char[] password = new char[0];
        store.setKeyEntry("status", keys.getPrivate(), password, new X509Certificate[] {certificate});
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(store, password);
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(keyManagers.getKeyManagers(), null, null);

        server = HttpsServer.create(new InetSocketAddress(0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        uri = "https://" + host + ":" + server.getAddress().getPort() + PATH;
        server.createContext(PATH, exchange -> {
            byte[] body = token(issuer).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/statuslist+jwt");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public String uri() {
        return uri;
    }

    /** The certificate in PEM form, for the truststore of the client. */
    public String certificatePem() throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private String token(KeyWrapper issuer) {
        long now = Instant.now().getEpochSecond();
        ObjectNode claims = ChainBuilder.object();
        claims.put("iss", "https://register.example");
        claims.put("sub", uri);
        claims.put("iat", now - 60);
        claims.put("exp", now + 3600);
        ObjectNode list = claims.putObject("status_list");
        list.put("bits", 1);
        // draft-ietf-oauth-status-list-21 counts the bits of a byte from the least significant one.
        list.put("lst", Base64Url.encode(deflate(new byte[] {(byte) (1 << INVALID_INDEX)})));
        return ChainBuilder.sign(issuer, "statuslist+jwt", claims);
    }

    private static X509Certificate certificate(String host, KeyPair keys) throws Exception {
        X500Name name = new X500Name("CN=" + host);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(Duration.ofDays(1))),
                name,
                keys.getPublic());
        builder.addExtension(
                Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, host)));
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
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
