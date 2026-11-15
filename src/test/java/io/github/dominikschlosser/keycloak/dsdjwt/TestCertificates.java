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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.trust.DefaultTrustIdentityProvider;
import org.keycloak.broker.trust.DefaultTrustIdentityProviderConfig;
import org.keycloak.crypto.KeyWrapper;

/** A test CA that issues signing certificates to credential issuers. */
public final class TestCertificates {

    private static final AtomicLong SERIAL = new AtomicLong(Instant.now().toEpochMilli());

    private final X500Name name;
    private final KeyPair keys;
    public final X509Certificate certificate;

    public TestCertificates(String commonName) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            keys = generator.generateKeyPair();
            name = new X500Name("CN=" + commonName);
            X509v3CertificateBuilder builder = builder(name, name, keys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            certificate = sign(builder, keys.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Keycloak's default trust provider with this CA as its only X.509 trust anchor. It reads no
     * session for X.509 trust.
     */
    public TrustMaterialIdentityProvider<?> trustMaterial() {
        DefaultTrustIdentityProviderConfig config = new DefaultTrustIdentityProviderConfig();
        config.getConfig().put(DefaultTrustIdentityProviderConfig.USE_X509, "true");
        config.setTrustedCertificates(pem());
        return new DefaultTrustIdentityProvider(null, config);
    }

    /** Issues a signing certificate for this key with these subject alternative names. */
    public X509Certificate issue(String commonName, KeyWrapper key, GeneralName... alternativeNames) {
        try {
            X509v3CertificateBuilder builder =
                    builder(name, new X500Name("CN=" + commonName), (PublicKey) key.getPublicKey());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            if (alternativeNames.length > 0) {
                builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(alternativeNames));
            }
            return sign(builder, keys.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static GeneralName uri(String value) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, value);
    }

    public static GeneralName dns(String value) {
        return new GeneralName(GeneralName.dNSName, value);
    }

    public String pem() {
        return pem(certificate);
    }

    public static String pem(X509Certificate certificate) {
        try {
            return pem("CERTIFICATE", certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pem(PrivateKey key) {
        return pem("PRIVATE KEY", key.getEncoded());
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    private static X509v3CertificateBuilder builder(X500Name issuer, X500Name subject, PublicKey key) {
        Instant now = Instant.now();
        return new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(Duration.ofDays(1))),
                subject,
                key);
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, PrivateKey key) throws Exception {
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key)));
    }
}
