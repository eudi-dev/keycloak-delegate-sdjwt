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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.util.JsonSerialization;

/**
 * Builds a dSD-JWT+KB with Keycloak's JOSE classes. Every field is open so a test can break one
 * part of the chain before {@link #build()}.
 */
public final class ChainBuilder {

    public static final String AUDIENCE = "https://iam.acme.example/realms/acme";
    public static final String NONCE = "YWNtZS1ub25jZQ";
    public static final String PRINCIPAL = "DEACME.HRB4711";
    public static final long NOW = 1794571300L;

    public final long now;
    public final String audience;
    public final KeyWrapper issuer;
    public final KeyWrapper holder = ecKey();
    public String credentialType = "dc+sd-jwt";
    public String credentialSdAlg = "sha-256";
    public final ObjectNode credentialClaims = object();
    public final Map<String, JsonNode> credentialDisclosures = new LinkedHashMap<>();
    /** The actions the credential allows. links() adds its actions here. */
    public final ArrayNode credentialActions = JsonSerialization.mapper.createArrayNode();
    /** Replaces the Disclosures of the credential after signing when not null. */
    public List<String> credentialDisclosureOverride;
    /** The x5c header of the credential. Without it the header carries no certificate. */
    public List<X509Certificate> credentialX5c;

    public final List<Link> links = new ArrayList<>();

    public String keyBindingType = "kb+jwt";
    public final ObjectNode keyBindingClaims = object();
    /** Signs the Key Binding JWT instead of the last agent when not null. */
    public KeyWrapper keyBindingSigner;
    /** Replaces the computed sd_hash of the Key Binding JWT when not null. */
    public String keyBindingSdHash;

    public static final class Link {
        public final KeyWrapper agent = ecKey();
        public final ObjectNode delegatePayload = object();
        public final ObjectNode claims = object();
        public String type = "kb-sd-jwt+kb";
        public boolean issuerJwtHash;
        public boolean withCnf = true;
        public boolean withPrecedingHash = true;
        /** Signs the KB-SD-JWT instead of the preceding cnf key when not null. */
        public KeyWrapper signer;
        /** Replaces the computed sd_hash or issuer_jwt_hash when not null. */
        public String precedingHash;
        /** Elements of delegate_payload after the digest of the Delegate Payload Disclosure. */
        public final List<JsonNode> extraElements = new ArrayList<>();
        /** Further Delegate Payloads, each disclosed as its own delegate_payload element. */
        public final List<ObjectNode> extraDelegatePayloads = new ArrayList<>();
        /** Top level claims of the KB-SD-JWT that Disclosures hold instead of the signed payload. */
        public final Map<String, JsonNode> disclosedClaims = new LinkedHashMap<>();
        /** Replaces the delegate_payload array and drops its Disclosures when not null. */
        public ArrayNode delegatePayloadArray;
        /** Discloses this value instead of the Delegate Payload when not null. */
        public JsonNode disclosedDelegatePayload;
        /** Claims of the Delegate Payload that sit in its own _sd, each behind a Disclosure. */
        public final Map<String, JsonNode> nestedDelegateDisclosures = new LinkedHashMap<>();
        /** Further Disclosures sent with the KB-SD-JWT, for digests a test puts in the Delegate Payload. */
        public final List<String> extraDisclosures = new ArrayList<>();
    }

    public ChainBuilder() {
        this(NOW, AUDIENCE, NONCE);
    }

    /** Builds chains for a verifier at this time, with this realm issuer and nonce. */
    public ChainBuilder(long now, String audience, String nonce) {
        this(now, audience, nonce, ecKey());
    }

    /** Builds chains whose credential this issuer key signs. */
    public ChainBuilder(long now, String audience, String nonce, KeyWrapper issuer) {
        this.issuer = issuer;
        this.now = now;
        this.audience = audience;
        credentialClaims.put("iss", "https://register.example");
        credentialClaims.put("vct", "urn:eudi-test:business:poa:1");
        credentialClaims.put("iat", now - 3600);
        credentialClaims.put("exp", now + 86400);
        credentialDisclosures.put("legal_name", text("Acme Logistics GmbH"));
        credentialDisclosures.put("euid_reference", text(PRINCIPAL));
        credentialDisclosures.put(
                "authorisation", JsonSerialization.mapper.createObjectNode().set("actions", credentialActions));
        keyBindingClaims.put("iat", now - 10);
        keyBindingClaims.put("aud", audience);
        keyBindingClaims.put("nonce", nonce);
    }

    /** Adds n links. Link i delegates to agent i with the given actions. */
    public ChainBuilder links(int n, String... actions) {
        for (int i = 0; i < n; i++) {
            Link link = new Link();
            int number = links.size() + 1;
            link.delegatePayload.put("vct", "urn:eudi-test:business:agent-mandate:1");
            link.delegatePayload.put("iat", now - 100);
            link.delegatePayload.put("exp", now + 3600);
            ObjectNode agent = link.delegatePayload.putObject("agent");
            agent.put("id", "urn:eudi-test:agent:procurement-" + number);
            agent.put("name", "Procurement agent " + number);
            ObjectNode mandate = link.delegatePayload.putObject("mandate");
            ArrayNode list = mandate.putArray("actions");
            for (String action : actions) {
                list.add(action);
                if (!credentialActions.valueStream().anyMatch(known -> known.asText()
                        .equals(action))) {
                    credentialActions.add(action);
                }
            }
            ObjectNode limit = mandate.putObject("limit");
            limit.put("amount", "2500.00");
            limit.put("currency", "EUR");
            mandate.put("purpose", "Approve supplier invoices");
            ArrayNode audiences = mandate.putArray("audiences");
            audiences.add(audience);
            link.claims.put("iat", now - 50);
            link.claims.put("aud", "urn:eudi-test:agent:procurement-" + number);
            link.claims.put("nonce", "link-" + number + "-nonce");
            links.add(link);
        }
        return this;
    }

    public Link link(int number) {
        return links.get(number - 1);
    }

    public KeyWrapper lastAgent() {
        return links.isEmpty() ? holder : links.get(links.size() - 1).agent;
    }

    public String build() {
        ObjectNode payload = credentialClaims.deepCopy();
        payload.set("cnf", cnf(holder));
        payload.put("_sd_alg", credentialSdAlg);
        ArrayNode sd = payload.putArray("_sd");
        List<String> disclosures = new ArrayList<>();
        credentialDisclosures.forEach((name, value) -> {
            String disclosure = disclosure(text(salt()), text(name), value);
            disclosures.add(disclosure);
            sd.add(digest(disclosure));
        });
        String jwt = sign(issuer, credentialType, payload, credentialX5c);
        List<String> shown = credentialDisclosureOverride != null ? credentialDisclosureOverride : disclosures;
        StringBuilder chain = new StringBuilder(segment(jwt, shown));
        String precedingSegment = chain.toString();
        String precedingJwt = jwt;
        KeyWrapper precedingKey = holder;

        for (Link link : links) {
            ObjectNode delegate = link.delegatePayload.deepCopy();
            if (link.withCnf) {
                delegate.set("cnf", cnf(link.agent));
            }
            List<String> nestedDisclosures = new ArrayList<>();
            if (!link.nestedDelegateDisclosures.isEmpty()) {
                ArrayNode nestedSd = delegate.putArray("_sd");
                link.nestedDelegateDisclosures.forEach((name, value) -> {
                    String nested = disclosure(text(salt()), text(name), value);
                    nestedSd.add(digest(nested));
                    nestedDisclosures.add(nested);
                });
            }
            String payloadDisclosure = disclosure(
                    text(salt()), link.disclosedDelegatePayload != null ? link.disclosedDelegatePayload : delegate);
            ObjectNode claims = link.claims.deepCopy();
            String hash = link.issuerJwtHash ? digest(precedingJwt) : digest(precedingSegment);
            if (link.withPrecedingHash) {
                claims.put(
                        link.issuerJwtHash ? "issuer_jwt_hash" : "sd_hash",
                        link.precedingHash != null ? link.precedingHash : hash);
            }
            claims.put("_sd_alg", "sha-256");
            ArrayNode elements = claims.putArray("delegate_payload");
            elements.addObject().put("...", digest(payloadDisclosure));
            List<String> linkDisclosures = new ArrayList<>(List.of(payloadDisclosure));
            linkDisclosures.addAll(nestedDisclosures);
            linkDisclosures.addAll(link.extraDisclosures);
            for (ObjectNode extra : link.extraDelegatePayloads) {
                String extraDisclosure = disclosure(text(salt()), extra);
                elements.addObject().put("...", digest(extraDisclosure));
                linkDisclosures.add(extraDisclosure);
            }
            link.extraElements.forEach(elements::add);
            if (link.delegatePayloadArray != null) {
                claims.set("delegate_payload", link.delegatePayloadArray);
                linkDisclosures.clear();
            }
            if (!link.disclosedClaims.isEmpty()) {
                ArrayNode linkSd = claims.putArray("_sd");
                link.disclosedClaims.forEach((name, value) -> {
                    String claimDisclosure = disclosure(text(salt()), text(name), value);
                    linkSd.add(digest(claimDisclosure));
                    linkDisclosures.add(claimDisclosure);
                });
            }
            String linkJwt = sign(link.signer != null ? link.signer : precedingKey, link.type, claims);
            String linkSegment = segment(linkJwt, linkDisclosures);
            chain.append('~').append(linkSegment);
            precedingSegment = linkSegment;
            precedingJwt = linkJwt;
            precedingKey = link.agent;
        }

        ObjectNode keyBinding = keyBindingClaims.deepCopy();
        keyBinding.put("sd_hash", keyBindingSdHash != null ? keyBindingSdHash : digest(precedingSegment));
        chain.append(sign(keyBindingSigner != null ? keyBindingSigner : precedingKey, keyBindingType, keyBinding));
        return chain.toString();
    }

    /** Moves a member of this object behind its own Disclosure and returns the Disclosure. */
    public static String discloseSeparately(ObjectNode parent, String name) {
        String disclosure = disclosure(text(salt()), text(name), parent.remove(name));
        parent.withArray("_sd").add(digest(disclosure));
        return disclosure;
    }

    /** Moves an element of this array behind its own Disclosure and returns the Disclosure. */
    public static String discloseSeparately(ArrayNode parent, int index) {
        String disclosure = disclosure(text(salt()), parent.get(index));
        parent.set(index, object().put("...", digest(disclosure)));
        return disclosure;
    }

    public JWK issuerJwk() {
        return publicJwk(issuer);
    }

    public static KeyWrapper ecKey() {
        return ecKey("P-256");
    }

    /** An EC key on P-256 or P-384. */
    public static KeyWrapper ecKey(String curve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve.equals("P-384") ? "secp384r1" : "secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            KeyWrapper key = new KeyWrapper();
            key.setKid(UUID.randomUUID().toString());
            key.setAlgorithm(curve.equals("P-384") ? "ES384" : "ES256");
            key.setType(KeyType.EC);
            key.setCurve(curve);
            key.setPrivateKey(pair.getPrivate());
            key.setPublicKey(pair.getPublic());
            return key;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A public JWK without kid, alg and use, like the cnf keys of a wallet. */
    public static JWK publicJwk(KeyWrapper key) {
        JWK jwk = JWKBuilder.create().ec(key.getPublicKey());
        jwk.setKeyId(null);
        jwk.setAlgorithm(null);
        jwk.setPublicKeyUse(null);
        return jwk;
    }

    public static String sign(KeyWrapper key, String type, ObjectNode payload) {
        return sign(key, type, payload, null);
    }

    public static String sign(KeyWrapper key, String type, ObjectNode payload, List<X509Certificate> x5c) {
        KeyWrapper signing = key.cloneKey();
        signing.setKid(null);
        JWSBuilder builder = new JWSBuilder().type(type);
        if (x5c != null) {
            builder.x5c(x5c);
        }
        return builder.jsonContent(payload).sign(new ECDSASignatureSignerContext(signing));
    }

    public static String digest(String value) {
        return SdJwtUtils.hashAndBase64EncodeNoPad(value.getBytes(StandardCharsets.US_ASCII), "sha-256");
    }

    public static String disclosure(JsonNode... parts) {
        ArrayNode array = JsonSerialization.mapper.createArrayNode();
        for (JsonNode part : parts) {
            array.add(part);
        }
        try {
            return Base64Url.encode(JsonSerialization.mapper.writeValueAsBytes(array));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static ObjectNode object() {
        return JsonSerialization.mapper.createObjectNode();
    }

    public static JsonNode text(String value) {
        return JsonSerialization.mapper.getNodeFactory().textNode(value);
    }

    private static ObjectNode cnf(KeyWrapper key) {
        ObjectNode cnf = object();
        cnf.set("jwk", JsonSerialization.mapper.valueToTree(publicJwk(key)));
        return cnf;
    }

    private static String segment(String jwt, List<String> disclosures) {
        StringBuilder segment = new StringBuilder(jwt).append('~');
        disclosures.forEach(disclosure -> segment.append(disclosure).append('~'));
        return segment.toString();
    }

    private static String salt() {
        return SdJwtUtils.randomSalt();
    }
}
