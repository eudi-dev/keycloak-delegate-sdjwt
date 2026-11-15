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
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.SdJwtVerificationContext;
import org.keycloak.util.JsonSerialization;

/**
 * Verifies a dSD-JWT+KB of draft-ietf-oauth-delegate-sd-jwt-00. Section numbers refer to that draft
 * unless another specification is given.
 */
public final class ChainVerifier {

    /** The largest number of KB-SD-JWTs in an accepted chain. */
    public static final int MAX_LINKS = 4;

    /** The largest subject_token in characters. A chain of {@link #MAX_LINKS} links stays far below it. */
    public static final int MAX_TOKEN_LENGTH = 64 * 1024;

    /**
     * RFC 9901 §7.3 leaves the accepted age of the Key Binding JWT to the Verifier. The holder signs it for
     * one request with a single use nonce, so 5 minutes only has to cover the time until the exchange.
     */
    static final Duration KEY_BINDING_MAX_AGE = Duration.ofMinutes(5);

    /**
     * The tolerance for every time claim in the chain and the status list. A minute covers the drift
     * between synchronized clocks and extends an expired credential by at most that minute.
     */
    public static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    static final String TYPE_KB_SD_JWT_KB = "kb-sd-jwt+kb";
    static final String TYPE_KB_JWT = "kb+jwt";
    private static final Set<String> CREDENTIAL_TYPES = Set.of("dc+sd-jwt", "vc+sd-jwt");

    /** draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: these claims "MUST NOT be included in Disclosures". */
    private static final List<String> CREDENTIAL_SIGNED_CLAIMS =
            List.of("iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status");

    /** The time claims of a KB-SD-JWT, which a Disclosure must not add either. */
    private static final List<String> LINK_SIGNED_CLAIMS = List.of("nbf", "exp");

    /** The time claims of a Delegate Payload, which a nested Disclosure must not add. */
    private static final List<String> DELEGATE_SIGNED_CLAIMS = List.of("nbf", "iat", "exp");

    // checkValidity checks the time claims against the injected clock, so the library checks none.
    private static final IssuerSignedJwtVerificationOpts NO_CLAIM_CHECKS =
            new IssuerSignedJwtVerificationOpts(List.of(), List.of());

    private final IssuerKeyResolver issuerKeys;
    private final Clock clock;

    public ChainVerifier(IssuerKeyResolver issuerKeys, Clock clock) {
        this.issuerKeys = Objects.requireNonNull(issuerKeys);
        this.clock = Objects.requireNonNull(clock);
    }

    /** @param audience the required aud of the Key Binding JWT */
    public VerifiedChain verify(String raw, String audience) throws ChainException {
        long now = clock.instant().getEpochSecond();
        long skew = CLOCK_SKEW.toSeconds();
        Parsed parsed = parse(raw);

        Segment credentialSegment = parsed.segments().get(0);
        IssuerSignedJWT credentialJwt = parseJwt(credentialSegment.jwt(), "the SD-JWT");
        String credentialType = credentialJwt.getJwsHeader().getType();
        if (!CREDENTIAL_TYPES.contains(credentialType)) {
            throw new ChainException("the SD-JWT has typ " + credentialType + ", expected dc+sd-jwt or vc+sd-jwt");
        }
        // draft-ietf-oauth-sd-jwt-vc-19 §2.5: the iss names the Issuer that the trusted key must belong to.
        JsonNode issuer = credentialJwt.getPayload().get("iss");
        if (issuer == null || !issuer.isTextual() || issuer.textValue().isEmpty()) {
            throw new ChainException("the SD-JWT has no iss string");
        }
        List<SignatureVerifierContext> trusted = issuerKeys.resolve(credentialJwt.getJwsHeader(), issuer.textValue());
        if (trusted == null || trusted.isEmpty()) {
            throw new ChainException("no trusted key of the credential issuer was found");
        }
        SignatureVerifierContext issuerKey =
                verifySignature(credentialJwt, trusted, "the SD-JWT", "a trusted issuer key");
        // §6 step 2: the initial SD-JWT is verified as RFC 9901 §7.1 describes.
        ObjectNode credential = disclose(credentialJwt, credentialSegment, issuerKey, "the SD-JWT");
        checkSignedClaims(credentialJwt, credential, CREDENTIAL_SIGNED_CLAIMS, "the SD-JWT");
        long expiresAt = checkValidity(credential, "the SD-JWT", false, now, skew);

        List<VerifiedLink> links = new ArrayList<>();
        Set<List<String>> firstWithheld = new HashSet<>();
        Segment preceding = credentialSegment;
        IssuerSignedJWT precedingJwt = credentialJwt;
        ObjectNode precedingClaims = credential;
        String precedingLabel = "the SD-JWT";
        for (int i = 1; i < parsed.segments().size(); i++) {
            Segment segment = parsed.segments().get(i);
            String label = "KB-SD-JWT " + i;
            IssuerSignedJWT linkJwt = parseJwt(segment.jwt(), label);
            // §6 steps 3.5 and 4.2: a chain with Key Binding needs a cnf key in every Delegate
            // Payload, so every KB-SD-JWT has the typ that announces it (§5.1.4).
            String type = linkJwt.getJwsHeader().getType();
            if (!TYPE_KB_SD_JWT_KB.equals(type)) {
                throw new ChainException(label + " has typ " + type + ", expected " + TYPE_KB_SD_JWT_KB);
            }
            // §6 step 3.1: "The cnf claim of the preceding component is used as the Issuer public key."
            JWK signerKey = JwkVerifiers.confirmationKey(precedingClaims, precedingLabel);
            SignatureVerifierContext verifier = verifierFor(signerKey, linkJwt, label);
            verifySignature(linkJwt, List.of(verifier), label, "the cnf key of " + precedingLabel);
            ObjectNode disclosed = disclose(linkJwt, segment, verifier, label);
            checkSignedClaims(linkJwt, disclosed, LINK_SIGNED_CLAIMS, label);

            ObjectNode payload = linkJwt.getPayload();
            // §5.1.4: "KB-SD-JWTs MUST conform to all the requirements of a KB-JWT".
            checkKeyBindingClaims(payload, label);
            expiresAt = Math.min(expiresAt, checkValidity(disclosed, label, false, now, skew));
            checkPrecedingHash(payload, preceding, precedingJwt, label);
            ObjectNode delegatePayload = delegatePayload(payload, disclosed, label);
            String delegateLabel = "the Delegate Payload of " + label;
            Map<String, JsonNode> disclosures = disclosuresByDigest(linkJwt, segment, delegateLabel);
            JsonNode signedPayload = signedDelegatePayload(linkJwt, disclosures, delegateLabel);
            checkDelegateSignedClaims(signedPayload, delegatePayload, delegateLabel);
            expiresAt = Math.min(expiresAt, checkValidity(delegatePayload, delegateLabel, true, now, skew));
            // §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate Payload MUST include a cnf claim."
            JWK delegateKey = JwkVerifiers.confirmationKey(delegatePayload, delegateLabel);
            if (i == 1) {
                collectWithheld(signedPayload, List.of(), disclosures, firstWithheld);
            }
            links.add(new VerifiedLink(delegatePayload, delegateKey));

            preceding = segment;
            precedingJwt = linkJwt;
            precedingClaims = delegatePayload;
            precedingLabel = delegateLabel;
        }

        KeyBinding keyBinding =
                checkKeyBindingJwt(parsed.keyBindingJwt(), preceding, precedingJwt, precedingClaims, audience, now);
        expiresAt = Math.min(expiresAt, keyBinding.expiresAt());
        return new VerifiedChain(credentialJwt, credential, links, firstWithheld, keyBinding.nonce(), expiresAt);
    }

    private record Segment(String jwt, List<String> disclosures, String raw) {}

    private record Parsed(List<Segment> segments, String keyBindingJwt) {}

    private record KeyBinding(String nonce, long expiresAt) {}

    /**
     * Splits the chain into the SD-JWT, the KB-SD-JWTs and the Key Binding JWT (§6 step 1). Each
     * segment keeps its trailing tilde because sd_hash covers it (RFC 9901 §4.3.1).
     */
    static Parsed parse(String raw) throws ChainException {
        if (raw == null || raw.isBlank()) {
            throw new ChainException("subject_token is empty");
        }
        if (raw.length() > MAX_TOKEN_LENGTH) {
            throw new ChainException("subject_token is longer than " + MAX_TOKEN_LENGTH + " characters");
        }
        String[] components = raw.split("~", -1);
        // §5.1.1: "dSD-JWT+KB and dSD-JWT formats are differentiated by a trailing ~ for dSD-JWT."
        String keyBindingJwt = components[components.length - 1];
        if (keyBindingJwt.isEmpty()) {
            // §6 step 5.1: a Verifier that requires Key Binding rejects a dSD-JWT.
            throw new ChainException("subject_token is a dSD-JWT without Key Binding, expected a dSD-JWT+KB");
        }
        // §5.1.1: "The resulting array of components MUST have exactly one empty component between
        // the last component of each SD-JWT or KB-SD-JWT and the following KB-SD-JWT."
        List<Segment> segments = new ArrayList<>();
        List<String> current = new ArrayList<>();
        for (int i = 0; i < components.length - 1; i++) {
            if (!components[i].isEmpty()) {
                current.add(components[i]);
                continue;
            }
            if (current.isEmpty()) {
                throw new ChainException("more than 1 empty component separates 2 parts of the chain");
            }
            segments.add(segment(current));
            current = new ArrayList<>();
        }
        if (current.isEmpty()) {
            throw new ChainException("no KB-SD-JWT follows the last empty component");
        }
        segments.add(segment(current));
        if (segments.size() < 2) {
            throw new ChainException("subject_token has no KB-SD-JWT, so it is not a Delegate SD-JWT");
        }
        int links = segments.size() - 1;
        if (links > MAX_LINKS) {
            throw new ChainException(
                    "the chain has " + links + " KB-SD-JWTs, but at most " + MAX_LINKS + " are accepted");
        }
        return new Parsed(List.copyOf(segments), keyBindingJwt);
    }

    private static Segment segment(List<String> components) {
        return new Segment(
                components.get(0),
                List.copyOf(components.subList(1, components.size())),
                String.join("~", components) + "~");
    }

    private static IssuerSignedJWT parseJwt(String jws, String label) throws ChainException {
        try {
            IssuerSignedJWT jwt = new IssuerSignedJWT(jws);
            if (jwt.getJwsHeader() == null || jwt.getPayload() == null) {
                throw new ChainException(label + " is not a JWS with a JSON payload");
            }
            return jwt;
        } catch (RuntimeException e) {
            throw new ChainException(label + " is not a JWS with a JSON payload", e);
        }
    }

    private static SignatureVerifierContext verifierFor(JWK key, IssuerSignedJWT jwt, String label)
            throws ChainException {
        try {
            return JwkVerifiers.forKey(key, jwt.getJwsHeader().getRawAlgorithm());
        } catch (ChainException e) {
            throw new ChainException(label + ": " + e.getMessage(), e);
        }
    }

    private static SignatureVerifierContext verifySignature(
            IssuerSignedJWT jwt, List<SignatureVerifierContext> verifiers, String label, String signer)
            throws ChainException {
        for (SignatureVerifierContext verifier : verifiers) {
            try {
                jwt.verifySignature(verifier);
                return verifier;
            } catch (VerificationException | RuntimeException e) {
                // The next candidate key may match.
            }
        }
        throw new ChainException("the signature of " + label + " does not verify with " + signer);
    }

    /** Checks the Disclosures with RFC 9901 §7.1 steps 3 to 5 and returns the processed payload. */
    private static ObjectNode disclose(
            IssuerSignedJWT jwt, Segment segment, SignatureVerifierContext verifier, String label)
            throws ChainException {
        try {
            jwt.verifySdHashAlgorithm();
        } catch (VerificationException e) {
            throw new ChainException(label + " has the _sd_alg " + jwt.getSdHashAlg() + ", which is not accepted", e);
        }
        JsonNode disclosed;
        try {
            // The library hashes every Disclosure with _sd_alg while it builds this context.
            disclosed = new SdJwtVerificationContext(jwt, segment.disclosures())
                    .verifyIssuance(List.of(verifier), NO_CLAIM_CHECKS, null);
        } catch (VerificationException e) {
            throw new ChainException(label + ": " + e.getMessage(), e);
        } catch (RuntimeException e) {
            // The library maps Disclosures by digest and fails on a duplicate or malformed one.
            throw new ChainException(label + " has a malformed or repeated Disclosure", e);
        }
        if (!(disclosed instanceof ObjectNode object)) {
            throw new ChainException(label + " has no JSON object payload");
        }
        return object;
    }

    private static void checkSignedClaims(IssuerSignedJWT jwt, JsonNode disclosed, List<String> names, String label)
            throws ChainException {
        for (String name : names) {
            if (disclosed.has(name) && !jwt.getPayload().has(name)) {
                throw new ChainException(
                        label + " has " + name + " in a Disclosure, but it must be in the signed payload");
            }
        }
    }

    /** Checks exp and nbf with the clock skew and returns exp, or Long.MAX_VALUE without one. */
    private static long checkValidity(JsonNode claims, String owner, boolean expRequired, long now, long skew)
            throws ChainException {
        OptionalLong exp = NumericDates.read(claims, "exp", owner);
        if (exp.isEmpty() && expRequired) {
            throw new ChainException(owner + " has no exp claim");
        }
        if (exp.isPresent() && now >= exp.getAsLong() + skew) {
            throw new ChainException(owner + " expired at " + exp.getAsLong());
        }
        OptionalLong nbf = NumericDates.read(claims, "nbf", owner);
        if (nbf.isPresent() && now + skew < nbf.getAsLong()) {
            throw new ChainException(owner + " is not valid before " + nbf.getAsLong());
        }
        OptionalLong iat = NumericDates.read(claims, "iat", owner);
        if (iat.isPresent() && now + skew < iat.getAsLong()) {
            throw new ChainException(owner + " has an iat in the future");
        }
        return exp.orElse(Long.MAX_VALUE);
    }

    /**
     * The claims that RFC 9901 §4.3 requires in a KB-JWT besides sd_hash. §6 step 3.1 validates a
     * KB-SD-JWT only as RFC 9901 §7.1 describes, and only step 5.2 compares aud and nonce with the
     * request, for the Key Binding JWT. So aud and nonce of a KB-SD-JWT must be present but may
     * hold any value.
     */
    private static void checkKeyBindingClaims(JsonNode payload, String label) throws ChainException {
        NumericDates.require(payload, "iat", label);
        for (String name : List.of("aud", "nonce")) {
            JsonNode value = payload.get(name);
            if (value == null || !value.isTextual() || value.textValue().isEmpty()) {
                throw new ChainException(label + " has no " + name + " string");
            }
        }
    }

    /**
     * §6 steps 3.3 and 3.4. §5.1.4: "Both sd_hash and issuer_jwt_hash use the hash algorithm of the
     * preceding Issuer-signed JWT or KB-SD-JWT+KB".
     */
    private static void checkPrecedingHash(
            JsonNode payload, Segment preceding, IssuerSignedJWT precedingJwt, String label) throws ChainException {
        String claim = "sd_hash";
        String input = preceding.raw();
        if (!payload.has(claim)) {
            // §5.1.4: issuer_jwt_hash "hashes over only the preceding Issuer-signed jwt or
            // KB-SD-JWT+KB and not any disclosures".
            claim = "issuer_jwt_hash";
            input = preceding.jwt();
            if (!payload.has(claim)) {
                throw new ChainException(label + " has neither sd_hash nor issuer_jwt_hash");
            }
        }
        String expected = SdJwtUtils.hashAndBase64EncodeNoPad(input, precedingJwt.getSdHashAlg());
        JsonNode actual = payload.get(claim);
        if (!actual.isTextual() || !expected.equals(actual.textValue())) {
            throw new ChainException("the " + claim + " of " + label + " does not match the preceding component");
        }
    }

    /** §5.1.4 and §6 step 3.2. */
    private static ObjectNode delegatePayload(JsonNode payload, JsonNode disclosed, String label)
            throws ChainException {
        JsonNode elements = payload.get("delegate_payload");
        if (elements == null || !elements.isArray() || elements.isEmpty()) {
            throw new ChainException(label + " has no non-empty delegate_payload array");
        }
        // §5.1.4: "If it contains more than one element then they MUST all be replaced with disclosures."
        if (elements.size() > 1) {
            for (JsonNode element : elements) {
                if (!isDigestPlaceholder(element)) {
                    throw new ChainException(
                            label + " has a delegate_payload with more than 1 element that is not a digest");
                }
            }
        }
        // §6 step 3.2: "Verify that there is exactly one disclosed element in the delegate_payload array."
        JsonNode disclosedElements = disclosed.get("delegate_payload");
        if (disclosedElements == null || !disclosedElements.isArray() || disclosedElements.size() != 1) {
            throw new ChainException(label + " must disclose exactly 1 element of delegate_payload");
        }
        if (!(disclosedElements.get(0) instanceof ObjectNode delegatePayload)) {
            throw new ChainException("the disclosed delegate_payload element of " + label + " is not a JSON object");
        }
        return delegatePayload;
    }

    /**
     * Refuses a time claim of the Delegate Payload that a nested Disclosure adds. The element as it
     * stands in delegate_payload, or as its array element Disclosure carries it, must hold the claim.
     */
    private static void checkDelegateSignedClaims(JsonNode signedPayload, ObjectNode delegatePayload, String label)
            throws ChainException {
        for (String name : DELEGATE_SIGNED_CLAIMS) {
            if (delegatePayload.has(name) && !signedPayload.has(name)) {
                throw new ChainException(label + " has " + name + " in a nested Disclosure, but it must be in the"
                        + " Delegate Payload itself");
            }
        }
    }

    /** The decoded Disclosures of a segment, keyed by their digest. */
    private static Map<String, JsonNode> disclosuresByDigest(IssuerSignedJWT jwt, Segment segment, String label)
            throws ChainException {
        Map<String, JsonNode> disclosures = new HashMap<>();
        for (String disclosure : segment.disclosures()) {
            try {
                disclosures.put(
                        SdJwtUtils.hashAndBase64EncodeNoPad(disclosure, jwt.getSdHashAlg()),
                        JsonSerialization.mapper.readTree(Base64Url.decode(disclosure)));
            } catch (IOException | RuntimeException e) {
                throw new ChainException(label + " has a malformed Disclosure", e);
            }
        }
        return disclosures;
    }

    private static JsonNode signedDelegatePayload(
            IssuerSignedJWT linkJwt, Map<String, JsonNode> disclosures, String label) throws ChainException {
        JsonNode elements = linkJwt.getPayload().get("delegate_payload");
        if (elements.size() == 1 && !isDigestPlaceholder(elements.get(0))) {
            return elements.get(0);
        }
        for (JsonNode element : elements) {
            JsonNode disclosure = isDigestPlaceholder(element)
                    ? disclosures.get(element.get("...").textValue())
                    : null;
            // RFC 9901 §4.2.2: an array element Disclosure is [salt, value].
            if (disclosure != null && disclosure.isArray() && disclosure.size() == 2) {
                return disclosure.get(1);
            }
        }
        throw new ChainException(label + " has no Disclosure for its delegate_payload element");
    }

    /**
     * RFC 9901 §7.1 drops a digest that no presented Disclosure matches, so the disclosed Delegate
     * Payload no longer shows where the agent left a part out. This walks the signed element and
     * collects the path of every object and array that holds such a digest. A decoy digest (RFC 9901
     * §4.2.5) looks the same and is collected too.
     */
    private static void collectWithheld(
            JsonNode node, List<String> path, Map<String, JsonNode> disclosures, Set<List<String>> withheld) {
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> member : node.properties()) {
                if (!"_sd".equals(member.getKey())) {
                    collectWithheld(member.getValue(), append(path, member.getKey()), disclosures, withheld);
                }
            }
            for (JsonNode digest : node.path("_sd")) {
                JsonNode disclosure = disclosures.get(digest.asText());
                // RFC 9901 §4.2.1: an object property Disclosure is [salt, name, value].
                if (disclosure != null && disclosure.isArray() && disclosure.size() == 3) {
                    collectWithheld(
                            disclosure.get(2), append(path, disclosure.get(1).asText()), disclosures, withheld);
                } else {
                    withheld.add(path);
                }
            }
        } else if (node.isArray()) {
            int index = 0;
            for (JsonNode element : node) {
                JsonNode value = element;
                if (isDigestPlaceholder(element)) {
                    JsonNode disclosure = disclosures.get(element.get("...").textValue());
                    if (disclosure == null || !disclosure.isArray() || disclosure.size() != 2) {
                        withheld.add(path);
                        continue;
                    }
                    value = disclosure.get(1);
                }
                collectWithheld(value, append(path, String.valueOf(index++)), disclosures, withheld);
            }
        }
    }

    private static List<String> append(List<String> path, String member) {
        List<String> longer = new ArrayList<>(path);
        longer.add(member);
        return List.copyOf(longer);
    }

    /** An array element of the form {"...": "<digest>"} (RFC 9901 §4.2.4.2). */
    private static boolean isDigestPlaceholder(JsonNode element) {
        return element.isObject() && element.size() == 1 && element.path("...").isTextual();
    }

    /** §6 steps 5.2 and 5.3. */
    private static KeyBinding checkKeyBindingJwt(
            String jws,
            Segment last,
            IssuerSignedJWT lastJwt,
            ObjectNode lastDelegatePayload,
            String audience,
            long now)
            throws ChainException {
        String label = "the Key Binding JWT";
        IssuerSignedJWT keyBinding = parseJwt(jws, label);
        String type = keyBinding.getJwsHeader().getType();
        if (!TYPE_KB_JWT.equals(type)) {
            throw new ChainException(label + " has typ " + type + ", expected " + TYPE_KB_JWT);
        }
        String lastLabel = "the Delegate Payload of the last KB-SD-JWT";
        JWK holderKey = JwkVerifiers.confirmationKey(lastDelegatePayload, lastLabel);
        SignatureVerifierContext verifier = verifierFor(holderKey, keyBinding, label);
        verifySignature(keyBinding, List.of(verifier), label, "the cnf key of " + lastLabel);

        ObjectNode payload = keyBinding.getPayload();
        checkKeyBindingClaims(payload, label);
        // §5.1.3: the sd_hash of the Key Binding JWT "is calculated over the preceding KB-SD-JWT and
        // its associated disclosures".
        String expected = SdJwtUtils.hashAndBase64EncodeNoPad(last.raw(), lastJwt.getSdHashAlg());
        JsonNode sdHash = payload.get("sd_hash");
        if (sdHash == null || !sdHash.isTextual() || !expected.equals(sdHash.textValue())) {
            throw new ChainException("the sd_hash of " + label + " does not match the last KB-SD-JWT");
        }

        long skew = CLOCK_SKEW.toSeconds();
        // RFC 9901 §7.3 step 5.e and 5.f bind the Key Binding JWT to this request. checkValidity refuses an
        // iat in the future.
        long iat = NumericDates.require(payload, "iat", label);
        if (now >= iat + KEY_BINDING_MAX_AGE.toSeconds() + skew) {
            throw new ChainException(label + " is older than " + KEY_BINDING_MAX_AGE.toSeconds() + " seconds");
        }
        String aud = payload.get("aud").textValue();
        if (!audience.equals(aud)) {
            throw new ChainException(label + " has aud " + aud + ", expected " + audience);
        }
        long expiresAt = checkValidity(payload, label, false, now, skew);
        return new KeyBinding(payload.get("nonce").textValue(), expiresAt);
    }
}
