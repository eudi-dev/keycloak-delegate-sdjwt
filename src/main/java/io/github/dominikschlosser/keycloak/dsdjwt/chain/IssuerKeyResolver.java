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

import java.util.List;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;

/** Finds the trusted keys that may have signed a JWS of a credential issuer. */
@FunctionalInterface
public interface IssuerKeyResolver {

    /**
     * Returns the candidate verifiers for a JWS with this header and the iss claim of the credential.
     * Every key must belong to that issuer. An empty list or an exception means the issuer is not
     * trusted.
     */
    List<SignatureVerifierContext> resolve(JWSHeader header, String issuer) throws ChainException;
}
