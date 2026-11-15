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

package io.github.dominikschlosser.keycloak.dsdjwt.nonce;

import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import java.util.Map;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Single use nonces for the Key Binding JWT, kept in the single use object store of Keycloak. */
public final class NonceStore {

    private static final String KEY_PREFIX = "dsdjwt.nonce.";

    private NonceStore() {}

    /** Issues a nonce that only this client can use once in this realm. */
    public static String issue(KeycloakSession session, RealmModel realm, ClientModel client, long lifespanSeconds) {
        String nonce = Base64Url.encode(SecretGenerator.getInstance().randomBytes(32));
        session.singleUseObjects().put(key(realm, client, nonce), lifespanSeconds, Map.of());
        return nonce;
    }

    public static void consume(KeycloakSession session, RealmModel realm, ClientModel client, String nonce)
            throws ChainException {
        // remove is atomic across cluster nodes, so 2 exchanges cannot both consume the nonce. The key holds
        // the client, so another client cannot use up the nonce.
        if (session.singleUseObjects().remove(key(realm, client, nonce)) == null) {
            throw new ChainException(
                    "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
        }
    }

    private static String key(RealmModel realm, ClientModel client, String nonce) {
        return KEY_PREFIX + realm.getId() + "." + client.getId() + "." + nonce;
    }
}
