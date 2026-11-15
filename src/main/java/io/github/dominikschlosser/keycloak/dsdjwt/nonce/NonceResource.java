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

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resource.RealmResourceProvider;

/** Serves POST /realms/{realm}/delegate-sd-jwt/nonce to confidential clients. */
public class NonceResource implements RealmResourceProvider {

    private final KeycloakSession session;
    private final long lifespanSeconds;

    public NonceResource(KeycloakSession session, long lifespanSeconds) {
        this.session = session;
        this.lifespanSeconds = lifespanSeconds;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @POST
    @Path("nonce")
    @Produces(MediaType.APPLICATION_JSON)
    public Response nonce() {
        RealmModel realm = session.getContext().getRealm();
        EventBuilder event =
                new EventBuilder(realm, session, session.getContext().getConnection()).event(EventType.CLIENT_LOGIN);
        ClientModel client =
                AuthorizeClientUtil.authorizeClient(session, event, null).getClient();
        if (client.isPublicClient()) {
            throw refuse(
                    event, OAuthErrorException.INVALID_CLIENT, "a public client cannot exchange a Delegate SD-JWT");
        }
        String nonce = NonceStore.issue(session, realm, client, lifespanSeconds);
        event.success();
        CacheControl noStore = new CacheControl();
        noStore.setNoStore(true);
        return Response.ok(Map.of("nonce", nonce, "expires_in", lifespanSeconds))
                .cacheControl(noStore)
                .build();
    }

    private static ErrorResponseException refuse(EventBuilder event, String error, String description) {
        event.detail(Details.REASON, description).error(error);
        return new ErrorResponseException(error, description, Response.Status.BAD_REQUEST);
    }

    @Override
    public void close() {}
}
