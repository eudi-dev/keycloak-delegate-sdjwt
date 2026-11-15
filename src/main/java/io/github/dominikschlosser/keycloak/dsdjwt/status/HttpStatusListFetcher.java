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

import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;

/** Loads a Status List Token with the HTTP client of Keycloak. */
public final class HttpStatusListFetcher implements StatusListFetcher {

    /** The exchange waits for the status list, so a slow server must not hold the token endpoint. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    /** The socket timeout resets with every packet, so a server that sends 1 byte at a time needs a total limit. */
    public static final Duration DEFAULT_DEADLINE = Duration.ofSeconds(10);

    private static final int MAX_RESPONSE_SIZE = 1024 * 1024;

    private final HttpClient client;
    private final RequestConfig requestConfig;
    private final Duration deadline;

    public HttpStatusListFetcher(HttpClient client, Duration timeout, Duration deadline) {
        this.client = client;
        this.deadline = deadline;
        int millis = Math.toIntExact(timeout.toMillis());
        // A redirect would lead the request to a URI that the credential does not hold.
        this.requestConfig = RequestConfig.custom()
                .setConnectTimeout(millis)
                .setConnectionRequestTimeout(millis)
                .setSocketTimeout(millis)
                .setRedirectsEnabled(false)
                .build();
    }

    @Override
    public String fetch(String uri) throws ChainException {
        HttpGet request;
        try {
            request = new HttpGet(uri);
        } catch (IllegalArgumentException e) {
            throw new ChainException("the status list at " + uri + " could not be loaded", e);
        }
        request.setConfig(requestConfig);
        // draft-ietf-oauth-status-list-21 §8.1: the JWT form has the media type statuslist+jwt.
        request.setHeader("Accept", "application/statuslist+jwt");
        CompletableFuture<Void> abort = CompletableFuture.runAsync(
                request::abort, CompletableFuture.delayedExecutor(deadline.toMillis(), TimeUnit.MILLISECONDS));
        boolean complete = false;
        try {
            HttpResponse response = client.execute(request);
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                throw new ChainException("the status list at " + uri + " answered with HTTP " + status);
            }
            String body = read(response.getEntity());
            EntityUtils.consume(response.getEntity());
            complete = true;
            return body.trim();
        } catch (IOException | RuntimeException e) {
            throw new ChainException("the status list at " + uri + " could not be loaded", e);
        } finally {
            abort.cancel(false);
            if (!complete) {
                // Closing the stream would read the rest of the body, so the connection is dropped instead.
                request.abort();
            }
        }
    }

    private static String read(HttpEntity entity) throws IOException {
        if (entity == null) {
            return "";
        }
        InputStream in = entity.getContent();
        byte[] body = in.readNBytes(MAX_RESPONSE_SIZE + 1);
        if (body.length > MAX_RESPONSE_SIZE) {
            throw new IOException("the response is larger than " + MAX_RESPONSE_SIZE + " bytes");
        }
        return new String(body, StandardCharsets.UTF_8);
    }
}
