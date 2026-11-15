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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HttpStatusListFetcherTest {

    private static final String TOKEN = "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0.e30.c2ln";

    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger redirectTargetCalls = new AtomicInteger();
    private HttpServer server;
    private CloseableHttpClient client;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/status/1", exchange -> respond(exchange, 200, TOKEN + "\n"));
        server.createContext("/moved", exchange -> {
            exchange.getResponseHeaders().add("Location", url("/target"));
            respond(exchange, 302, "");
        });
        server.createContext("/target", exchange -> {
            redirectTargetCalls.incrementAndGet();
            respond(exchange, 200, TOKEN);
        });
        server.createContext("/slow", exchange -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(exchange, 200, TOKEN);
        });
        server.createContext("/drip", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                while (release.getCount() > 0) {
                    out.write('a');
                    out.flush();
                    release.await(50, TimeUnit.MILLISECONDS);
                }
            } catch (IOException | InterruptedException e) {
                // The client closed the connection.
            }
        });
        server.createContext("/huge", exchange -> respond(exchange, 200, "a".repeat(1024 * 1024 + 1)));
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        client = HttpClients.createDefault();
    }

    @AfterEach
    void stop() throws IOException {
        release.countDown();
        client.close();
        server.stop(0);
    }

    @Test
    void returnsTheToken() throws Exception {
        assertEquals(TOKEN, fetcher(Duration.ofSeconds(5)).fetch(url("/status/1")));
    }

    @Test
    void refusesARedirect() {
        ChainException e = assertThrows(
                ChainException.class, () -> fetcher(Duration.ofSeconds(5)).fetch(url("/moved")));

        assertEquals("the status list at " + url("/moved") + " answered with HTTP 302", e.getMessage());
        assertEquals(0, redirectTargetCalls.get());
    }

    @Test
    void givesUpOnASlowServer() {
        long start = System.nanoTime();

        ChainException e = assertThrows(
                ChainException.class, () -> fetcher(Duration.ofMillis(300)).fetch(url("/slow")));

        assertEquals("the status list at " + url("/slow") + " could not be loaded", e.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(5)) < 0);
    }

    @Test
    void givesUpOnAServerThatSendsTheBodyByteByByte() {
        long start = System.nanoTime();

        ChainException e = assertThrows(ChainException.class, () -> new HttpStatusListFetcher(
                        client, Duration.ofMillis(300), Duration.ofMillis(800))
                .fetch(url("/drip")));

        assertEquals("the status list at " + url("/drip") + " could not be loaded", e.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(5)) < 0);
    }

    @Test
    void refusesAResponseLargerThan1Megabyte() {
        ChainException e = assertThrows(
                ChainException.class, () -> fetcher(Duration.ofSeconds(5)).fetch(url("/huge")));

        assertEquals("the status list at " + url("/huge") + " could not be loaded", e.getMessage());
    }

    private HttpStatusListFetcher fetcher(Duration timeout) {
        return new HttpStatusListFetcher(client, timeout, HttpStatusListFetcher.DEFAULT_DEADLINE);
    }

    private String url(String path) {
        return "http://" + server.getAddress().getHostString() + ":"
                + server.getAddress().getPort() + path;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
