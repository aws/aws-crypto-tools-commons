package aws.cryptography.testserver.tests;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;
import software.amazon.smithy.java.client.core.error.TransportException;

/**
 * Caches ONE generated Test_Client per base endpoint URL, parameterized on the
 * per-SDK client type. Each SDK's Tests wrap this cache in a thin
 * {@code <SDK>TestServerClients} that supplies the builder function; the cache
 * itself never imports an SDK-specific model or transport.
 *
 * <p>Clients are <strong>cached per endpoint</strong> and reused. A smithy-java
 * client (like an AWS SDK client) is thread-safe and designed to be shared; its
 * JDK {@code HttpClient} keeps a connection pool. The heavily-parameterized
 * Tests make thousands of calls, so building a fresh client per call would open
 * an equal number of short-lived connection pools and hammer each server with
 * connection churn — which surfaced as intermittent
 * {@code TransportException: ... received no bytes} (a reused/closed connection
 * or an overflowed listen backlog). One stable client per endpoint keeps a
 * warm, reusable connection pool and eliminates that churn.
 *
 * <p>{@link #withRetry(Supplier)} is the shared retry primitive: it retries
 * only a smithy-java {@link TransportException} — a dropped or reset connection
 * — and propagates every other outcome on the first attempt, so a Test
 * asserting a modeled error is unaffected.
 */
public final class TestServerClientCache<TClient> {

    private static final int MAX_ATTEMPTS = 4;
    private static final long BASE_BACKOFF_MILLIS = 100L;

    private final Function<URI, TClient> builder;
    private final Map<URI, TClient> clients = new ConcurrentHashMap<>();

    /**
     * @param builder builds one Test_Client per endpoint URL, invoked at most
     *                once per URI over the lifetime of this cache. The builder
     *                must not return {@code null}.
     */
    public TestServerClientCache(Function<URI, TClient> builder) {
        this.builder = Objects.requireNonNull(builder, "builder");
    }

    /** @return a shared, reused Test_Client targeting {@code endpoint}. */
    public TClient forEndpoint(URI endpoint) {
        return clients.computeIfAbsent(endpoint, builder);
    }

    /**
     * Run a single Test_Client RPC, retrying only a {@link TransportException}
     * (a dropped or reset connection, seen as {@code received no bytes} when
     * the matrix drives thousands of calls at once). A modeled client error or
     * any other outcome propagates on the first attempt, so a Test asserting a
     * modeled error is unaffected.
     */
    public static <T> T withRetry(Supplier<T> call) {
        TransportException last = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return call.get();
            } catch (TransportException transportFailure) {
                last = transportFailure;
                if (attempt == MAX_ATTEMPTS) {
                    break;
                }
                try {
                    Thread.sleep(BASE_BACKOFF_MILLIS * attempt);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw transportFailure;
                }
            }
        }
        throw last;
    }
}
