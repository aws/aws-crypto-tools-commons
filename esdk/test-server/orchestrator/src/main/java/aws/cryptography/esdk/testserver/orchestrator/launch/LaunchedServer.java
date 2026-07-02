package aws.cryptography.esdk.testserver.orchestrator.launch;

import java.net.URI;

/**
 * A running {@code Language_Server} bound to its configured port (Requirement
 * 9.4). {@link #close()} shuts the server down; the orchestrator closes every
 * launched server after the run.
 */
public final class LaunchedServer implements AutoCloseable {

    private final String language;
    private final int port;
    private final URI endpoint;
    private final AutoCloseable handle;

    public LaunchedServer(String language, int port, URI endpoint, AutoCloseable handle) {
        this.language = language;
        this.port = port;
        this.endpoint = endpoint;
        this.handle = handle;
    }

    public String language() {
        return language;
    }

    public int port() {
        return port;
    }

    /** @return the base endpoint URL the single Java Test_Client should target. */
    public URI endpoint() {
        return endpoint;
    }

    @Override
    public void close() {
        try {
            handle.close();
        } catch (Exception e) {
            // Best-effort shutdown; a failure to stop a server must not mask the run result.
        }
    }
}
