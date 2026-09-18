package aws.cryptography.esdk.testserver.orchestrator.launch;

import java.net.URI;
import java.time.Duration;
import java.util.function.BooleanSupplier;

/**
 * A running {@code Language_Server} bound to its configured port (Requirement
 * 2.1), per the design "Launcher contract": {@code language}, {@code port},
 * {@code endpoint}, and {@link #close()} returning a {@link CloseResult}.
 *
 * <p>{@link #close()} tears the server down and reports honestly: for a
 * subprocess-backed server ({@link #forProcess}) it kills the whole process
 * tree (Gradle/venv children included) and then verifies the configured port
 * no longer accepts connections; anything short of that is
 * {@code STILL_RUNNING} naming the language — a cleanup failure the
 * orchestrator reports (Requirements 2.6, 2.11). {@code close()} is
 * idempotent: repeated calls return the first result.
 *
 * <p>Note on the design sketch's {@code implements AutoCloseable}: Java cannot
 * narrow {@code AutoCloseable.close()}'s {@code void} return, so this class
 * exposes the result-returning {@code close()} without the interface; the
 * orchestrator closes servers explicitly in a {@code finally} block, which is
 * what the design's teardown-in-finally requires anyway.
 */
public final class LaunchedServer {

    /** How a concrete launcher stops its server and verifies the stop. */
    @FunctionalInterface
    public interface Terminator {
        CloseResult terminate();
    }

    /** How long to wait for the OS to release the port after the tree is killed. */
    private static final Duration PORT_RELEASE_WAIT = Duration.ofSeconds(10);

    private final String language;
    private final int port;
    private final URI endpoint;
    private final Terminator terminator;
    private final BooleanSupplier reachabilityProbe;
    private CloseResult closeResult;

    /**
     * A server whose reachability is probed by a real TCP connect to
     * {@code port} (Requirement 2.9).
     */
    public LaunchedServer(String language, int port, URI endpoint, Terminator terminator) {
        this(language, port, endpoint, terminator, () -> Ports.acceptsConnection(port));
    }

    /**
     * A server with an explicit reachability probe — lets test doubles report
     * reachability without binding a real port.
     */
    public LaunchedServer(String language, int port, URI endpoint, Terminator terminator,
            BooleanSupplier reachabilityProbe) {
        this.language = language;
        this.port = port;
        this.endpoint = endpoint;
        this.terminator = terminator;
        this.reachabilityProbe = reachabilityProbe;
    }

    /**
     * A server backed by a launched subprocess: {@code close()} kills the whole
     * process tree, then verifies {@code port} no longer accepts connections
     * (Requirements 2.6, 2.11).
     */
    public static LaunchedServer forProcess(String language, int port, URI endpoint, Process process) {
        return new LaunchedServer(language, port, endpoint, () -> {
            boolean treeTerminated = ProcessTrees.killTree(process.toHandle());
            boolean portReleased = Ports.awaitReleased(port, PORT_RELEASE_WAIT);
            return treeTerminated && portReleased
                ? CloseResult.stopped()
                : CloseResult.stillRunning(language);
        });
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

    /**
     * Whether this server currently accepts a TCP connection on its configured
     * port — the only reachability signal the orchestrator trusts
     * (Requirement 2.9). The pipeline re-checks every launched server through
     * this probe immediately before invoking the test runner, so Tests begin
     * only after every configured Language_Server is reachable
     * (Requirement 2.3).
     */
    public boolean reachable() {
        return reachabilityProbe.getAsBoolean();
    }

    /**
     * Stop the server and verify the stop (Requirement 2.6).
     *
     * @return {@link CloseResult#stopped()} on a verified stop, else
     *     {@link CloseResult#stillRunning} naming this server's language
     *     (Requirement 2.11); never throws
     */
    public CloseResult close() {
        if (closeResult == null) {
            try {
                closeResult = terminator.terminate();
            } catch (RuntimeException e) {
                // Teardown must never mask the run result; a throwing
                // terminator is a cleanup failure naming the language.
                closeResult = CloseResult.stillRunning(language);
            }
        }
        return closeResult;
    }
}
