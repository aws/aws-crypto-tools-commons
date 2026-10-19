package aws.cryptography.testserver.orchestrator.launch;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;

/**
 * The shared subprocess launch machinery every language launch plan builds on
 * (design "Launcher contract"): pre-launch port-availability probe → spawn the
 * server subprocess → poll TCP-connect readiness on the configured port →
 * return a {@link LaunchedServer} wrapping the process.
 *
 * <p>Ordered guarantees:
 * <ol>
 *   <li><b>Pre-launch probe.</b> If the configured port is already bound, the
 *       launch aborts with category {@code PORT} <em>before any process is
 *       spawned</em> — a pre-existing binder is a launch failure, never flaky
 *       readiness (Requirement 2.5).</li>
 *   <li><b>Spawn.</b> A process that cannot start, or that exits before ever
 *       accepting a connection, aborts with category {@code BUILD}.</li>
 *   <li><b>Readiness.</b> Reachability is determined only by the server
 *       accepting a TCP connection on its configured port (Requirement 2.9),
 *       polled up to the readiness timeout — 180 seconds by default
 *       (Requirement 2.5), overridable via the
 *       {@value #READY_TIMEOUT_ENV_VAR} environment variable and injectable
 *       for tests.</li>
 *   <li><b>Timeout.</b> On readiness timeout the spawned process tree is
 *       killed, then the launch aborts with category {@code TIMEOUT}.</li>
 * </ol>
 *
 * <p>The returned {@link LaunchedServer}'s {@code close()} kills the whole
 * process tree and verifies the port no longer accepts connections
 * (Requirements 2.6, 2.11).
 */
public final class SubprocessLauncher {

    /** Readiness window: reachable within 180 seconds of launch (Requirement 2.5). */
    public static final Duration DEFAULT_READINESS_TIMEOUT = Duration.ofSeconds(180);

    /**
     * Environment variable overriding the default readiness window, in whole
     * seconds. Launch plans that build inside the readiness window (the Java
     * plan's {@code gradlew runServer}) need a larger window when many servers
     * build concurrently on a small host, e.g. an orchestrated CI run.
     */
    public static final String READY_TIMEOUT_ENV_VAR =
        "TESTSERVER_READY_TIMEOUT_SECONDS";

    private static final Duration READINESS_POLL_INTERVAL = Duration.ofMillis(250);

    private final Duration readinessTimeout;

    public SubprocessLauncher() {
        this(defaultReadinessTimeout(System.getenv(READY_TIMEOUT_ENV_VAR)));
    }

    /**
     * The readiness window default construction uses: {@code envValue} seconds
     * when set ({@link #READY_TIMEOUT_ENV_VAR}), else
     * {@link #DEFAULT_READINESS_TIMEOUT}. A set but non-numeric or
     * non-positive value is a configuration error naming the variable.
     */
    static Duration defaultReadinessTimeout(String envValue) {
        if (envValue == null || envValue.isBlank()) {
            return DEFAULT_READINESS_TIMEOUT;
        }
        long seconds;
        try {
            seconds = Long.parseLong(envValue.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(READY_TIMEOUT_ENV_VAR
                + " must be a positive whole number of seconds (was '" + envValue + "')", e);
        }
        if (seconds <= 0) {
            throw new IllegalArgumentException(READY_TIMEOUT_ENV_VAR
                + " must be a positive whole number of seconds (was '" + envValue + "')");
        }
        return Duration.ofSeconds(seconds);
    }

    /** @param readinessTimeout the readiness window (injectable for tests). */
    public SubprocessLauncher(Duration readinessTimeout) {
        if (readinessTimeout == null || readinessTimeout.isNegative() || readinessTimeout.isZero()) {
            throw new IllegalArgumentException("readinessTimeout must be positive");
        }
        this.readinessTimeout = readinessTimeout;
    }

    /**
     * Launch {@code processBuilder} as {@code language}'s server subprocess and
     * wait for it to accept a TCP connection on {@code port}.
     *
     * @param language       the language this server implements (names failures)
     * @param port           the configured port from the effective entry
     * @param processBuilder the fully prepared server command (directory,
     *                       environment, and output redirection are the launch
     *                       plan's responsibility)
     * @return the running server, reachable at {@code http://127.0.0.1:<port>}
     * @throws ServerLaunchException {@code PORT} if the port is bound before
     *     spawn, {@code BUILD} if the process cannot start or exits before
     *     readiness, {@code TIMEOUT} if the port never accepts a connection
     *     within the readiness window (the process tree is killed first)
     */
    public LaunchedServer launch(String language, int port, ProcessBuilder processBuilder)
            throws ServerLaunchException {
        // 1. Pre-launch port availability probe — before spawning anything.
        if (!Ports.isBindable(port)) {
            throw new ServerLaunchException(language,
                ServerLaunchException.Category.PORT,
                "port " + port + " is already in use before launch; cannot bind the "
                    + language + " Language_Server");
        }

        // 2. Spawn the server subprocess.
        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new ServerLaunchException(language,
                ServerLaunchException.Category.BUILD,
                "failed to start the " + language + " Language_Server process ("
                    + String.join(" ", processBuilder.command()) + "): " + e.getMessage(), e);
        }

        // 3. Poll readiness: a successful TCP connect to the configured port
        //    is the only reachability signal (Requirement 2.9).
        Instant spawnedAt = Instant.now();
        Instant deadline = spawnedAt.plus(readinessTimeout);
        while (Instant.now().isBefore(deadline)) {
            if (Ports.acceptsConnection(port)) {
                LaunchTimings.log(language, "server start (spawn to TCP ready)", spawnedAt);
                URI endpoint = URI.create("http://127.0.0.1:" + port);
                return LaunchedServer.forProcess(language, port, endpoint, process);
            }
            if (!process.isAlive()) {
                throw new ServerLaunchException(language,
                    ServerLaunchException.Category.BUILD,
                    "the " + language + " Language_Server process exited with code "
                        + process.exitValue() + " before accepting connections on port " + port);
            }
            Ports.sleep(READINESS_POLL_INTERVAL);
        }

        // 4. Readiness timeout: kill the tree we spawned, then abort (Req 2.5).
        ProcessTrees.killTree(process.toHandle());
        throw new ServerLaunchException(language,
            ServerLaunchException.Category.TIMEOUT,
            "the " + language + " Language_Server did not accept a TCP connection on port "
                + port + " within " + readinessTimeout.toSeconds() + " seconds of launch");
    }
}
