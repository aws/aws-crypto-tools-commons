package aws.cryptography.esdk.testserver.orchestrator.launch;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

/**
 * Process-tree termination for launched {@code Language_Server} subprocesses.
 * A server launch typically fans out into children (a Gradle daemon-less run,
 * a Python venv interpreter), so stopping only the direct child leaks the
 * actual listener — the {@code pkill -P} + {@code lsof -ti tcp:<port>} problem
 * today's Makefile solves. {@link #killTree} destroys the root <em>and every
 * descendant</em>, escalating to {@code destroyForcibly} for survivors
 * (Requirements 2.6, 2.11).
 */
final class ProcessTrees {

    private static final Duration GRACEFUL_WAIT = Duration.ofSeconds(5);
    private static final Duration FORCIBLE_WAIT = Duration.ofSeconds(5);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(100);

    private ProcessTrees() {
    }

    /**
     * Destroy {@code root} and its whole descendant tree: graceful destroy
     * first, then {@code destroyForcibly} for anything still alive.
     *
     * @return true iff every process in the tree terminated
     */
    static boolean killTree(ProcessHandle root) {
        // Snapshot the descendants BEFORE destroying the root — children may
        // reparent (and become invisible to descendants()) once the root dies.
        List<ProcessHandle> tree =
            Stream.concat(Stream.of(root), root.descendants()).toList();

        tree.forEach(ProcessHandle::destroy);
        if (awaitTerminated(tree, GRACEFUL_WAIT)) {
            return true;
        }
        tree.forEach(ProcessHandle::destroyForcibly);
        return awaitTerminated(tree, FORCIBLE_WAIT);
    }

    /** Poll until every handle in {@code tree} is dead or {@code timeout} elapses. */
    private static boolean awaitTerminated(List<ProcessHandle> tree, Duration timeout) {
        Instant deadline = Instant.now().plus(timeout);
        while (true) {
            if (tree.stream().noneMatch(ProcessHandle::isAlive)) {
                return true;
            }
            if (!Instant.now().isBefore(deadline)) {
                return false;
            }
            Ports.sleep(POLL_INTERVAL);
        }
    }
}
