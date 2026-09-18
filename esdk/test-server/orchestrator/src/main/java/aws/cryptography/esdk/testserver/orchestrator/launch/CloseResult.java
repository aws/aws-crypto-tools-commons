package aws.cryptography.esdk.testserver.orchestrator.launch;

/**
 * The outcome of stopping a launched {@code Language_Server} (design "Launcher
 * contract"): {@link Status#STOPPED} when the whole process tree terminated and
 * the configured port no longer accepts connections, or
 * {@link Status#STILL_RUNNING} — naming the affected language — when either
 * check fails. A {@code STILL_RUNNING} result is a cleanup failure the
 * orchestrator must report, identifying each language whose server was not
 * stopped (Requirements 2.6, 2.11).
 *
 * @param status   whether the server actually stopped
 * @param language the affected language for a {@code STILL_RUNNING} result
 *                 (Requirement 2.11); {@code null} for {@code STOPPED}
 */
public record CloseResult(Status status, String language) {

    /** The two possible teardown outcomes. */
    public enum Status {
        /** Process tree terminated and the port no longer accepts connections. */
        STOPPED,
        /** The process tree or the port survived teardown — a cleanup failure. */
        STILL_RUNNING
    }

    public CloseResult {
        if (status == null) {
            throw new IllegalArgumentException("a CloseResult requires a status");
        }
        if (status == Status.STILL_RUNNING && (language == null || language.isBlank())) {
            throw new IllegalArgumentException(
                "a STILL_RUNNING result must name the language (Requirement 2.11)");
        }
        if (status == Status.STOPPED && language != null) {
            throw new IllegalArgumentException("a STOPPED result carries no language");
        }
    }

    /** A clean stop: the process tree is gone and the port is free. */
    public static CloseResult stopped() {
        return new CloseResult(Status.STOPPED, null);
    }

    /** A cleanup failure naming the language whose server was not stopped. */
    public static CloseResult stillRunning(String language) {
        return new CloseResult(Status.STILL_RUNNING, language);
    }

    /** @return true iff the server stopped cleanly. */
    public boolean isStopped() {
        return status == Status.STOPPED;
    }
}
