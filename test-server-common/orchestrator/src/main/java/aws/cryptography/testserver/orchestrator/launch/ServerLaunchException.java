package aws.cryptography.testserver.orchestrator.launch;

/**
 * An abort raised while resolving, building, or launching a
 * {@code Language_Server}. Every instance names the offending language and a
 * {@link Category}, so the orchestrator can run zero {@code Tests} and report a
 * failure identifying the language and the cause (Requirement 2.5).
 */
public class ServerLaunchException extends Exception {

    /** The class of launch abort (design "Launcher contract": RESOLVE | BUILD | PORT | TIMEOUT). */
    public enum Category {
        /** The resolved sources this launch needs are missing or unusable (Req 2.5). */
        RESOLVE,
        /** Building the server/library, or spawning the server process, failed (Req 2.5). */
        BUILD,
        /**
         * The configured port was already bound before launch — a pre-existing
         * binder is a launch failure, not flaky readiness (Req 2.5).
         */
        PORT,
        /** The server did not accept a TCP connection within the readiness window (Req 2.5, 2.9). */
        TIMEOUT
    }

    private final String language;
    private final Category category;

    public ServerLaunchException(String language, Category category, String message) {
        super(message);
        this.language = language;
        this.category = category;
    }

    public ServerLaunchException(String language, Category category, String message, Throwable cause) {
        super(message, cause);
        this.language = language;
        this.category = category;
    }

    public String language() {
        return language;
    }

    public Category category() {
        return category;
    }
}
