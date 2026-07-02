package aws.cryptography.esdk.testserver.orchestrator.launch;

/**
 * An abort raised while building or launching a {@code Language_Server}. Every
 * instance names the offending language so the orchestrator can report a
 * fail-open failure that identifies the cause (Requirements 9.6, 10.4, 11.4,
 * 12.8) before any {@code Tests} run.
 */
public class ServerLaunchException extends Exception {

    /** The class of launch abort, so the reporter can describe the cause precisely. */
    public enum Category {
        /** The resolved reference (commit/artifact/head) could not be resolved (Req 10.4, 12.8). */
        UNRESOLVABLE_SOURCE,
        /** Live/submodule source could not be built (Req 11.4, 12.8). */
        BUILD_FAILURE,
        /** The configured port was already in use when binding (Req 9.6). */
        PORT_CONFLICT,
        /** No server implementation exists for this language yet (parked; tasks 9-10). */
        UNSUPPORTED_LANGUAGE
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
