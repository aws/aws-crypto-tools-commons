package aws.cryptography.esdk.testserver.orchestrator.run;

/**
 * Raised when the single Java {@code Tests} suite would be run with no target
 * endpoint configured (Requirement 7.4). The run must stop before executing any
 * Test and record no partial results.
 */
public class MissingRuntimeConfigException extends Exception {
    public MissingRuntimeConfigException(String message) {
        super(message);
    }
}
