package aws.cryptography.esdk.testserver.orchestrator.config;

import java.nio.file.Path;

/**
 * A configuration file could not be loaded: it is missing from its expected
 * location or is unparseable (malformed JSON, a duplicate key rejected by
 * strict duplicate detection, or a non-object top level). The message always
 * names the expected location when one is known, so failures satisfy
 * Requirements 4.9, 7.4, and 8.10's "name the expected location" clauses.
 */
public final class ConfigurationLoadException extends RuntimeException {

    /** The expected file location, or null for a parse of an in-memory string. */
    private final transient Path expectedLocation;

    public ConfigurationLoadException(String message, Path expectedLocation) {
        super(message);
        this.expectedLocation = expectedLocation;
    }

    public ConfigurationLoadException(String message, Path expectedLocation, Throwable cause) {
        super(message, cause);
        this.expectedLocation = expectedLocation;
    }

    /** @return the expected file location, or null when parsing an in-memory string. */
    public Path expectedLocation() {
        return expectedLocation;
    }
}
