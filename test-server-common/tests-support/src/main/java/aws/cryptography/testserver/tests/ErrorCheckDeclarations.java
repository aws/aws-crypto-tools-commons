package aws.cryptography.testserver.tests;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.OptionalInt;

/**
 * Which error checks each server has turned on, and at which version.
 *
 * <p>The orchestrator reads the {@code errors} block of each server's
 * {@code feature-config.json} and passes it in {@code testserver.errorChecks}
 * (or the {@code TESTSERVER_ERROR_CHECKS} environment variable), for example
 * {@code rust:1:aws-crypto-tools-rust:kind=2;service=1;message=unsupported}.
 *
 * <p>A check is off for a server when the server marks it {@code unsupported},
 * leaves it out, or declares no error checks at all.
 * That is the normal case today, so a missing declaration is never an error.
 */
public final class ErrorCheckDeclarations {

    public static final String ERROR_CHECKS_PROPERTY = "testserver.errorChecks";
    public static final String ERROR_CHECKS_ENV = "TESTSERVER_ERROR_CHECKS";

    private static final String UNSUPPORTED = "unsupported";

    private static volatile ErrorCheckDeclarations instance;

    /** {@code language:major:repo} to (check to version). Unsupported checks are not stored. */
    private final Map<String, Map<String, Integer>> versions;

    private ErrorCheckDeclarations(Map<String, Map<String, Integer>> versions) {
        this.versions = versions;
    }

    /** The registry for this JVM, read from the runtime property on first use. */
    public static ErrorCheckDeclarations shared() {
        ErrorCheckDeclarations local = instance;
        if (local == null) {
            synchronized (ErrorCheckDeclarations.class) {
                local = instance;
                if (local == null) {
                    String raw = System.getProperty(ERROR_CHECKS_PROPERTY);
                    if (raw == null || raw.isBlank()) {
                        raw = System.getenv(ERROR_CHECKS_ENV);
                    }
                    local = parse(raw);
                    instance = local;
                }
            }
        }
        return local;
    }

    /** Parse a {@value #ERROR_CHECKS_PROPERTY} value. Blank or {@code null} means no server has checks. */
    public static ErrorCheckDeclarations parse(String raw) {
        Map<String, Map<String, Integer>> bySource = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) {
            return new ErrorCheckDeclarations(bySource);
        }
        for (String entry : raw.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            // The check list has no colons, so the fourth part is all of it.
            String[] parts = trimmed.split(":", 4);
            if (parts.length != 4) {
                throw new IllegalArgumentException("malformed " + ERROR_CHECKS_PROPERTY
                    + " entry (expected language:major:repo:check=version[;check=version...]): "
                    + trimmed);
            }
            String source = parts[0].trim() + ":" + parts[1].trim() + ":" + parts[2].trim();
            if (bySource.containsKey(source)) {
                throw new IllegalArgumentException(
                    "duplicate source in " + ERROR_CHECKS_PROPERTY + ": " + source);
            }
            bySource.put(source, parseChecks(source, parts[3]));
        }
        return new ErrorCheckDeclarations(bySource);
    }

    private static Map<String, Integer> parseChecks(String source, String raw) {
        Map<String, Integer> byCheck = new LinkedHashMap<>();
        for (String declaration : raw.split(";")) {
            String trimmed = declaration.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            if (eq < 1) {
                throw new IllegalArgumentException("malformed error check for source '" + source
                    + "' (expected check=version): " + trimmed);
            }
            String check = trimmed.substring(0, eq).trim();
            String value = trimmed.substring(eq + 1).trim();
            if (value.equals(UNSUPPORTED)) {
                continue;
            }
            int version;
            try {
                version = Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("error check '" + check + "' for source '"
                    + source + "' must be a version or 'unsupported': " + value, e);
            }
            if (version < 1) {
                throw new IllegalArgumentException("error check '" + check + "' for source '"
                    + source + "' must have a version of 1 or more: " + value);
            }
            byCheck.put(check, version);
        }
        return byCheck;
    }

    /** The version that {@code languageServer} runs {@code check} at, or empty when the check is off. */
    public OptionalInt version(LanguageServerTarget languageServer, String check) {
        Map<String, Integer> byCheck = versions.get(
            languageServer.language() + ":" + languageServer.majorVersion() + ":" + languageServer.repo());
        if (byCheck == null || !byCheck.containsKey(check)) {
            return OptionalInt.empty();
        }
        return OptionalInt.of(byCheck.get(check));
    }
}
