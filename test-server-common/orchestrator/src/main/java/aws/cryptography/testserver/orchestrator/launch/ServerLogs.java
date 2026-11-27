package aws.cryptography.testserver.orchestrator.launch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/** Reads a launched server's log file to explain why it stopped. */
final class ServerLogs {

    private static final int TAIL_LINES = 20;

    private ServerLogs() {
    }

    /** @return the file the server's output goes to, or null when it is not a file. */
    static Path of(ProcessBuilder processBuilder) {
        ProcessBuilder.Redirect redirect = processBuilder.redirectOutput();
        return redirect.file() == null ? null : redirect.file().toPath();
    }

    /** @return the last lines of {@code log} as a message suffix, or "" when there are none. */
    static String tail(Path log) {
        List<String> lines = read(log);
        if (lines.isEmpty()) {
            return "";
        }
        List<String> tail = lines.subList(Math.max(0, lines.size() - TAIL_LINES), lines.size());
        return "; last lines of " + log + ":\n    " + String.join("\n    ", tail);
    }

    /** @return true iff {@code log} says the server could not bind because the address was in use. */
    static boolean reportsAddressInUse(Path log) {
        for (String line : read(log)) {
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.contains("address already in use") || lower.contains("eaddrinuse")
                    || lower.contains("address in use")) {
                return true;
            }
        }
        return false;
    }

    private static List<String> read(Path log) {
        if (log == null) {
            return List.of();
        }
        try {
            return new String(Files.readAllBytes(log), StandardCharsets.UTF_8).lines().toList();
        } catch (IOException | RuntimeException e) {
            return List.of();
        }
    }
}
