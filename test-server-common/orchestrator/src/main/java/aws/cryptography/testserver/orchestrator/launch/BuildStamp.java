package aws.cryptography.testserver.orchestrator.launch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * A {@code .<name>-build-stamp} file recording the commit a directory's
 * build outputs were produced from, so a reused clone of the same commit
 * skips its build.
 */
final class BuildStamp {

    private final Path stampFile;

    /**
     * @param directory the directory holding the stamp file
     * @param name      the stamp file is {@code .<name>-build-stamp}
     */
    BuildStamp(Path directory, String name) {
        this.stampFile = directory.resolve("." + name + "-build-stamp");
    }

    /**
     * Whether the stamp records {@code commit} and every output exists. A
     * {@code dirty} working tree is never up to date: the commit does not
     * capture its uncommitted edits. {@code null} dirty means a clone.
     */
    boolean upToDate(String commit, Boolean dirty, List<Path> outputs) {
        if (commit == null || Boolean.TRUE.equals(dirty) || !Files.isRegularFile(stampFile)) {
            return false;
        }
        for (Path output : outputs) {
            if (!Files.exists(output)) {
                return false;
            }
        }
        try {
            return Files.readString(stampFile, StandardCharsets.UTF_8).trim().equals(commit);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Record a successful build of {@code commit}. A dirty working tree or a
     * {@code null} commit clears the stamp instead, so a later clean build of
     * the same commit is not skipped.
     */
    void write(String language, String commit, Boolean dirty) throws ServerLaunchException {
        try {
            if (commit == null || Boolean.TRUE.equals(dirty)) {
                Files.deleteIfExists(stampFile);
            } else {
                Files.writeString(stampFile, commit, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new ServerLaunchException(language, ServerLaunchException.Category.BUILD,
                "failed to write the " + language + " build stamp " + stampFile
                    + ": " + e.getMessage(), e);
        }
    }
}
