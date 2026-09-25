package aws.cryptography.testserver.orchestrator.launch;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A smithy-dafny project whose {@code runtimes/<lang>} directory is a
 * Language_Server's library component (e.g.
 * {@code AwsEncryptionSDK/runtimes/net},
 * {@code AwsCryptographyPrimitives/runtimes/python}). Its generated code is
 * not committed, so the launch plans transpile it with the project's own
 * Makefile before building the server.
 */
final class DafnyProject {

    /** Submodules a smithy-dafny transpile reads, initialized when the repository has them. */
    static final List<String> SUBMODULES = List.of("libraries", "smithy-dafny", "mpl");

    private static final ConcurrentMap<Path, Object> LOCKS = new ConcurrentHashMap<>();

    private DafnyProject() {
    }

    /**
     * The monitor serializing Dafny builds in one repository: servers launch
     * concurrently, and each transpile rewrites shared Dafny sources in place.
     */
    static Object lockFor(Path repositoryRoot) {
        return LOCKS.computeIfAbsent(repositoryRoot.toAbsolutePath().normalize(), root -> new Object());
    }

    /**
     * The smithy-dafny project owning {@code libraryDir}: its grandparent, when
     * {@code libraryDir} sits in a {@code runtimes/} directory next to a Makefile.
     */
    static Optional<Path> of(Path libraryDir) {
        Path runtimes = libraryDir.getParent();
        if (runtimes == null || runtimes.getFileName() == null
                || !"runtimes".equals(runtimes.getFileName().toString())) {
            return Optional.empty();
        }
        Path project = runtimes.getParent();
        return project != null && Files.isRegularFile(project.resolve("Makefile"))
            ? Optional.of(project) : Optional.empty();
    }

    /** The repository root holding {@code project} and its sibling dependencies. */
    static Path repositoryRoot(Path project) {
        return project.getParent();
    }

    /** {@code git submodule update --init --recursive <name>} for each present {@link #SUBMODULES} entry. */
    static List<List<String>> submoduleCommands(Path repositoryRoot) {
        List<List<String>> commands = new ArrayList<>();
        for (String name : SUBMODULES) {
            if (Files.isDirectory(repositoryRoot.resolve(name))) {
                commands.add(List.of("git", "submodule", "update", "--init", "--recursive", name));
            }
        }
        return commands;
    }

    /** Whether an executable {@code command} is on {@code pathValue} (a PATH-format string). */
    static boolean commandOnPath(String command, String pathValue) {
        if (pathValue == null || pathValue.isBlank()) {
            return false;
        }
        for (String dir : pathValue.split(File.pathSeparator)) {
            if (dir.isBlank()) {
                continue;
            }
            Path candidate = Path.of(dir).resolve(command);
            if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return true;
            }
        }
        return false;
    }
}
