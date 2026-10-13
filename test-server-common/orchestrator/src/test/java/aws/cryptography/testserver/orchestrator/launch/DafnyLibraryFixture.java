package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.source.ComponentId;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;
import aws.cryptography.testserver.orchestrator.source.ResolutionReason;
import aws.cryptography.testserver.orchestrator.source.SourcePlan;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * A materialized clone for the Rust and Go launch-plan tests: a server
 * directory and a library directory, plus stand-in build tools that append
 * their invocation to a shared log and fail, so a test can see which steps
 * ran without building anything.
 */
final class DafnyLibraryFixture {

    private static final String COMMIT = "0123456789abcdef0123456789abcdef01234567";

    final Path serverDir;
    final Path libraryDir;
    final Path toolLog;

    private DafnyLibraryFixture(Path serverDir, Path libraryDir, Path toolLog) {
        this.serverDir = serverDir;
        this.libraryDir = libraryDir;
        this.toolLog = toolLog;
    }

    /**
     * A clone whose library is {@code libraryPath}; when {@code smithyDafny},
     * the library's grandparent is a project directory with a Makefile, which
     * {@link DafnyProject#of} recognizes.
     */
    static DafnyLibraryFixture create(Path root, String serverPath, String libraryPath,
            boolean smithyDafny) throws IOException {
        Path clone = root.resolve("clone");
        Path serverDir = Files.createDirectories(clone.resolve(serverPath));
        Path libraryDir = Files.createDirectories(clone.resolve(libraryPath));
        if (smithyDafny) {
            Files.writeString(libraryDir.getParent().getParent().resolve("Makefile"), "");
        }
        return new DafnyLibraryFixture(serverDir, libraryDir, root.resolve("tools.log"));
    }

    /** An executable that logs {@code name} and its arguments, then exits 3. */
    Path tool(Path root, String name) throws IOException {
        Path script = root.resolve("fake-" + name);
        Files.writeString(script, "#!/bin/sh\necho \"" + name + " $*\" >> '" + toolLog + "'\nexit 3\n",
            StandardCharsets.UTF_8);
        if (!script.toFile().setExecutable(true)) {
            throw new IOException("could not mark " + script + " executable");
        }
        return script;
    }

    /** The resolved server and library components for {@code language}. */
    MaterializedSources sources(String language, String serverPath, String libraryPath) {
        String url = "git@github.com:aws/aws-encryption-sdk.git";
        return new MaterializedSources(List.of(
            new MaterializedSources.Success(ComponentId.server(language),
                new SourcePlan.Clone(url, "main", serverPath), ResolutionReason.CONFIGURATION_ENTRY,
                serverDir, COMMIT, "main", null),
            new MaterializedSources.Success(ComponentId.library(language),
                new SourcePlan.Clone(url, "main", libraryPath), ResolutionReason.CONFIGURATION_ENTRY,
                libraryDir, COMMIT, "main", null)));
    }

    /** The logged tool invocations, in order. */
    List<String> toolCalls() throws IOException {
        return Files.exists(toolLog) ? Files.readAllLines(toolLog, StandardCharsets.UTF_8) : List.of();
    }
}
