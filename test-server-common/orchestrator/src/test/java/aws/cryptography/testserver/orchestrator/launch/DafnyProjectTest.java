package aws.cryptography.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DafnyProjectTest {

    @TempDir
    Path repo;

    @Test
    @DisplayName("a runtimes/<lang> library next to a project Makefile is a smithy-dafny project")
    void recognizesProject() throws IOException {
        Path project = Files.createDirectories(repo.resolve("AwsCryptographyPrimitives"));
        Files.writeString(project.resolve("Makefile"), "");
        Path library = Files.createDirectories(project.resolve("runtimes").resolve("net"));

        assertEquals(Optional.of(project), DafnyProject.of(library));
        assertEquals(repo, DafnyProject.repositoryRoot(project));
    }

    @Test
    @DisplayName("a library outside runtimes/, or without a project Makefile, is not a smithy-dafny project")
    void rejectsNonProject() throws IOException {
        Path noMakefile = Files.createDirectories(repo.resolve("A").resolve("runtimes").resolve("java"));
        Path notRuntimes = Files.createDirectories(repo.resolve("releases").resolve("go"));
        Files.writeString(repo.resolve("releases").resolve("Makefile"), "");

        assertEquals(Optional.empty(), DafnyProject.of(noMakefile));
        assertEquals(Optional.empty(), DafnyProject.of(notRuntimes));
        assertEquals(Optional.empty(), DafnyProject.of(repo));
    }

    @Test
    @DisplayName("only the Dafny submodules present in the repository are initialized, in a fixed order")
    void submoduleCommands() throws IOException {
        Files.createDirectories(repo.resolve("mpl"));
        Files.createDirectories(repo.resolve("libraries"));

        assertEquals(
            List.of(
                List.of("git", "submodule", "update", "--init", "--recursive", "--depth", "1", "--jobs", "8", "libraries"),
                List.of("git", "submodule", "update", "--init", "--recursive", "--depth", "1", "--jobs", "8", "mpl")),
            DafnyProject.submoduleCommands(repo));
    }
}
