package aws.cryptography.primitives.testserver.orchestrator.run;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Runs the Tests Gradle module, passing system properties for target endpoints.
 */
public final class GradleTestRunner {

    private GradleTestRunner() {
    }

    /**
     * Run {@code ./gradlew cleanTest test} in the tests module directory,
     * forwarding the given system properties.
     *
     * @return the exit code (0 = success)
     */
    public static int run(Path testsModuleDir, Map<String, String> systemProperties) {
        List<String> command = new ArrayList<>();
        command.add(testsModuleDir.resolve("gradlew").toString());
        command.add("--console=plain");
        command.add("cleanTest");
        command.add("test");

        for (Map.Entry<String, String> entry : systemProperties.entrySet()) {
            command.add("-D" + entry.getKey() + "=" + entry.getValue());
        }

        ProcessBuilder pb = new ProcessBuilder(command)
            .directory(testsModuleDir.toFile())
            .inheritIO();

        try {
            Process proc = pb.start();
            return proc.waitFor();
        } catch (IOException | InterruptedException e) {
            System.err.println("Failed to run tests: " + e.getMessage());
            return 1;
        }
    }
}
