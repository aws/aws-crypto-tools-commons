package aws.cryptography.mpl.testserver.orchestrator.launch;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;

/**
 * Launch plan for a Rust MPL Language_Server.
 */
public final class RustLaunchPlan {

    private final Path serverDir;

    public RustLaunchPlan(Path serverDir) {
        this.serverDir = serverDir;
    }

    public LaunchedServer launch(int port) {
        // Build
        ProcessBuilder buildPb = new ProcessBuilder("cargo", "build", "--release")
            .directory(serverDir.toFile())
            .inheritIO();
        try {
            Process buildProc = buildPb.start();
            int buildExit = buildProc.waitFor();
            if (buildExit != 0) {
                throw new RuntimeException("cargo build failed with exit code " + buildExit);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to build Rust server at " + serverDir, e);
        }

        // Launch
        Path binary = serverDir.resolve("target/release/mpl-test-server");
        ProcessBuilder launchPb = new ProcessBuilder(binary.toString(), String.valueOf(port))
            .directory(serverDir.toFile());
        launchPb.redirectErrorStream(true);
        launchPb.redirectOutput(serverDir.resolve(".server.log").toFile());

        Process process;
        try {
            process = launchPb.start();
        } catch (IOException e) {
            throw new RuntimeException("Failed to launch server binary", e);
        }

        waitForPort(port, 120);
        return new LaunchedServer(process, port);
    }

    private void waitForPort(int port, int timeoutSeconds) {
        long deadline = System.currentTimeMillis() + (timeoutSeconds * 1000L);
        while (System.currentTimeMillis() < deadline) {
            try (Socket s = new Socket("127.0.0.1", port)) {
                return;
            } catch (IOException ignored) {
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for port " + port);
            }
        }
        throw new RuntimeException("Server did not become ready on port " + port
            + " within " + timeoutSeconds + " seconds");
    }
}
