package aws.cryptography.primitives.testserver.orchestrator.launch;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;

/**
 * Launch plan for a Rust Language_Server. Builds with {@code cargo build --release}
 * and launches the binary as a subprocess.
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

        // Find the binary name from Cargo.toml [[bin]] name
        Path binary = serverDir.resolve("target/release/prim-test-server");

        // Launch
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

        // Wait for readiness
        waitForPort(port, 120);

        return new LaunchedServer(process, port);
    }

    private void waitForPort(int port, int timeoutSeconds) {
        long deadline = System.currentTimeMillis() + (timeoutSeconds * 1000L);
        while (System.currentTimeMillis() < deadline) {
            try (Socket s = new Socket("127.0.0.1", port)) {
                return; // connected
            } catch (IOException ignored) {
                // not ready yet
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
