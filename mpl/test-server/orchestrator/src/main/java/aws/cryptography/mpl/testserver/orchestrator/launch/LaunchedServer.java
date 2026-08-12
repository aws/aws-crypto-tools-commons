package aws.cryptography.mpl.testserver.orchestrator.launch;

public final class LaunchedServer {

    private final Process process;
    private final int port;

    public LaunchedServer(Process process, int port) {
        this.process = process;
        this.port = port;
    }

    public int port() {
        return port;
    }

    public void stop() {
        if (process.isAlive()) {
            process.destroy();
            try {
                process.waitFor(java.util.concurrent.TimeUnit.SECONDS, 5);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            if (process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
