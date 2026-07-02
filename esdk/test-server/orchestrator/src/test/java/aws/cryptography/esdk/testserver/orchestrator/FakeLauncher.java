package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedSource;
import java.net.URI;

/**
 * A test double {@link Launcher} that either aborts with a preset
 * {@link ServerLaunchException} or returns a dummy {@link LaunchedServer} without
 * binding a real port. Lets the orchestrator error-path tests exercise
 * build/resolution/port failures deterministically without cloning repos or
 * launching servers (design: keep git/artifact behind an abstraction; real
 * launching is exercised by the Java integration tests / the end-to-end run).
 */
final class FakeLauncher implements Launcher {

    private final ServerLaunchException toThrow;
    private int launchCount = 0;

    private FakeLauncher(ServerLaunchException toThrow) {
        this.toThrow = toThrow;
    }

    /** A launcher that always aborts with {@code ex}. */
    static FakeLauncher throwing(ServerLaunchException ex) {
        return new FakeLauncher(ex);
    }

    /** A launcher that always "launches" a dummy (unbound) server. */
    static FakeLauncher succeeding() {
        return new FakeLauncher(null);
    }

    int launchCount() {
        return launchCount;
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, ResolvedSource source)
            throws ServerLaunchException {
        launchCount++;
        if (toThrow != null) {
            throw toThrow;
        }
        URI endpoint = URI.create("http://127.0.0.1:" + entry.port());
        return new LaunchedServer(entry.language(), entry.port(), endpoint, () -> { });
    }
}
