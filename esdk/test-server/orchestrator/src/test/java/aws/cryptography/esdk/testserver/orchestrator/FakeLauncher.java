package aws.cryptography.esdk.testserver.orchestrator;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.launch.CloseResult;
import aws.cryptography.esdk.testserver.orchestrator.launch.LaunchedServer;
import aws.cryptography.esdk.testserver.orchestrator.launch.Launcher;
import aws.cryptography.esdk.testserver.orchestrator.launch.ServerLaunchException;
import aws.cryptography.esdk.testserver.orchestrator.source.MaterializedSources;
import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A test double {@link Launcher} that either aborts with a preset
 * {@link ServerLaunchException} or returns a dummy {@link LaunchedServer} without
 * binding a real port (its close() reports {@link CloseResult#stopped()}). Lets
 * the orchestrator error-path tests exercise resolve/build/port/timeout failures
 * deterministically without cloning repos or launching servers (design: keep
 * git/subprocess behind an abstraction; real launching is exercised by the
 * launch integration tests / the end-to-end run).
 */
final class FakeLauncher implements Launcher {

    private final ServerLaunchException toThrow;
    private final AtomicInteger launchCount = new AtomicInteger();

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
        return launchCount.get();
    }

    @Override
    public LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
            throws ServerLaunchException {
        launchCount.incrementAndGet();
        if (toThrow != null) {
            throw toThrow;
        }
        URI endpoint = URI.create("http://127.0.0.1:" + entry.port());
        // An explicit always-reachable probe: the dummy server binds no real
        // port, so the pipeline's pre-Tests reachability re-check (Requirement
        // 2.3) must not do a live TCP connect against an unbound port.
        return new LaunchedServer(entry.language(), entry.port(), endpoint,
            CloseResult::stopped, () -> true);
    }
}
