package aws.cryptography.testserver.orchestrator.launch;

import aws.cryptography.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.testserver.orchestrator.source.MaterializedSources;

/**
 * Builds a {@code Language_Server} from its materialized sources and launches
 * it bound to the port in its effective {@link ConfigurationEntry} (design
 * "Launcher contract", Requirement 2.1). The launcher looks up its language's
 * resolved server/library directories from the {@link MaterializedSources}
 * (via {@code directoryOf(ComponentId.server/library(language))}).
 *
 * <p>Failures surface as a {@link ServerLaunchException} carrying the language
 * and a {@link ServerLaunchException.Category} — RESOLVE | BUILD | PORT |
 * TIMEOUT — so the run aborts before any {@code Tests} run and the report
 * identifies the language and the cause (Requirement 2.5).
 *
 * <p>Kept as an interface so the pure-logic property tests and the error-path
 * integration tests can substitute fakes/stubs. Concrete subprocess launch
 * plans (JavaLaunchPlan, PythonLaunchPlan) build on the shared
 * {@link SubprocessLauncher} machinery (tasks 6.2, 6.3).
 */
public interface Launcher {

    /**
     * Build and launch the server for {@code entry} from the run's
     * materialized sources.
     *
     * @throws ServerLaunchException naming the language and the failure
     *     category if the sources are unusable ({@code RESOLVE}), the
     *     build/spawn fails ({@code BUILD}), the configured port is already
     *     bound ({@code PORT}), or the server does not become reachable within
     *     the readiness window ({@code TIMEOUT})
     */
    LaunchedServer launch(ConfigurationEntry entry, MaterializedSources sources)
        throws ServerLaunchException;
}
