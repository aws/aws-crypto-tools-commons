package aws.cryptography.esdk.testserver.orchestrator.launch;

import aws.cryptography.esdk.testserver.orchestrator.config.ConfigurationEntry;
import aws.cryptography.esdk.testserver.orchestrator.source.ResolvedSource;

/**
 * Builds a {@code Language_Server} from its resolved source (or consumes its
 * artifact) and launches it bound to the port from its {@link ConfigurationEntry}
 * (design Builder + Launcher, Requirements 9.4, 12). Build failures, unresolvable
 * references, and port conflicts surface as a {@link ServerLaunchException} that
 * names the language, so the run aborts before any {@code Tests} run
 * (Requirements 9.6, 10.4, 11.4, 12.8).
 *
 * <p>Kept as an interface so the pure-logic property tests and the error-path
 * integration tests can substitute fakes/stubs — real git cloning and artifact
 * fetching for the Other languages is task 11 territory; only the Java server is
 * exercised end-to-end for this pass.
 */
public interface Launcher {

    /**
     * Build and launch the server for {@code entry} from {@code source}.
     *
     * @throws ServerLaunchException if the source is unresolvable/unbuildable, the
     *     port is already in use, or the language has no server implementation.
     */
    LaunchedServer launch(ConfigurationEntry entry, ResolvedSource source) throws ServerLaunchException;
}
