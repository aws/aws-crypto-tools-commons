package aws.cryptography.testserver.orchestrator.run;

import java.net.URI;

/**
 * One launched {@code Target} handed to the {@code Tests}: a (language, major
 * version) pair backed by a reachable {@code Language_Server} endpoint. The
 * runner formats these into the {@code testserver.targets} runtime
 * property.
 *
 * @param language     the logical language key, e.g. {@code "java"}
 * @param majorVersion the library major version, e.g. {@code 3}
 * @param repo         the source repository name (from {@code libraryRepository.name})
 * @param endpoint     the launched Language_Server's base endpoint URL
 */
public record TestTarget(String language, int majorVersion, String repo, URI endpoint) {

    /** The {@code language:major:repo=url} form of the targets property. */
    public String asPropertyEntry() {
        return language + ":" + majorVersion + ":" + repo + "=" + endpoint;
    }
}
