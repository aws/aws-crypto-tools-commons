package aws.cryptography.esdk.testserver.orchestrator.run;

import java.net.URI;

/**
 * One launched {@code Target} handed to the {@code Tests}: a (language, major
 * version, repository) identity backed by a reachable {@code Language_Server}
 * endpoint. The runner formats these into the {@code esdk.testserver.targets}
 * runtime property (Requirement 2.2; design "Runtime properties handed to the
 * Tests"). The repository is the library repository the server's implementation
 * is built from — the identity a known-bug declaration is keyed on.
 *
 * @param language     the logical language key, e.g. {@code "java"}
 * @param majorVersion the library major version, e.g. {@code 3}
 * @param repository   the library repository name, e.g. {@code "aws-crypto-tools-java"}
 * @param endpoint     the launched Language_Server's base endpoint URL
 */
public record TestTarget(String language, int majorVersion, String repository, URI endpoint) {

    /** The {@code language:major:repository=url} form of the targets property (design). */
    public String asPropertyEntry() {
        return language + ":" + majorVersion + ":" + repository + "=" + endpoint;
    }
}
