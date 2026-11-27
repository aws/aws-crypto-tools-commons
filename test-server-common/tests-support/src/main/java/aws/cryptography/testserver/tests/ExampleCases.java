package aws.cryptography.testserver.tests;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

/**
 * Test cases for a {@code @ParameterizedTest} that runs every example against every language server.
 *
 * <p>The example comes first and the language server last, so a display name such as
 * {@code "rejects {0} {1}"} ends with the server, which is how the dashboard reads a result.
 */
public final class ExampleCases {

    private ExampleCases() {
    }

    /** One case per example and language server: the arguments are (example, languageServer). */
    public static Stream<Arguments> withEachLanguageServer(List<? extends Example<?>> examples) {
        List<LanguageServerTarget> languageServers = LanguageServerRegistry.shared().targets();
        return examples.stream().flatMap(example -> languageServers.stream()
            .map(languageServer -> Arguments.of(example, languageServer)));
    }

    /**
     * One case per example and encrypting-decrypting pair of language servers:
     * the arguments are (example, pair).
     */
    public static Stream<Arguments> withEachPair(List<? extends Example<?>> examples) {
        List<TargetPair> pairs = LanguageServerRegistry.shared().pairs();
        return examples.stream().flatMap(example -> pairs.stream().map(pair -> Arguments.of(example, pair)));
    }
}
