package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.GenerateRandomBytesInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * GenerateRandomBytes, per target. The Dafny primitives' TestGenerateRandomBytes.dfy
 * checks only the length (5 bytes); this also checks that two 32-byte draws
 * differ, which a constant or unseeded generator would fail. (Two honest 32-byte
 * draws collide with probability 2^-256.)
 */
public class GenerateRandomBytesTest {

    static List<LanguageServerTarget> targets() {
        return LanguageServerRegistry.shared().targets();
    }

    static Stream<Arguments> lengths() {
        return targets().stream()
            .flatMap(target -> IntStream.of(1, 5, 32, 1024)
                .mapToObj(length -> Arguments.of(length, target)));
    }

    @ParameterizedTest(name = "[random] length {0} {1}")
    @MethodSource("lengths")
    void returnsRequestedLength(int length, LanguageServerTarget target) {
        FeatureGate.require(Set.of("random"), target);
        assertEquals(length, draw(target, length).length);
    }

    @ParameterizedTest(name = "[random] two draws differ {0}")
    @MethodSource("targets")
    void twoDrawsDiffer(LanguageServerTarget target) {
        FeatureGate.require(Set.of("random"), target);
        byte[] first = draw(target, 32);
        byte[] second = draw(target, 32);
        assertFalse(Arrays.equals(first, second), "two 32-byte draws must differ");
    }

    private static byte[] draw(LanguageServerTarget target, int length) {
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());
        return Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.generateRandomBytes(GenerateRandomBytesInput.builder()
                .length(length)
                .build())).getData());
    }
}
