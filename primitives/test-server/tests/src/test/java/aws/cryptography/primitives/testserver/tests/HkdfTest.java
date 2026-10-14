package aws.cryptography.primitives.testserver.tests;

import aws.cryptography.primitives.testserver.client.client.PrimitivesTestServerClient;
import aws.cryptography.primitives.testserver.client.model.DigestAlgorithm;
import aws.cryptography.primitives.testserver.client.model.HkdfInput;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * HKDF (extract + expand) known answers, per target, from RFC 5869 Appendix A
 * test cases 1-3 (the vectors in the Dafny primitives' TestHKDF_Rfc5869TestVectors.dfy;
 * TestAwsCryptographyPrimitivesHKDF.dfy's TestCase1 is A.1).
 *
 * <p>The model limits {@code expectedLength} to 16, 24 or 32, so each vector is
 * checked at those lengths against a prefix of the RFC's 42/82-byte OKM. HKDF-Expand
 * output blocks T(1), T(2)... do not depend on L, so the first n bytes of the
 * RFC's OKM are the OKM for length n.
 */
public class HkdfTest {

    private static final int[] LENGTHS = {16, 24, 32};

    record Vector(String name, String ikm, String salt, String info, String okm32) {
        @Override
        public String toString() {
            return name;
        }
    }

    static final List<Vector> VECTORS = List.of(
        new Vector("RFC 5869 A.1",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"),
        new Vector("RFC 5869 A.2",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                + "404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"),
        // No salt and empty info. The model's salt is required, and the Dafny
        // primitives reject a present-but-empty salt, so "no salt" is sent as
        // RFC 5869 section 2.2's default: HashLen (32) zero bytes. HMAC zero-pads
        // a short key, so this yields the same PRK and OKM as an empty salt.
        new Vector("RFC 5869 A.3",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"));

    static Stream<Arguments> cases() {
        return LanguageServerRegistry.shared().targets().stream()
            .flatMap(target -> VECTORS.stream()
                .flatMap(vector -> Arrays.stream(LENGTHS)
                    .mapToObj(length -> Arguments.of(vector, length, target))));
    }

    @ParameterizedTest(name = "[hkdf] {0} L={1} {2}")
    @MethodSource("cases")
    void knownAnswer(Vector vector, int length, LanguageServerTarget target) {
        FeatureGate.require(Set.of("hkdf"), target);
        PrimitivesTestServerClient client = PrimitivesTestServerClients.forEndpoint(target.endpoint());

        byte[] okm = Bytes.of(PrimitivesTestServerClients.withRetry(() ->
            client.hkdf(HkdfInput.builder()
                .algorithm(DigestAlgorithm.SHA_256)
                .ikm(Bytes.buf(vector.ikm()))
                .salt(Bytes.buf(vector.salt()))
                .info(Bytes.buf(vector.info()))
                .expectedLength(length)
                .build())).getOkm());

        assertArrayEquals(Arrays.copyOf(Bytes.hex(vector.okm32()), length), okm);
    }
}
