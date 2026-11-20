package aws.cryptography.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.testserver.tests.PrimitivesInputs.DigestVector;
import aws.cryptography.testserver.tests.PrimitivesInputs.HkdfVector;
import aws.cryptography.testserver.tests.PrimitivesInputs.HmacVector;
import aws.cryptography.testserver.tests.PrimitivesInputs.KbkdfVector;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class PrimitivesInputsTest {

    private static final Fuzz FUZZ = new Fuzz(500, 42, null);
    private static final HexFormat HEX = HexFormat.of();
    private static final Set<String> ALGORITHMS = Set.of("SHA_256", "SHA_384", "SHA_512");

    @Test
    void defaultRunHasOnlyTheFixedExamples() {
        assertEquals(8, PrimitivesInputs.aesGcmMessages(Fuzz.NONE).size());
        assertEquals(6, PrimitivesInputs.digestVectors(Fuzz.NONE).size());
        assertEquals(6, PrimitivesInputs.hmacVectors(Fuzz.NONE).size());
        assertEquals(9, PrimitivesInputs.hkdfVectors(Fuzz.NONE).size());
        assertEquals(10, PrimitivesInputs.kbkdfVectors(Fuzz.NONE).size());
    }

    // The published vectors check the JDK code that gives each random example its expected output.

    @Test
    void theJdkDigestMatchesThePublishedVectors() {
        for (Example<DigestVector> vector : PrimitivesInputs.digestVectors(Fuzz.NONE)) {
            DigestVector v = vector.value();
            assertEquals(v.digest(), HEX.formatHex(PrimitivesInputs.digest(v.algorithm(), HEX.parseHex(v.data()))),
                vector.name());
        }
    }

    @Test
    void theJdkHmacMatchesThePublishedVectors() {
        for (Example<HmacVector> vector : PrimitivesInputs.hmacVectors(Fuzz.NONE)) {
            HmacVector v = vector.value();
            assertEquals(v.digest(),
                HEX.formatHex(PrimitivesInputs.hmac(v.algorithm(), HEX.parseHex(v.key()), HEX.parseHex(v.message()))),
                vector.name());
        }
    }

    @Test
    void theJdkHkdfMatchesThePublishedVectors() {
        for (Example<HkdfVector> vector : PrimitivesInputs.hkdfVectors(Fuzz.NONE)) {
            HkdfVector v = vector.value();
            assertEquals(v.okm(), HEX.formatHex(PrimitivesInputs.hkdf(v.algorithm(),
                HEX.parseHex(v.salt()), HEX.parseHex(v.ikm()), HEX.parseHex(v.info()), v.length())), vector.name());
        }
    }

    @Test
    void theJdkKbkdfMatchesThePublishedVectors() {
        for (Example<KbkdfVector> vector : PrimitivesInputs.kbkdfVectors(Fuzz.NONE)) {
            KbkdfVector v = vector.value();
            assertEquals(v.okm(), HEX.formatHex(PrimitivesInputs.kbkdf(v.algorithm(),
                HEX.parseHex(v.ikm()), HEX.parseHex(v.info()), v.length())), vector.name());
        }
    }

    @Test
    void everyDigestAlgorithmIsInTheModel() {
        for (Example<DigestVector> vector : PrimitivesInputs.digestVectors(FUZZ)) {
            assertTrue(ALGORITHMS.contains(vector.value().algorithm()), vector.name());
        }
    }

    @Test
    void everyHmacKeyIsNotEmpty() {
        for (Example<HmacVector> vector : PrimitivesInputs.hmacVectors(FUZZ)) {
            HmacVector v = vector.value();
            assertTrue(ALGORITHMS.contains(v.algorithm()), vector.name());
            assertTrue(HEX.parseHex(v.key()).length > 0, vector.name());
        }
    }

    @Test
    void everyHkdfVectorHasASaltAndAModelLength() {
        for (Example<HkdfVector> vector : PrimitivesInputs.hkdfVectors(FUZZ)) {
            HkdfVector v = vector.value();
            assertTrue(ALGORITHMS.contains(v.algorithm()), vector.name());
            assertTrue(HEX.parseHex(v.salt()).length > 0, vector.name());
            assertTrue(List.of(16, 24, 32).contains(v.length()), vector.name());
            assertEquals(v.length(), HEX.parseHex(v.okm()).length, vector.name());
        }
    }

    @Test
    void everyKbkdfVectorHasEnoughKeyMaterialAndAPositiveLength() {
        for (Example<KbkdfVector> vector : PrimitivesInputs.kbkdfVectors(FUZZ)) {
            KbkdfVector v = vector.value();
            assertTrue(ALGORITHMS.contains(v.algorithm()), vector.name());
            assertTrue(HEX.parseHex(v.ikm()).length >= 32, vector.name());
            assertTrue(v.length() > 0, vector.name());
            assertEquals(v.length(), HEX.parseHex(v.okm()).length, vector.name());
        }
    }
}
