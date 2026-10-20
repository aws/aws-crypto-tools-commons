package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Non-framed message decrypt conformance, anchored on externally produced known-answer vectors.
 * The ESDK spec forbids producing new non-framed messages, so no Language_Server can emit one —
 * but decrypt MUST still support the non-framed content type
 * ({@code spec/client-apis/decrypt.md#nonframed-message-body-decryption}). Every decrypt target
 * must therefore recover the known plaintext from these fixed ciphertexts.
 *
 * <p>Both vectors come from the public {@code awslabs/aws-encryption-sdk-test-vectors} corpus
 * (via the native Rust ESDK's vendored copies) and share one raw-AES-256 wrapping key
 * (namespace {@code aws-raw-vectors-persistant}, name {@code aes-256}):
 *
 * <ul>
 *   <li>V1: producer aws-encryption-sdk-python 1.3.5, test id
 *       {@code 9b86a9ce-e251-4d71-ba7b-cb83e0766aae}, suite 0x0178 (non-committing),
 *       10240-byte plaintext.</li>
 *   <li>V2: producer aws-encryption-sdk-python 2.0.0, test id
 *       {@code 24cfe457-2c2b-42c6-8bb5-5300e736b18a}, suite 0x0478 (committing, non-signing),
 *       10240-byte plaintext.</li>
 * </ul>
 *
 * <p>A per-decrypt-target property (the encrypt side is the fixed vector). Fully offline
 * (Raw-AES). A tampered final byte (the non-framed body auth tag for these non-signing suites)
 * must be rejected as a modeled {@link ESDKClientError}.
 */
class NonFramedVectorTests {

    /** The `aes-256` static key from aws-encryption-sdk-test-vectors' keys.json. */
    private static final byte[] WRAPPING_KEY = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31
    };

    /** One known-answer vector: resource paths, expected version byte, and the decrypt policy. */
    record Vector(String label, String ciphertextResource, String plaintextResource,
                  int versionByte, ESDKCommitmentPolicy decryptPolicy) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final Vector V1 = new Vector("v1-nonframed-0178",
        "/vectors/nonframed/v1_nonframed_aes256_0178.bin",
        "/vectors/nonframed/v1_nonframed_plaintext_small.bin",
        1, ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT);
    private static final Vector V2 = new Vector("v2-nonframed-0478",
        "/vectors/nonframed/v2_nonframed_aes256_0478.bin",
        "/vectors/nonframed/v2_nonframed_plaintext_small.bin",
        2, ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            cases.add(Arguments.of(target, V1));
            cases.add(Arguments.of(target, V2));
        }
        return cases;
    }

    private static byte[] resource(String path) {
        try (InputStream in = NonFramedVectorTests.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("missing test resource: " + path);
            }
            return in.readAllBytes();
        } catch (Exception e) {
            throw new IllegalStateException("failed to read test resource: " + path, e);
        }
    }

    /** The vectors' raw-AES keyring: namespace aws-raw-vectors-persistant, key name aes-256. */
    private static ESDKClientConfig config(ESDKCommitmentPolicy policy) {
        Keyring keyring = Keyring.builder()
            .rawAes(RawAesKeyringConfig.builder()
                .keyNamespace("aws-raw-vectors-persistant")
                .keyName("aes-256")
                .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY.clone()))
                .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
                .build())
            .build();
        return ESDKClientConfig.builder()
            .commitmentPolicy(policy)
            .cmm(CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder().keyring(keyring).build())
                .build())
            .build();
    }

    /** Decrypt of the externally produced non-framed vector recovers the known plaintext. */
    @ParameterizedTest(name = "nonFramedVectorDecrypts[{1}] {0}")
    @MethodSource("cases")
    void nonFramedVectorDecryptsToKnownPlaintext(LanguageServerTarget target, Vector vector) {
        FeatureGate.require(Set.of("raw-aes"), new TargetPair(target, target));
        byte[] ciphertext = resource(vector.ciphertextResource());
        byte[] expected = resource(vector.plaintextResource());
        assertEquals(vector.versionByte(), ciphertext[0] & 0xFF,
            vector + ": fixture version byte");
        byte[] recovered = EsdkOps.decrypt(target.endpoint(), config(vector.decryptPolicy()), ciphertext);
        assertArrayEquals(expected, recovered,
            target + " " + vector + ": decrypt of the non-framed known-answer vector must recover "
                + "the expected plaintext");
    }

    /** A flipped final byte (the non-framed body auth tag for these non-signing suites) is rejected. */
    @ParameterizedTest(name = "nonFramedTamperRejected[{1}] {0}")
    @MethodSource("cases")
    void nonFramedVectorTamperRejected(LanguageServerTarget target, Vector vector) {
        FeatureGate.require(Set.of("raw-aes"), new TargetPair(target, target));
        byte[] tampered = resource(vector.ciphertextResource());
        tampered[tampered.length - 1] ^= (byte) 0xFF;
        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(target.endpoint(), config(vector.decryptPolicy()), tampered),
            target + " " + vector + ": decrypt of the vector with its final auth-tag byte flipped "
                + "must be rejected");
    }

    /**
     * A non-framed body whose 8-byte encrypted content length is inflated past the 2^36 - 32
     * bound is rejected ({@code spec/data-format/message-body.md#encrypted-content-length}):
     * the bound caps what one AES-GCM invocation may authenticate, and honoring a huge declared
     * length instead drives allocation and decrypt work for a body that is not there. Tampering
     * only the length field leaves every authenticated byte untouched, so acceptance could only
     * come from a reader that trusts the declared length.
     */
    @ParameterizedTest(name = "nonFramedContentLengthBoundRejected[{1}] {0}")
    @MethodSource("cases")
    void nonFramedContentLengthOverBoundRejected(LanguageServerTarget target, Vector vector) {
        FeatureGate.require(Set.of("raw-aes"), new TargetPair(target, target));
        byte[] ciphertext = resource(vector.ciphertextResource());
        int contentLength = resource(vector.plaintextResource()).length;
        // Non-framed body (non-signing suite): ... IV(12) ‖ contentLength(8 BE) ‖ content ‖ tag(16).
        int contentLengthOffset = ciphertext.length - 16 - contentLength - 8;
        long declaredBaseline = 0;
        for (int i = 0; i < 8; i++) {
            declaredBaseline = (declaredBaseline << 8) | (ciphertext[contentLengthOffset + i] & 0xFFL);
        }
        assertEquals(contentLength, declaredBaseline,
            vector + ": baseline — the computed offset must hold the vector's content length");

        long bound = (1L << 36) - 32;
        for (long declared : new long[] {bound + 1, -1L /* 0xFFFFFFFFFFFFFFFF */}) {
            byte[] tampered = ciphertext.clone();
            for (int i = 0; i < 8; i++) {
                tampered[contentLengthOffset + i] = (byte) (declared >>> (8 * (7 - i)));
            }
            assertThrows(ESDKClientError.class,
                () -> EsdkOps.decrypt(target.endpoint(), config(vector.decryptPolicy()), tampered),
                target + " " + vector + ": a non-framed content length of " + Long.toUnsignedString(declared)
                    + " exceeds 2^36 - 32 and must be rejected");
        }
    }
}
