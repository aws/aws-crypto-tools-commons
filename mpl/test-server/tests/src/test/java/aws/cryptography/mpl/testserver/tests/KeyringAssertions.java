package aws.cryptography.mpl.testserver.tests;

import static aws.cryptography.mpl.testserver.tests.Materials.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptedDataKey;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Assertions for what keyring tests check again and again:
 * the data key and EDKs in materials, the fields of one EDK, and the requests that {@link MockKms} got.
 *
 * <pre>{@code
 * assertThat(encrypted).hasDataKey(plaintext).hasEdkCount(1);
 * assertThat(edk).hasProviderId("aws-kms").hasCiphertext(ciphertext);
 * assertThat(mockKms.decryptCalls()).sentInOrder(edk1, edk2);
 * assertThat(mockKms.encryptCalls()).onlyOneCall().sentKeyId(KMS_KEY_ARN);
 * }</pre>
 * Each method returns its assertion object, so a test can chain several checks on one value.
 */
final class KeyringAssertions {

    private KeyringAssertions() {
    }

    static EncryptionMaterialsAssert assertThat(EncryptionMaterials materials) {
        return new EncryptionMaterialsAssert(materials);
    }

    static DecryptionMaterialsAssert assertThat(DecryptionMaterials materials) {
        return new DecryptionMaterialsAssert(materials);
    }

    static EdkAssert assertThat(EncryptedDataKey edk) {
        return new EdkAssert(edk);
    }

    /** {@code requests} is one operation's requests, such as {@link MockKms#decryptCalls()}. */
    static KmsCallsAssert assertThat(List<MockKms.Request> requests) {
        return new KmsCallsAssert(requests);
    }

    record EncryptionMaterialsAssert(EncryptionMaterials materials) {

        EncryptionMaterialsAssert hasDataKey(byte[] dataKey) {
            assertArrayEquals(dataKey, bytes(materials.getPlaintextDataKey()),
                "the encryption materials must hold this plaintext data key");
            return this;
        }

        EncryptionMaterialsAssert hasEdkCount(int count) {
            assertEquals(count, materials.getEncryptedDataKeys().size(),
                "the encryption materials must hold this many encrypted data keys");
            return this;
        }
    }

    record DecryptionMaterialsAssert(DecryptionMaterials materials) {

        DecryptionMaterialsAssert hasDataKey(byte[] dataKey) {
            assertArrayEquals(dataKey, bytes(materials.getPlaintextDataKey()),
                "the decryption materials must hold this plaintext data key");
            return this;
        }
    }

    record EdkAssert(EncryptedDataKey edk) {

        EdkAssert hasProviderId(String providerId) {
            assertEquals(providerId, edk.getKeyProviderId(), "the EDK must have this key provider ID");
            return this;
        }

        /** The EDK's key provider info must be the UTF-8 bytes of {@code providerInfo}. */
        EdkAssert hasProviderInfo(String providerInfo) {
            assertArrayEquals(providerInfo.getBytes(StandardCharsets.UTF_8), bytes(edk.getKeyProviderInfo()),
                "the EDK's key provider info must be the UTF-8 bytes of " + providerInfo);
            return this;
        }

        EdkAssert hasCiphertext(byte[] ciphertext) {
            assertArrayEquals(ciphertext, bytes(edk.getCiphertext()), "the EDK must have this ciphertext");
            return this;
        }
    }

    record KmsCallsAssert(List<MockKms.Request> requests) {

        void noCalls() {
            assertEquals(0, requests.size(), "MockKms must get no request of this kind");
        }

        /** MockKms got exactly one request, and the returned object checks that request's fields. */
        KmsRequestAssert onlyOneCall() {
            assertEquals(1, requests.size(), "MockKms must get exactly one request of this kind");
            return new KmsRequestAssert(requests.get(0));
        }

        /** MockKms got one Decrypt request for each EDK, with that EDK's ciphertext, in this order. */
        void sentInOrder(EncryptedDataKey... edks) {
            assertEquals(edks.length, requests.size(), "MockKms must get one request for each of these EDKs");
            for (int i = 0; i < edks.length; i++) {
                assertArrayEquals(bytes(edks[i].getCiphertext()), requests.get(i).blob("CiphertextBlob"),
                    "request " + i + " must send the ciphertext of EDK " + i);
            }
        }
    }

    record KmsRequestAssert(MockKms.Request request) {

        KmsRequestAssert sentKeyId(String keyId) {
            assertEquals(keyId, request.text("KeyId"), "the request must send this KeyId");
            return this;
        }

        KmsRequestAssert sentEncryptionContext(Map<String, String> encryptionContext) {
            assertEquals(encryptionContext, request.stringMap("EncryptionContext"),
                "the request must send this EncryptionContext");
            return this;
        }

        KmsRequestAssert sentGrantTokens(List<String> grantTokens) {
            assertEquals(grantTokens, request.stringList("GrantTokens"), "the request must send these GrantTokens");
            return this;
        }

        /** An Encrypt request's Plaintext. */
        KmsRequestAssert sentPlaintext(byte[] plaintext) {
            assertArrayEquals(plaintext, request.blob("Plaintext"), "the request must send this Plaintext");
            return this;
        }

        /** A Decrypt request's CiphertextBlob. */
        KmsRequestAssert sentCiphertext(byte[] ciphertext) {
            assertArrayEquals(ciphertext, request.blob("CiphertextBlob"), "the request must send this CiphertextBlob");
            return this;
        }

        /** A GenerateDataKey request's NumberOfBytes. */
        KmsRequestAssert sentNumberOfBytes(int numberOfBytes) {
            assertEquals(String.valueOf(numberOfBytes), request.text("NumberOfBytes"),
                "the request must send this NumberOfBytes");
            return this;
        }
    }
}
