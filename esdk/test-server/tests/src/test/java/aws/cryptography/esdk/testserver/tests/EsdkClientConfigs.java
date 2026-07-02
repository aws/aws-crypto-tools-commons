package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import java.nio.ByteBuffer;

/**
 * A fixed, valid, fully-offline ESDK client configuration used by the blob
 * round-trip Tests. It uses a Raw AES keyring wrapped in a Default CMM so the
 * round trip runs with NO AWS/KMS calls (Requirement 4.2, 4.3), and requires key
 * commitment on both encrypt and decrypt.
 *
 * <p>The same fixed 32-byte wrapping key and {@code ALG_AES256_GCM_IV12_TAG16}
 * wrapping algorithm are used for every constructed client, so ciphertext
 * produced by any endpoint's client is decryptable by any other endpoint's
 * client built from this config — the precondition of the cross-endpoint blob
 * round-trip (Requirement 4.4).
 *
 * <p>These builders use the generated <em>client</em> model shapes, keeping the
 * Tests dependent only on the one generated Test_Client.
 */
public final class EsdkClientConfigs {

    /**
     * A fixed 32-byte wrapping key (all bytes distinct-enough for a valid AES-256
     * key; the exact value is irrelevant as long as encrypt and decrypt share it).
     */
    private static final byte[] WRAPPING_KEY_32 = new byte[] {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31
    };

    private static final String KEY_NAMESPACE = "esdk-test-server";
    private static final String KEY_NAME = "raw-aes-round-trip-key";

    private EsdkClientConfigs() {
    }

    /**
     * @return a fresh {@link ESDKClientConfig} for an offline Raw-AES / Default-CMM
     *     client with {@code REQUIRE_ENCRYPT_REQUIRE_DECRYPT} commitment.
     */
    public static ESDKClientConfig rawAes() {
        RawAesKeyringConfig rawAes = RawAesKeyringConfig.builder()
            .keyNamespace(KEY_NAMESPACE)
            .keyName(KEY_NAME)
            .wrappingKey(ByteBuffer.wrap(WRAPPING_KEY_32.clone()))
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build();

        return ESDKClientConfig.builder()
            .commitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
            .cmm(CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder()
                    .keyring(Keyring.builder().rawAes(rawAes).build())
                    .build())
                .build())
            .build();
    }
}
