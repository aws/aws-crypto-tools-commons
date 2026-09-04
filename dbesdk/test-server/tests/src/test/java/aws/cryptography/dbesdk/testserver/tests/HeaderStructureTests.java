package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.parseHeaderEncryptionContext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Header byte-level structural facts. Each test asserts a property of the
 * {@code aws_dbe_head} byte string that is invariant of Configuration Version
 * or attribute schema — the version-conditional properties (byte 0, encrypt
 * legend) live in {@link V1EncryptionContextBehaviorTests} and
 * {@link V2EncryptionContextBehaviorTests} instead.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #messageIdIsFreshPerEncrypt} — bytes 2–33 differ between two independent encrypts</li>
 *   <li>{@link #flavorByteEncodesEcdsaSigningSuite} — byte 1 is 0x01 for the default (ECDSA-signed) suite</li>
 *   <li>{@link #headerEcContainsAwsCryptoPublicKeyUnderEcdsaSuite} — the header EC carries exactly the
 *       {@code aws-crypto-public-key} entry that an ECDSA-signing algorithm suite adds</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 3 assertions × pairs}. Only the encrypt-side
 * endpoint is used — every test is a structural check on the encrypted item,
 * no decrypt step needed.
 */
class HeaderStructureTests {

    /** Header byte 1 for a signing algorithm suite (ECDSA-P384). */
    private static final byte FLAVOR_ECDSA_SIGNING = 0x01;

    /** The single EC entry an ECDSA-signing algorithm suite writes into the header. */
    private static final String AWS_CRYPTO_PUBLIC_KEY = "aws-crypto-public-key";

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /**
     * Two independent encrypts of identical plaintext under the same client
     * MUST produce distinct 32-byte message IDs (header bytes 2–33). Freshness
     * per {@code specification/structured-encryption/header.md#message-id} —
     * each encrypt draws a new random ID rather than being deterministic.
     */
    @ParameterizedTest(name = "message ID (bytes 2-33) is fresh per encrypt {0}")
    @MethodSource("testPairs")
    void messageIdIsFreshPerEncrypt(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        byte[] hdr1 = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(HEAD));
        byte[] hdr2 = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(HEAD));
        byte[] msgId1 = Arrays.copyOfRange(hdr1, 2, 34);
        byte[] msgId2 = Arrays.copyOfRange(hdr2, 2, 34);
        assertFalse(Arrays.equals(msgId1, msgId2),
            "two independent encrypts of identical plaintext must produce distinct 32-byte "
                + "message IDs (" + pair + ")");
    }

    /**
     * Header byte 1 (the "flavor") encodes the algorithm suite family. The
     * default MPL/DBE algorithm suite is ECDSA-P384-signed and MUST be
     * represented as {@code 0x01}. A future non-signing suite would produce
     * {@code 0x00}; that variant is out of scope for this file and would live
     * in a dedicated algorithm-suite-selection test file.
     */
    @ParameterizedTest(name = "flavor byte encodes ECDSA signing suite {0}")
    @MethodSource("testPairs")
    void flavorByteEncodesEcdsaSigningSuite(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        byte[] header = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(HEAD));
        assertEquals(FLAVOR_ECDSA_SIGNING, header[1],
            "header byte 1 (flavor) must be 0x01 for the default ECDSA-signed algorithm suite ("
                + pair + ")");
    }

    /**
     * Under an ECDSA-signing algorithm suite (the default), the CMM writes one
     * {@code aws-crypto-public-key} entry into the header's Encryption Context
     * so the decrypter can verify the signature. The value is the base64
     * encoding of the DER-encoded ephemeral ECDSA public key. This test asserts
     * only the presence and non-emptiness of the entry — its exact bytes vary
     * per encrypt.
     */
    @ParameterizedTest(name = "header EC contains aws-crypto-public-key under ECDSA suite {0}")
    @MethodSource("testPairs")
    void headerEcContainsAwsCryptoPublicKeyUnderEcdsaSuite(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        byte[] header = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(HEAD));
        Map<String, String> ec = parseHeaderEncryptionContext(header);
        assertTrue(ec.containsKey(AWS_CRYPTO_PUBLIC_KEY),
            "an ECDSA-signing algorithm suite must add an aws-crypto-public-key entry to the header "
                + "Encryption Context; found entries: " + ec.keySet() + " (" + pair + ")");
        assertFalse(ec.get(AWS_CRYPTO_PUBLIC_KEY).isEmpty(),
            "aws-crypto-public-key entry must have a non-empty base64-encoded public key value ("
                + pair + ")");
    }
}
