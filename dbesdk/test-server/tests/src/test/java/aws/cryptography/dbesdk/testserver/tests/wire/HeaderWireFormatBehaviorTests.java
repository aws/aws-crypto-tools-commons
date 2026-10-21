package aws.cryptography.dbesdk.testserver.tests.wire;

import aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers;
import aws.cryptography.dbesdk.testserver.tests.DbeTestServerClients;

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
import aws.cryptography.testserver.tests.LanguageServerTarget;
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
 * legend) live in {@link ConfigurationVersionWireEncodingTests} instead.
 *
 * <p><b>Topology: target-local.</b> Every assertion is a structural check on
 * an item the encrypting server produces (no decrypt step), so each runs once
 * per configured target via {@link DbeTestHelpers#targets()} rather than across
 * the N&sup2; pair matrix.
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #messageIdIsFreshPerEncrypt} — bytes 2–33 differ between two independent encrypts</li>
 *   <li>{@link #flavorByteEncodesEcdsaSigningSuite} — byte 1 is 0x01 for the default (ECDSA-signed) suite</li>
 *   <li>{@link #headerEcContainsAwsCryptoPublicKeyUnderEcdsaSuite} — the header EC carries exactly the
 *       {@code aws-crypto-public-key} entry that an ECDSA-signing algorithm suite adds</li>
 * </ol>
 */
class HeaderWireFormatBehaviorTests {

    /** Header byte 1 for a signing algorithm suite (ECDSA-P384). */
    private static final byte FLAVOR_ECDSA_SIGNING = 0x01;

    /** The single EC entry an ECDSA-signing algorithm suite writes into the header. */
    private static final String AWS_CRYPTO_PUBLIC_KEY = "aws-crypto-public-key";

    static Stream<LanguageServerTarget> targets() {
        return DbeTestHelpers.targets().stream();
    }

    private static byte[] encryptHeader(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, standardActions(), List.of());
        return bytesOf(encryptOnce(client, clientId, canonicalPlaintext()).get(HEAD));
    }

    /**
     * Two independent encrypts of identical plaintext under the same client
     * MUST produce distinct 32-byte message IDs (header bytes 2–33). Freshness
     * per {@code specification/structured-encryption/header.md#message-id} —
     * each encrypt draws a new random ID rather than being deterministic.
     */
    @ParameterizedTest(name = "message ID (bytes 2-33) is fresh per encrypt {0}")
    @MethodSource("targets")
    void messageIdIsFreshPerEncrypt(LanguageServerTarget target) {
        DBESDKTestServerClient client = DbeTestServerClients.forEndpoint(target.endpoint());
        String clientId = newKmsClient(client, TABLE, PK, standardActions(), List.of());
        byte[] hdr1 = bytesOf(encryptOnce(client, clientId, canonicalPlaintext()).get(HEAD));
        byte[] hdr2 = bytesOf(encryptOnce(client, clientId, canonicalPlaintext()).get(HEAD));
        byte[] msgId1 = Arrays.copyOfRange(hdr1, 2, 34);
        byte[] msgId2 = Arrays.copyOfRange(hdr2, 2, 34);
        //= specification/structured-encryption/header.md#message-id
        //= type=test
        //# Implementations MUST generate a fresh 256-bit random MessageID, from a cryptographically secure source, for each record encrypted.
        assertFalse(Arrays.equals(msgId1, msgId2),
            "two independent encrypts of identical plaintext must produce distinct 32-byte "
                + "message IDs (" + target + ")");
    }

    /**
     * Header byte 1 (the "flavor") encodes the algorithm suite family. The
     * default MPL/DBE algorithm suite is ECDSA-P384-signed and MUST be
     * represented as {@code 0x01}. The non-signing ({@code 0x00}) flavor is
     * asserted in the footer known-bug tests.
     */
    @ParameterizedTest(name = "flavor byte encodes ECDSA signing suite {0}")
    @MethodSource("targets")
    void flavorByteEncodesEcdsaSigningSuite(LanguageServerTarget target) {
        byte[] header = encryptHeader(target);
        //= specification/structured-encryption/header.md#format-flavor
        //= type=test
        //# The algorithm suite indicated by the flavor MUST be a
        //# [DBE supported algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum).
        assertEquals(FLAVOR_ECDSA_SIGNING, header[1],
            "header byte 1 (flavor) must be 0x01 for the default ECDSA-signed algorithm suite ("
                + target + ")");
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
    @MethodSource("targets")
    void headerEcContainsAwsCryptoPublicKeyUnderEcdsaSuite(LanguageServerTarget target) {
        Map<String, String> ec = parseHeaderEncryptionContext(encryptHeader(target));
        assertTrue(ec.containsKey(AWS_CRYPTO_PUBLIC_KEY),
            "an ECDSA-signing algorithm suite must add an aws-crypto-public-key entry to the header "
                + "Encryption Context; found entries: " + ec.keySet() + " (" + target + ")");
        assertFalse(ec.get(AWS_CRYPTO_PUBLIC_KEY).isEmpty(),
            "aws-crypto-public-key entry must have a non-empty base64-encoded public key value ("
                + target + ")");
    }
}
