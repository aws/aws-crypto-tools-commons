package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.FOOT;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.testserver.tests.TargetPair;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Footer byte-level structural facts. The {@code aws_dbe_foot} attribute
 * carries the Recipient Tag (HMAC-SHA-384, 48 bytes) and — under a signing
 * algorithm suite — the ECDSA-P384 signature appended after the tag
 * ({@code specification/structured-encryption/footer.md}).
 *
 * <p><b>Tests here:</b>
 * <ol>
 *   <li>{@link #footerAttributeIsPresent} — every encrypted item has an aws_dbe_foot attribute</li>
 *   <li>{@link #footerIsAtLeast48Bytes} — the Recipient Tag alone is 48 bytes; the footer is that plus signature</li>
 *   <li>{@link #footerBytesDifferBetweenEncrypts} — a fresh ECDSA signature (and fresh derived tag) per encrypt</li>
 * </ol>
 *
 * <p><b>Test count</b> = {@code 3 assertions × pairs}. Only the encrypt-side
 * endpoint is used.
 */
class FooterFormatTests {

    /** Recipient Tag length — HMAC-SHA-384 is 48 bytes. */
    private static final int RECIPIENT_TAG_LEN = 48;

    static Stream<TargetPair> testPairs() {
        return DbeTestHelpers.pairs().stream();
    }

    /** Every encrypted item MUST carry an {@code aws_dbe_foot} attribute. */
    @ParameterizedTest(name = "encrypted item contains aws_dbe_foot attribute {0}")
    @MethodSource("testPairs")
    void footerAttributeIsPresent(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, canonicalPlaintext());
        //= specification/structured-encryption/encrypt-path-structure.md#encrypted-structured-data
        //= type=test
        //# - The [Footer Field](#footer-field) MUST exist in the final Encrypted Structured Data
        //
        //= specification/structured-encryption/encrypt-path-structure.md#footer-field
        //= type=test
        //# The Footer Field name MUST be `aws_dbe_foot`
        assertNotNull(item.get(FOOT),
            "encrypted item must carry an aws_dbe_foot attribute (" + pair + ")");
    }

    /**
     * The footer is at least 48 bytes (the Recipient Tag alone). Under the
     * default ECDSA-signed suite it is longer — the ECDSA-P384 signature
     * (typically ~100 bytes DER-encoded) is appended after the tag. Asserting
     * strict equality would over-fit to a specific signature encoding, so this
     * test only asserts the lower bound.
     */
    @ParameterizedTest(name = "footer is at least 48 bytes {0}")
    @MethodSource("testPairs")
    void footerIsAtLeast48Bytes(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        byte[] footer = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(FOOT));
        //= specification/structured-encryption/footer.md#recipient-tags
        //= type=test
        //= reason=one 48-byte Recipient Tag per Encrypted Data Key sets the footer's 48-byte floor
        //# There MUST be one Recipient Tag for each Encrypted Data Key in the [header](./header.md#encrypted-data-keys)
        assertTrue(footer.length >= RECIPIENT_TAG_LEN,
            "footer must contain at least a 48-byte Recipient Tag; got " + footer.length
                + " bytes (" + pair + ")");
    }

    /**
     * Two independent encrypts of identical plaintext MUST produce different
     * footer bytes. Freshness at the signature layer: the ECDSA signature
     * incorporates fresh randomness, and the Recipient Tag depends on the
     * message ID which is fresh per encrypt.
     */
    @ParameterizedTest(name = "footer bytes differ between two encrypts {0}")
    @MethodSource("testPairs")
    void footerBytesDifferBetweenEncrypts(TargetPair pair) {
        DBESDKTestServerClient encryptClient =
            DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, standardActions(), List.of());
        byte[] foot1 = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(FOOT));
        byte[] foot2 = bytesOf(encryptOnce(encryptClient, encryptClientId, canonicalPlaintext()).get(FOOT));
        assertFalse(Arrays.equals(foot1, foot2),
            "two independent encrypts of identical plaintext must produce different footer bytes ("
                + pair + ")");
    }
}
