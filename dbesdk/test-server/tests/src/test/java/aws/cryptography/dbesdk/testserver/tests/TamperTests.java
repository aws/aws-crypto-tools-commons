package aws.cryptography.dbesdk.testserver.tests;

import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.FOOT;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.HEAD;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PK;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.PUBLIC;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.SECRET;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.TABLE;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.bytesOf;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.canonicalPlaintext;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.copy;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.encryptOnce;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.newKmsClient;
import static aws.cryptography.dbesdk.testserver.tests.DbeTestHelpers.standardActions;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import aws.cryptography.dbesdk.testserver.client.client.DBESDKTestServerClient;
import aws.cryptography.dbesdk.testserver.client.model.AttributeValue;
import aws.cryptography.dbesdk.testserver.client.model.CryptoAction;
import aws.cryptography.dbesdk.testserver.client.model.DBESDKClientError;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemInput;
import aws.cryptography.dbesdk.testserver.client.model.DecryptItemOutput;
import aws.cryptography.testserver.tests.TargetPair;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * DB-ESDK cross-language tamper tests — 42 mutations, each run once per
 * launched {@code (encryptTarget, decryptTarget)} pair. Each test method
 * receives a pre-built {@link TestContext} (both endpoints' clients + the
 * per-pair encrypted item), mutates the wire bytes, and asserts decrypt on
 * the pair's decrypt target refuses the mutation with a
 * {@link DBESDKClientError}.
 *
 * <p>Categories (from the DB-ESDK Test Plan §0.3.1):
 * <ul>
 *   <li>Section 1 — Header field tamper (11 mutations)</li>
 *   <li>Section 2 — Footer field tamper (6 mutations)</li>
 *   <li>Section 3 — Attribute-level tamper (9 mutations)</li>
 *   <li>Section 4 — Cross-record splice (5 mutations)</li>
 *   <li>Section 5 — Truncation (8 mutations)</li>
 *   <li>Section 6 — Schema promotion (3 decrypt-side schema mismatches)</li>
 * </ul>
 *
 * <p>Test count = {@code 42 mutations × pairs²} — 378 tests today with three
 * launched targets. Adding a language expands the matrix automatically.
 *
 * <p>All mutations use the AWS-KMS keyring pinned to the ESDK-shared symmetric
 * key ({@link DbeTestHelpers#resolveKmsKeyArn()}), so both sides of a
 * cross-language pair unwrap the same wire EDK. The pre-encrypted per-pair
 * baseline is memoized in {@link #CONTEXTS}: a full run performs one
 * CreateClient + one EncryptItem per pair — not per mutation.
 *
 * <p>The per-pair baseline builder also runs a round-trip check before any
 * mutation-refused assertion: a broken decrypt path that refuses every input
 * would silently pass every tamper assertion for the wrong reason, so we
 * prove the untampered baseline decrypts successfully first. When the check
 * fails, every tamper test for that pair reports the same clear
 * "baseline round-trip failed on {@code <pair>}" cause.
 */
class TamperTests {

    // =====================================================================
    // §0.3.1.1 — Header field tamper (11 mutations of aws_dbe_head).
    // =====================================================================

    /** Version byte set to an out-of-range value (0xFF). */
    @ParameterizedTest(name = "1. Version byte → invalid value 0xFF {0}")
    @MethodSource("testContexts")
    void versionByteInvalid(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[0] = (byte) 0xFF;
        //= specification/structured-encryption/header.md#format-version
        //= type=test
        //# The Version MUST be `0x01` or `0x02`.
        assertDecryptFails(ctx, withHeader(ctx, header), "invalid version byte accepted");
    }

    /** Version byte flipped between the two legal values (0x01 ↔ 0x02). */
    @ParameterizedTest(name = "2. Version byte → 0x01↔0x02 flipped between two legal values {0}")
    @MethodSource("testContexts")
    void versionByteFlippedLegal(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[0] = (byte) (header[0] == 0x01 ? 0x02 : 0x01);
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "flipped-legal version accepted");
    }

    /** Format flavor byte set to an unsupported value (0xFF). */
    @ParameterizedTest(name = "3. Format flavor byte → invalid value 0xFF {0}")
    @MethodSource("testContexts")
    void flavorByteInvalid(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[1] = (byte) 0xFF;
        //= specification/structured-encryption/header.md#format-flavor
        //= type=test
        //# The algorithm suite indicated by the flavor MUST be a
        //# [DBE supported algorithm suite](../../submodules/MaterialProviders/aws-encryption-sdk-specification/framework/algorithm-suites.md#supported-algorithm-suites-enum).
        assertDecryptFails(ctx, withHeader(ctx, header), "invalid flavor byte accepted");
    }

    /** Message ID byte flipped mid-field. */
    @ParameterizedTest(name = "4. Message ID byte (mid-field) {0}")
    @MethodSource("testContexts")
    void messageIdMidFieldFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[16] ^= (byte) 0xFF;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "message ID byte flip accepted");
    }

    /** Encrypt Legend Length byte (big-endian UInt16 after message ID). */
    @ParameterizedTest(name = "5. Encrypt Legend Length (big-endian UInt16 after message ID) {0}")
    @MethodSource("testContexts")
    void encryptLegendLengthFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[34] ^= (byte) 0xFF;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "encrypt legend length flip accepted");
    }

    /** First byte of the Encrypt Legend contents. */
    @ParameterizedTest(name = "6. Encrypt Legend Bytes (first legend character) {0}")
    @MethodSource("testContexts")
    void encryptLegendByteFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[36] ^= (byte) 0xFF;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "encrypt legend byte flip accepted");
    }

    /** Encryption Context count (2 bytes after the legend). */
    @ParameterizedTest(name = "7. Encryption Context count (2 bytes after the legend) {0}")
    @MethodSource("testContexts")
    void encryptionContextCountFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        int legendLen = ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
        int ecCountOffset = 36 + legendLen;
        header[ecCountOffset] ^= (byte) 0x7F;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "EC count flip accepted");
    }

    /** Byte inside the first Encryption Context entry. */
    @ParameterizedTest(name = "8. Encryption Context entry bytes (inside first EC pair) {0}")
    @MethodSource("testContexts")
    void encryptionContextEntryFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        int legendLen = ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
        int ecCountOffset = 36 + legendLen;
        int ecCount = ((header[ecCountOffset] & 0xFF) << 8) | (header[ecCountOffset + 1] & 0xFF);
        if (ecCount == 0) {
            header[ecCountOffset] ^= (byte) 0xFF;
        } else {
            int keyLenOffset = ecCountOffset + 2;
            int keyLen = ((header[keyLenOffset] & 0xFF) << 8) | (header[keyLenOffset + 1] & 0xFF);
            header[keyLenOffset + 2 + Math.min(1, keyLen - 1)] ^= (byte) 0xFF;
        }
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "EC entry flip accepted");
    }

    /** Encrypted Data Key count set to 0 — spec MUST-not condition. */
    @ParameterizedTest(name = "9. Encrypted Data Key count {0}")
    @MethodSource("testContexts")
    void encryptedDataKeyCountZero(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[edkCountOffset(header)] = 0x00;
        //= specification/structured-encryption/header.md#encrypted-data-key-count
        //= type=test
        //# This value MUST be greater than 0.
        assertDecryptFails(ctx, withHeader(ctx, header), "EDK count = 0 accepted");
    }

    /** Byte inside the first Encrypted Data Key ciphertext. */
    @ParameterizedTest(name = "10. Encrypted Data Key entry bytes (first EDK ciphertext) {0}")
    @MethodSource("testContexts")
    void encryptedDataKeyEntryFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        int firstEdkOffset = edkCountOffset(header) + 1;
        header[firstEdkOffset + 10] ^= (byte) 0xFF;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "EDK entry flip accepted");
    }

    /** Byte in the header commitment (last 32 bytes). */
    @ParameterizedTest(name = "11. Header Commitment (last 32 bytes of the header) {0}")
    @MethodSource("testContexts")
    void headerCommitmentFlip(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        header[header.length - 1] ^= (byte) 0xFF;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, header), "header commitment flip accepted");
    }

    // =====================================================================
    // §0.3.1.2 — Footer field tamper (6 mutations of aws_dbe_foot).
    // =====================================================================

    @ParameterizedTest(name = "1. Flip a byte inside a Recipient Tag {0}")
    @MethodSource("testContexts")
    void recipientTagByteFlip(TestContext ctx) {
        byte[] footer = footerBytes(ctx);
        footer[10] ^= (byte) 0xFF;
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, withFooter(ctx, footer), "recipient tag flip accepted");
    }

    @ParameterizedTest(name = "2. Zero the entire Recipient Tag block {0}")
    @MethodSource("testContexts")
    void recipientTagZeroed(TestContext ctx) {
        byte[] footer = footerBytes(ctx);
        for (int i = 0; i < footer.length; i++) footer[i] = 0;
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, withFooter(ctx, footer), "zeroed recipient tag accepted");
    }

    @ParameterizedTest(name = "3. Truncate the last byte of the Recipient Tag {0}")
    @MethodSource("testContexts")
    void recipientTagSingleByteTruncated(TestContext ctx) {
        byte[] footer = footerBytes(ctx);
        byte[] trunc = new byte[footer.length - 1];
        System.arraycopy(footer, 0, trunc, 0, trunc.length);
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, withFooter(ctx, trunc), "single-byte truncated tag accepted");
    }

    @ParameterizedTest(name = "4. Add 96 bytes of fake signature on a non-signing (flavor 0x00) footer {0}")
    @MethodSource("testContexts")
    void spuriousSignatureOnNonSigningFooter(TestContext ctx) {
        byte[] footer = footerBytes(ctx);
        byte[] extended = new byte[footer.length + 96];
        System.arraycopy(footer, 0, extended, 0, footer.length);
        for (int i = footer.length; i < extended.length; i++) extended[i] = (byte) 0xAB;
        //= specification/structured-encryption/footer.md#signature
        //= type=test
        //# The signature MUST be included in the footer if the flavor
        //# in the [header](./header.md#format-flavor) is 0x01
        //# and MUST NOT be included in the footer if the flavor
        //# in the [header](./header.md#format-flavor) is 0x00.
        assertDecryptFails(ctx, withFooter(ctx, extended), "unexpected signature bytes accepted");
    }

    @ParameterizedTest(name = "5. Empty footer (0 bytes) {0}")
    @MethodSource("testContexts")
    void emptyFooter(TestContext ctx) {
        //= specification/structured-encryption/decrypt-path-structure.md#verify-signatures
        //= type=test
        //# The footer field value MUST be [verified](footer.md#footer-verification).
        assertDecryptFails(ctx, withFooter(ctx, new byte[0]), "empty footer accepted");
    }

    @ParameterizedTest(name = "6. Extra trailing byte after the Recipient Tag {0}")
    @MethodSource("testContexts")
    void extraTrailingByte(TestContext ctx) {
        byte[] footer = footerBytes(ctx);
        byte[] extended = new byte[footer.length + 1];
        System.arraycopy(footer, 0, extended, 0, footer.length);
        extended[footer.length] = (byte) 0xAA;
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, withFooter(ctx, extended), "trailing byte accepted");
    }

    // =====================================================================
    // §0.3.1.3 — Attribute-level tamper (9 mutations of per-attribute values).
    // =====================================================================

    @ParameterizedTest(name = "1. Flip a byte in the ciphertext of an encrypted attribute {0}")
    @MethodSource("testContexts")
    void ciphertextByteFlip(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        byte[] bytes = bytesOf(item.get(SECRET));
        bytes[5] ^= (byte) 0xFF;
        item.put(SECRET, AttributeValue.builder().b(ByteBuffer.wrap(bytes)).build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "encrypted ciphertext byte flip accepted");
    }

    @ParameterizedTest(name = "2. Flip a byte in a sign-only plaintext attribute {0}")
    @MethodSource("testContexts")
    void signOnlyPlaintextFlip(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(PUBLIC, AttributeValue.builder().s(item.get(PUBLIC).getS() + "!").build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "sign-only plaintext mutation accepted");
    }

    @ParameterizedTest(name = "3. Delete a signed attribute {0}")
    @MethodSource("testContexts")
    void deleteSignedAttribute(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.remove(PUBLIC);
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "missing signed attribute accepted");
    }

    @ParameterizedTest(name = "4. Add an extra signed attribute not present at encrypt time {0}")
    @MethodSource("testContexts")
    void addExtraSignedAttribute(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put("intruder", AttributeValue.builder().s("added").build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "extra signed attribute accepted");
    }

    @ParameterizedTest(name = "5. Rename an attribute (move a value to a different key) {0}")
    @MethodSource("testContexts")
    void renameAttribute(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        AttributeValue value = item.remove(PUBLIC);
        item.put("public_renamed", value);
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "renamed attribute accepted");
    }

    @ParameterizedTest(name = "6. Swap two sign-only attribute VALUES (keep both keys) {0}")
    @MethodSource("testContexts")
    void swapSignOnlyValues(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        String pk = item.get(PK).getS();
        String pub = item.get(PUBLIC).getS();
        item.put(PK, AttributeValue.builder().s(pub).build());
        item.put(PUBLIC, AttributeValue.builder().s(pk).build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "swapped sign-only attribute values accepted");
    }

    @ParameterizedTest(name = "7. Change the 2-byte TypeID prefix on an encrypted attribute value {0}")
    @MethodSource("testContexts")
    void typeIdMutation(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        byte[] bytes = bytesOf(item.get(SECRET));
        bytes[0] ^= (byte) 0xFF;
        bytes[1] ^= (byte) 0xFF;
        item.put(SECRET, AttributeValue.builder().b(ByteBuffer.wrap(bytes)).build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "TypeID mutation accepted");
    }

    @ParameterizedTest(name = "8. Change the partition key value (sign-only) {0}")
    @MethodSource("testContexts")
    void partitionKeyMutation(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(PK, AttributeValue.builder().s("intruder-pk").build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "partition key mutation accepted");
    }

    @ParameterizedTest(name = "9. Replace encrypted attribute with plaintext string {0}")
    @MethodSource("testContexts")
    void encryptedToPlaintextSwap(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(SECRET, AttributeValue.builder().s("hunter2").build());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "encrypted-to-plaintext swap accepted");
    }

    // =====================================================================
    // §0.3.1.4 — Cross-record splice (5 mixings of head/foot/attrs).
    // =====================================================================

    @ParameterizedTest(name = "1. Splice: header from record1, attributes+footer from record2 {0}")
    @MethodSource("testContexts")
    void spliceHeaderFromRecord1(TestContext ctx) {
        Map<String, AttributeValue> other = encryptOther(ctx);
        Map<String, AttributeValue> item = copy(other);
        item.put(HEAD, ctx.encryptedItem().get(HEAD));
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "cross-record header splice accepted");
    }

    @ParameterizedTest(name = "2. Splice: footer from record1, header+attributes from record2 {0}")
    @MethodSource("testContexts")
    void spliceFooterFromRecord1(TestContext ctx) {
        Map<String, AttributeValue> other = encryptOther(ctx);
        Map<String, AttributeValue> item = copy(other);
        item.put(FOOT, ctx.encryptedItem().get(FOOT));
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "cross-record footer splice accepted");
    }

    @ParameterizedTest(name = "3. Splice: header+footer from record1, attributes from record2 {0}")
    @MethodSource("testContexts")
    void spliceHeadAndFootFromRecord1(TestContext ctx) {
        Map<String, AttributeValue> other = encryptOther(ctx);
        Map<String, AttributeValue> item = copy(other);
        item.put(HEAD, ctx.encryptedItem().get(HEAD));
        item.put(FOOT, ctx.encryptedItem().get(FOOT));
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "cross-record head+foot splice accepted");
    }

    @ParameterizedTest(name = "4. Splice: single encrypted attribute from record2 into record1 {0}")
    @MethodSource("testContexts")
    void spliceEncryptedAttributeFromRecord2(TestContext ctx) {
        Map<String, AttributeValue> other = encryptOther(ctx);
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(SECRET, other.get(SECRET));
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "cross-record encrypted attribute accepted");
    }

    @ParameterizedTest(name = "5. Splice: header/footer from a different logical table {0}")
    @MethodSource("testContexts")
    void spliceFromDifferentTable(TestContext ctx) {
        // A separate encrypt-side client whose logical table differs by name
        // only — same keyring, so its EDKs unwrap fine, but the canonical
        // path prefix differs and the signature should reject.
        String otherTableClient = newKmsClient(ctx.encryptClient(), "another-table", PK,
            standardActions(), List.of());
        Map<String, AttributeValue> encForOtherTable = encryptOnce(
            ctx.encryptClient(), otherTableClient, canonicalPlaintext());
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(HEAD, encForOtherTable.get(HEAD));
        item.put(FOOT, encForOtherTable.get(FOOT));
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx, item, "cross-table splice accepted");
    }

    // =====================================================================
    // §0.3.1.5 — Truncation (8 head/foot truncations + additions).
    // =====================================================================

    @ParameterizedTest(name = "1. Header truncated mid-way (drop last 33 bytes = commitment + 1) {0}")
    @MethodSource("testContexts")
    void headerTruncatedMidCommitment(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        byte[] trunc = new byte[header.length - 33];
        System.arraycopy(header, 0, trunc, 0, trunc.length);
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, trunc), "mid-header truncation accepted");
    }

    @ParameterizedTest(name = "2. Header truncated to the commitment boundary (last 32 bytes stripped) {0}")
    @MethodSource("testContexts")
    void headerTruncatedAtCommitmentBoundary(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        byte[] trunc = new byte[header.length - 32];
        System.arraycopy(header, 0, trunc, 0, trunc.length);
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, trunc), "commitment-stripped header accepted");
    }

    @ParameterizedTest(name = "3. Header missing entirely (aws_dbe_head attribute removed) {0}")
    @MethodSource("testContexts")
    void headerAttributeRemoved(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.remove(HEAD);
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, item, "missing aws_dbe_head accepted");
    }

    @ParameterizedTest(name = "4. Header truncated to a single byte {0}")
    @MethodSource("testContexts")
    void headerTruncatedToSingleByte(TestContext ctx) {
        byte[] trunc = new byte[] { headerBytes(ctx)[0] };
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, trunc), "1-byte header accepted");
    }

    @ParameterizedTest(name = "5. Header extended with 16 extra trailing bytes {0}")
    @MethodSource("testContexts")
    void headerExtendedWithTrailingBytes(TestContext ctx) {
        byte[] header = headerBytes(ctx);
        byte[] extended = new byte[header.length + 16];
        System.arraycopy(header, 0, extended, 0, header.length);
        for (int i = header.length; i < extended.length; i++) extended[i] = (byte) 0xCC;
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, withHeader(ctx, extended), "trailing-byte header accepted");
    }

    @ParameterizedTest(name = "6. Footer truncated to a single byte {0}")
    @MethodSource("testContexts")
    void footerTruncatedToSingleByte(TestContext ctx) {
        byte[] footer = footerBytes(ctx);
        byte[] trunc = new byte[] { footer[0] };
        //= specification/structured-encryption/decrypt-path-structure.md#verify-signatures
        //= type=test
        //# The footer field value MUST be [verified](footer.md#footer-verification).
        assertDecryptFails(ctx, withFooter(ctx, trunc), "1-byte footer accepted");
    }

    @ParameterizedTest(name = "7. Footer missing entirely (aws_dbe_foot attribute removed) {0}")
    @MethodSource("testContexts")
    void footerAttributeRemoved(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.remove(FOOT);
        //= specification/structured-encryption/decrypt-path-structure.md#verify-signatures
        //= type=test
        //# A footer field MUST exist with the name `aws_dbe_foot`
        assertDecryptFails(ctx, item, "missing aws_dbe_foot accepted");
    }

    @ParameterizedTest(name = "8. Both aws_dbe_head and aws_dbe_foot removed {0}")
    @MethodSource("testContexts")
    void bothHeadAndFootRemoved(TestContext ctx) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.remove(HEAD);
        item.remove(FOOT);
        //= specification/structured-encryption/decrypt-path-structure.md#parse-the-header
        //= type=test
        //# The header field value MUST be [verified](header.md#commitment-verification)
        assertDecryptFails(ctx, item, "missing head+foot accepted");
    }

    // =====================================================================
    // §0.3.1.6 — Schema promotion (3 decrypt-side schema mismatches).
    // Instead of mutating bytes on the wire the tests build a second
    // decrypt-side client with a different schema and decrypt the pair's
    // baseline against it; the recipient-tag check must catch every mismatch.
    // =====================================================================

    @ParameterizedTest(name = "1. Decrypt schema marks a formerly-signed attribute as unsigned {0}")
    @MethodSource("testContexts")
    void signedToUnsignedPromotion(TestContext ctx) {
        // Encrypt used PUBLIC as SIGN_ONLY; decrypt now claims PUBLIC is
        // unsigned via allowedUnsignedAttributes. Signature scope shift.
        Map<String, CryptoAction> reduced = new LinkedHashMap<>();
        reduced.put(PK, CryptoAction.SIGN_ONLY);
        reduced.put(SECRET, CryptoAction.ENCRYPT_AND_SIGN);
        String otherClientId = newKmsClient(
            ctx.decryptClient(), TABLE, PK, reduced, List.of(PUBLIC));
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx.decryptClient(), otherClientId, ctx.encryptedItem(),
            "signed→unsigned attribute promotion accepted");
    }

    @ParameterizedTest(name = "2. Decrypt uses a different partitionKeyName {0}")
    @MethodSource("testContexts")
    void differentPartitionKeyName(TestContext ctx) {
        String otherClientId = newKmsClient(
            ctx.decryptClient(), TABLE, PUBLIC, standardActions(), List.of());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx.decryptClient(), otherClientId, ctx.encryptedItem(),
            "different partitionKeyName accepted");
    }

    @ParameterizedTest(name = "3. Decrypt uses a different logicalTableName {0}")
    @MethodSource("testContexts")
    void differentLogicalTableName(TestContext ctx) {
        String otherClientId = newKmsClient(
            ctx.decryptClient(), "different-table-name", PK, standardActions(), List.of());
        //= specification/structured-encryption/footer.md#recipient-tag-verification
        //= type=test
        //# Verification MUST fail unless at least one of the [Recipient Tags](#recipient-tags)
        //# matches a calculated recipient tag using the provided symmetricSigningKey.
        assertDecryptFails(ctx.decryptClient(), otherClientId, ctx.encryptedItem(),
            "different logicalTableName accepted");
    }

    // =====================================================================
    // TestContext — the per-pair pre-encrypted state each test method receives.
    // =====================================================================

    /**
     * Per-pair pre-built state a tamper test receives:
     * <ul>
     *   <li>{@code pair} — the {@code (encrypt, decrypt)} target pair;
     *       {@link #toString()} formats as e.g. {@code java-v3->rust-v1} for
     *       parameterized test names.</li>
     *   <li>{@code encryptClient / decryptClient} — the two HTTP clients
     *       already cached in {@link DbeTestServerClients} per endpoint.</li>
     *   <li>{@code encryptClientId / decryptClientId} — the two
     *       server-assigned {@code clientId}s from the CreateClient calls
     *       (both configured with the same schema and AWS-KMS keyring).</li>
     *   <li>{@code encryptedItem} — the untampered baseline encrypted on
     *       {@code encryptClient}. Every mutation reads bytes from here.</li>
     * </ul>
     */
    record TestContext(
        TargetPair pair,
        DBESDKTestServerClient encryptClient,
        DBESDKTestServerClient decryptClient,
        String encryptClientId,
        String decryptClientId,
        Map<String, AttributeValue> encryptedItem
    ) {
        @Override
        public String toString() {
            return pair.toString();
        }
    }

    // =====================================================================
    // TestContext provider (the @MethodSource every test above binds to) +
    // per-pair cache. Each pair's baseline is built lazily on first request
    // and shared by all 42 tests that receive it.
    //
    // Every test method receives TestContext directly — no forPair(pair) lookup
    // inside the method body.
    // =====================================================================

    private static final Map<TargetPair, TestContext> CONTEXTS = new ConcurrentHashMap<>();

    static Stream<TestContext> testContexts() {
        return DbeTestHelpers.pairs().stream()
            .map(pair -> CONTEXTS.computeIfAbsent(pair, TamperTests::buildContext));
    }

    private static TestContext buildContext(TargetPair pair) {
        DBESDKTestServerClient encryptClient = DbeTestServerClients.forEndpoint(pair.encryptEndpoint());
        DBESDKTestServerClient decryptClient = DbeTestServerClients.forEndpoint(pair.decryptEndpoint());
        // Same schema on both sides — a matched pair is the baseline. Tests
        // that want a decrypt-side schema mismatch build their own client via
        // DbeTestHelpers.newKmsClient(...).
        Map<String, CryptoAction> actions = standardActions();
        String encryptClientId = newKmsClient(encryptClient, TABLE, PK, actions, List.of());
        String decryptClientId = newKmsClient(decryptClient, TABLE, PK, actions, List.of());
        Map<String, AttributeValue> plaintext = canonicalPlaintext();
        Map<String, AttributeValue> item = encryptOnce(encryptClient, encryptClientId, plaintext);
        assertNotNull(item.get(HEAD),
            "encrypted item from " + pair.encryptTarget().label() + " missing aws_dbe_head");
        assertNotNull(item.get(FOOT),
            "encrypted item from " + pair.encryptTarget().label() + " missing aws_dbe_foot");
        // Prove the untampered baseline actually round-trips before any tamper
        // test runs against this pair. Without this, a broken decrypt path
        // that refuses every input would pass every mutation-refused assertion
        // in the tamper suite (378 tests) for the wrong reason. Failing here
        // once per pair fails the first tamper test that requests the pair's
        // baseline with a clear "baseline round-trip failed" cause, and every
        // subsequent tamper test for the same pair fails identically —
        // instead of scattered errors deep inside each mutation.
        verifyPairRoundTrip(pair, decryptClient, decryptClientId, item, plaintext);
        return new TestContext(pair, encryptClient, decryptClient, encryptClientId, decryptClientId, item);
    }

    private static void verifyPairRoundTrip(TargetPair pair, DBESDKTestServerClient decryptClient,
                                                String decryptClientId,
                                                Map<String, AttributeValue> item,
                                                Map<String, AttributeValue> plaintext) {
        try {
            DecryptItemOutput decrypted = decryptClient.decryptItem(
                DecryptItemInput.builder()
                    .clientId(decryptClientId)
                    .encryptedItem(item)
                    .build());
            Map<String, AttributeValue> recovered = decrypted.getPlaintextItem();
            assertNotNull(recovered,
                "baseline decrypt on " + pair.decryptTarget().label() + " returned no plaintext");
            for (Map.Entry<String, AttributeValue> entry : plaintext.entrySet()) {
                AttributeValue actual = recovered.get(entry.getKey());
                assertNotNull(actual,
                    "baseline round-trip on " + pair + " lost attribute '" + entry.getKey() + "'");
                assertTrue(entry.getValue().getS().equals(actual.getS()),
                    "baseline round-trip on " + pair
                        + " did not preserve attribute '" + entry.getKey()
                        + "' (expected " + entry.getValue().getS()
                        + ", got " + actual.getS() + ")");
            }
        } catch (RuntimeException e) {
            fail("baseline round-trip failed on " + pair
                + " — tamper tests for this pair would give misleading results. Root cause: " + e);
        }
    }

    // =====================================================================
    // Tamper-specific free helpers.
    // =====================================================================

    /** @return the raw bytes of the baseline's {@code aws_dbe_head} attribute. */
    private static byte[] headerBytes(TestContext ctx) {
        return bytesOf(ctx.encryptedItem().get(HEAD));
    }

    /** @return the raw bytes of the baseline's {@code aws_dbe_foot} attribute. */
    private static byte[] footerBytes(TestContext ctx) {
        return bytesOf(ctx.encryptedItem().get(FOOT));
    }

    /** @return a copy of the baseline item with its {@code aws_dbe_head} replaced by {@code header}. */
    private static Map<String, AttributeValue> withHeader(TestContext ctx, byte[] header) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(HEAD, AttributeValue.builder().b(ByteBuffer.wrap(header)).build());
        return item;
    }

    /** @return a copy of the baseline item with its {@code aws_dbe_foot} replaced by {@code footer}. */
    private static Map<String, AttributeValue> withFooter(TestContext ctx, byte[] footer) {
        Map<String, AttributeValue> item = copy(ctx.encryptedItem());
        item.put(FOOT, AttributeValue.builder().b(ByteBuffer.wrap(footer)).build());
        return item;
    }

    /**
     * Decrypt {@code tampered} on the pair's decrypt client and assert the
     * DBE library refuses it with a {@link DBESDKClientError}.
     */
    private static void assertDecryptFails(TestContext ctx, Map<String, AttributeValue> tampered, String message) {
        assertDecryptFails(ctx.decryptClient(), ctx.decryptClientId(), tampered, message);
    }

    /**
     * As {@link #assertDecryptFails(TestContext, Map, String)} but on a
     * caller-supplied client/id — schema-promotion tests build their own
     * decrypt-side client with a mismatched schema.
     */
    private static void assertDecryptFails(DBESDKTestServerClient client, String clientId,
                                           Map<String, AttributeValue> encryptedItem, String message) {
        DBESDKClientError error = assertThrows(
            DBESDKClientError.class,
            () -> client.decryptItem(DecryptItemInput.builder()
                .clientId(clientId)
                .encryptedItem(encryptedItem)
                .build()),
            message);
        assertTrue(error.getMessage() == null || !error.getMessage().isEmpty(),
            "DBE error surfaced but with an empty message");
    }

    /** Encrypt a second record on the baseline's encrypt-side client (used by the splice mutations). */
    private static Map<String, AttributeValue> encryptOther(TestContext ctx) {
        Map<String, AttributeValue> otherPlaintext = new LinkedHashMap<>();
        otherPlaintext.put(PK, AttributeValue.builder().s("item-splice-2").build());
        otherPlaintext.put(SECRET, AttributeValue.builder().s("other-secret").build());
        otherPlaintext.put(PUBLIC, AttributeValue.builder().s("other-public").build());
        return encryptOnce(ctx.encryptClient(), ctx.encryptClientId(), otherPlaintext);
    }

    /**
     * Byte offset of the EDK count in the header:
     * {@code 1 + 1 + 32 + 2 + legendLen + 2 + sum(EC entries)}.
     */
    private static int edkCountOffset(byte[] header) {
        int legendLen = ((header[34] & 0xFF) << 8) | (header[35] & 0xFF);
        int off = 36 + legendLen;
        int ecCount = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
        off += 2;
        for (int i = 0; i < ecCount; i++) {
            int keyLen = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
            off += 2 + keyLen;
            int valLen = ((header[off] & 0xFF) << 8) | (header[off + 1] & 0xFF);
            off += 2 + valLen;
        }
        return off;
    }
}
