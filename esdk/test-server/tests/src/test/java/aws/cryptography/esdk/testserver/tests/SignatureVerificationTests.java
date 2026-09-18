package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Footer-signature conformance (FOOT-007): the footer signature is a standard ECDSA signature under
 * the suite's curve, over exactly the header ‖ body, verifiable with the public key the server
 * published in the {@code aws-crypto-public-key} encryption-context entry. This test verifies the
 * signature independently (its own JCE ECDSA verifier over the parsed signed region and decompressed
 * public key), so it proves the produced signature is genuine rather than relying on decrypt to
 * re-verify it. Catalog behavior (esdk-test-behavior-catalog.md):
 *
 * <ul>
 *   <li><b>FOOT-007</b> — the footer signature is ECDSA under the suite's curve over header ‖ body:
 *       independent verification succeeds, and perturbed input or a wrong key each fail
 *       ({@code spec/client-apis/encrypt.md#construct-the-signature},
 *       {@code spec/client-apis/decrypt.md#verify-the-signature}).</li>
 * </ul>
 *
 * <p>Per-server property (the signature is produced by the encrypt target). Signature verification
 * is keyring-independent, so each combination runs once under the keyring both endpoints support
 * ({@link ConformanceKeyring}): Raw-AES where available, else the hierarchical keyring the native
 * Rust ESDK supports. Over a P-384 (SHA-384) and a P-256 (SHA-256) signing suite.
 */
class SignatureVerificationTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server footer-signature plaintext".getBytes(StandardCharsets.UTF_8);
    private static final String PUBLIC_KEY_EC = "aws-crypto-public-key";

    /** A signing suite plus its JCE curve name and ECDSA signature algorithm. */
    record SigningLayout(String label, ESDKCommitmentPolicy policy, ESDKAlgorithmSuiteId suite,
                         String curveName, String signatureAlgorithm) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final SigningLayout P384 = new SigningLayout("v2-ecdsa-p384",
        ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, "secp384r1",
        "SHA384withECDSA");
    private static final SigningLayout P256 = new SigningLayout("v1-ecdsa-p256",
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256, "secp256r1",
        "SHA256withECDSA");

    static List<Arguments> cases() {
        List<Arguments> cases = new ArrayList<>();
        for (LanguageServerTarget target : LanguageServerRegistry.shared().targets()) {
            cases.add(Arguments.of(target, P384));
            cases.add(Arguments.of(target, P256));
        }
        return cases;
    }

    /**
     * The single keyring both endpoints support (Raw-AES, else hierarchical), gated so the
     * combination is a visible skip when they share none. Resolved before producing a message.
     */
    private static ConformanceKeyring keyringFor(EndpointPair combination) {
        Optional<ConformanceKeyring> negotiated = ConformanceKeyring.negotiate(combination);
        Assumptions.assumeTrue(negotiated.isPresent(),
            "no keyring shared by both endpoints of " + combination);
        ConformanceKeyring keyring = negotiated.get();
        FeatureGate.require(keyring.features(), combination);
        return keyring;
    }

    /**
     * FOOT-007: the footer signature verifies independently over header ‖ body with the published
     * verification key; a perturbed signed region and a wrong key each fail to verify.
     */
    @ParameterizedTest(name = "footerSignatureVerifies[{1}] {0}")
    @MethodSource("cases")
    void footerSignatureIndependentlyVerifies(LanguageServerTarget target, SigningLayout layout)
        throws Exception {
        ESDKClientConfig config =
            keyringFor(new EndpointPair(target, target)).config(layout.policy());
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT, Map.of(),
            layout.suite(), null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.footerOffset >= 0 && message.signatureLength > 0,
            target + " " + layout + ": a signing suite must produce a footer signature");

        // header ‖ body is everything before the footer; the signature follows the 2-byte length.
        int signedLength = message.footerOffset;
        byte[] signature = Arrays.copyOfRange(ciphertext, message.footerOffset + 2,
            message.footerOffset + 2 + message.signatureLength);
        PublicKey publicKey = publicKeyFrom(layout.curveName(),
            java.util.Base64.getDecoder().decode(verificationKeyValue(message)));

        assertTrue(verify(layout.signatureAlgorithm(), publicKey, ciphertext, signedLength, signature),
            target + " " + layout + ": the footer signature must verify over header ‖ body with the "
                + "published verification key");

        byte[] perturbed = ciphertext.clone();
        perturbed[signedLength / 2] ^= (byte) 0x01;
        assertFalse(verify(layout.signatureAlgorithm(), publicKey, perturbed, signedLength, signature),
            target + " " + layout + ": the signature must not verify over a perturbed signed region");

        PublicKey wrongKey = freshPublicKey(layout.curveName());
        assertFalse(verify(layout.signatureAlgorithm(), wrongKey, ciphertext, signedLength, signature),
            target + " " + layout + ": the signature must not verify under a different key");
    }

    private static boolean verify(String algorithm, PublicKey publicKey, byte[] message,
                                  int length, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(publicKey);
        verifier.update(message, 0, length);
        return verifier.verify(signature);
    }

    static List<Arguments> pairCases() {
        List<Arguments> cases = new ArrayList<>();
        for (EndpointPair pair : LanguageServerRegistry.shared().pairs()) {
            cases.add(Arguments.of(pair, P384));
            cases.add(Arguments.of(pair, P256));
        }
        return cases;
    }

    /**
     * A footer signature replaced with a structurally perfect ECDSA signature made by a
     * DIFFERENT key over the same header ‖ body is rejected on decrypt
     * ({@code spec/client-apis/decrypt.md#verify-the-signature}). This is sharper than
     * corrupting signature bytes: a corrupted signature usually fails DER parsing, so it cannot
     * detect a decryptor that parses the signature and then ignores the verifier's boolean
     * result — the verification bypass fixed in the Dafny ESDK in 2022, where only parse
     * failures propagated and {@code Success(false)} was discarded.
     */
    @ParameterizedTest(name = "wrongKeySignatureRejected[{1}] {0}")
    @MethodSource("pairCases")
    void decryptRejectsWellFormedSignatureByWrongKey(EndpointPair pair, SigningLayout layout)
        throws Exception {
        ESDKClientConfig config = keyringFor(pair).config(layout.policy());
        byte[] ciphertext = EsdkOps.encrypt(pair.encryptEndpoint(), config, PLAINTEXT,
            Map.of(), layout.suite(), null);
        EsdkMessage message = EsdkMessage.parse(ciphertext);
        assertTrue(message.footerOffset >= 0 && message.signatureLength > 0,
            pair + " " + layout + ": a signing suite must produce a footer signature");

        KeyPair wrongKeyPair = freshKeyPair(layout.curveName());
        Signature signer = Signature.getInstance(layout.signatureAlgorithm());
        signer.initSign(wrongKeyPair.getPrivate());
        signer.update(ciphertext, 0, message.footerOffset);
        byte[] forgedSignature = signer.sign();

        byte[] forged = new byte[message.footerOffset + 2 + forgedSignature.length];
        System.arraycopy(ciphertext, 0, forged, 0, message.footerOffset);
        forged[message.footerOffset] = (byte) (forgedSignature.length >>> 8);
        forged[message.footerOffset + 1] = (byte) forgedSignature.length;
        System.arraycopy(forgedSignature, 0, forged, message.footerOffset + 2,
            forgedSignature.length);

        assertThrows(ESDKClientError.class,
            () -> EsdkOps.decrypt(pair.decryptEndpoint(), config, forged),
            pair + " " + layout + ": a well-formed signature by a key other than the message's "
                + "verification key must be rejected");
    }

    /**
     * Every emitted footer signature is canonical DER: one SEQUENCE of exactly two
     * minimally-encoded non-negative INTEGERs filling the footer's 2-byte length field.
     * Post-2024 implementations parse the signature strictly (the signature-verification
     * advisories fixed leniencies such as trailing bytes and non-minimal integers), so an
     * encryptor emitting non-canonical DER produces messages that strict readers reject.
     * Historic encoder bugs — a sign-bit mishandled when converting raw (r, s) to DER, or a
     * component length taken from the wrong integer — appear on roughly every other message,
     * so a small sample per suite detects them deterministically.
     */
    @ParameterizedTest(name = "footerSignatureCanonicalDer[{1}] {0}")
    @MethodSource("cases")
    void emittedFooterSignatureIsCanonicalDer(LanguageServerTarget target, SigningLayout layout) {
        ESDKClientConfig config =
            keyringFor(new EndpointPair(target, target)).config(layout.policy());
        for (int i = 0; i < 8; i++) {
            byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), config, PLAINTEXT,
                Map.of(), layout.suite(), null);
            EsdkMessage message = EsdkMessage.parse(ciphertext);
            byte[] signature = Arrays.copyOfRange(ciphertext, message.footerOffset + 2,
                message.footerOffset + 2 + message.signatureLength);
            String problem = canonicalDerEcdsaProblem(signature);
            assertTrue(problem == null,
                target + " " + layout + " sample " + i + ": footer signature must be canonical "
                    + "DER, but " + problem);
        }
    }

    /**
     * @return null when {@code sig} is one canonical-DER ECDSA signature (SEQUENCE of two
     *     minimal non-negative INTEGERs, no trailing bytes), else a description of the defect.
     */
    private static String canonicalDerEcdsaProblem(byte[] sig) {
        if (sig.length < 8 || (sig[0] & 0xFF) != 0x30) {
            return "it does not start with a SEQUENCE tag";
        }
        int seqLen = sig[1] & 0xFF;
        int pos = 2;
        if (seqLen == 0x81) {
            seqLen = sig[2] & 0xFF;
            pos = 3;
            if (seqLen < 0x80) {
                return "it uses a long-form SEQUENCE length for a short value";
            }
        } else if (seqLen >= 0x80) {
            return "its SEQUENCE length form is invalid for an ECDSA signature";
        }
        if (pos + seqLen != sig.length) {
            return "its SEQUENCE length does not fill the signature field exactly (trailing bytes)";
        }
        for (int component = 0; component < 2; component++) {
            if (pos + 2 > sig.length || (sig[pos] & 0xFF) != 0x02) {
                return "component " + component + " is not an INTEGER";
            }
            int len = sig[pos + 1] & 0xFF;
            pos += 2;
            if (len == 0 || len >= 0x80 || pos + len > sig.length) {
                return "component " + component + " has an invalid length";
            }
            int first = sig[pos] & 0xFF;
            if ((first & 0x80) != 0) {
                return "component " + component + " is negative (missing 0x00 pad for a high bit)";
            }
            if (len > 1 && first == 0x00 && (sig[pos + 1] & 0x80) == 0) {
                return "component " + component + " has a superfluous leading 0x00 (non-minimal)";
            }
            pos += len;
        }
        return pos == sig.length ? null : "it has bytes after the second INTEGER";
    }

    /** The base64 text stored under {@code aws-crypto-public-key} in the header AAD. */
    private static String verificationKeyValue(EsdkMessage message) {
        byte[] b = message.bytes;
        int pos = message.aadContentOffset;
        int pairs = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
        pos += 2;
        for (int i = 0; i < pairs; i++) {
            int keyLen = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2;
            String key = new String(b, pos, keyLen, StandardCharsets.US_ASCII);
            pos += keyLen;
            int valLen = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            pos += 2;
            if (key.equals(PUBLIC_KEY_EC)) {
                return new String(b, pos, valLen, StandardCharsets.US_ASCII);
            }
            pos += valLen;
        }
        throw new IllegalStateException("header AAD has no " + PUBLIC_KEY_EC + " entry");
    }

    private static ECParameterSpec ecParameters(String curveName) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    /** Build an EC public key from a SEC1 compressed point (prefix 0x02/0x03 ‖ x). */
    private static PublicKey publicKeyFrom(String curveName, byte[] compressedPoint) throws Exception {
        ECParameterSpec params = ecParameters(curveName);
        EllipticCurve curve = params.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressedPoint, 1, compressedPoint.length));
        // y^2 = x^3 + a*x + b (mod p); with p ≡ 3 (mod 4), sqrt(z) = z^((p+1)/4) mod p.
        BigInteger alpha = x.modPow(BigInteger.valueOf(3), p)
            .add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        BigInteger y = alpha.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        boolean wantOdd = (compressedPoint[0] & 0xFF) == 0x03;
        if (y.testBit(0) != wantOdd) {
            y = p.subtract(y);
        }
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
    }

    private static PublicKey freshPublicKey(String curveName) throws Exception {
        return freshKeyPair(curveName).getPublic();
    }

    private static KeyPair freshKeyPair(String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }
}
