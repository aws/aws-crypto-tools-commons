package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
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
import java.util.Set;
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
 * <p>Per-server property (the signature is produced by the encrypt target). Fully offline (Raw-AES),
 * over a P-384 (SHA-384) and a P-256 (SHA-256) signing suite.
 */
class SignatureVerificationTests {

    private static final byte[] PLAINTEXT =
        "esdk-test-server footer-signature plaintext".getBytes(StandardCharsets.UTF_8);
    private static final String PUBLIC_KEY_EC = "aws-crypto-public-key";

    /** A signing suite plus its JCE curve name and ECDSA signature algorithm. */
    record SigningLayout(String label, ESDKClientConfig config, ESDKAlgorithmSuiteId suite,
                         String curveName, String signatureAlgorithm) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final SigningLayout P384 = new SigningLayout("v2-ecdsa-p384",
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT),
        ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, "secp384r1",
        "SHA384withECDSA");
    private static final SigningLayout P256 = new SigningLayout("v1-ecdsa-p256",
        EsdkClientConfigs.rawAesWithCommitmentPolicy(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT),
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
     * FOOT-007: the footer signature verifies independently over header ‖ body with the published
     * verification key; a perturbed signed region and a wrong key each fail to verify.
     */
    @ParameterizedTest(name = "footerSignatureVerifies[{1}] {0}")
    @MethodSource("cases")
    void footerSignatureIndependentlyVerifies(LanguageServerTarget target, SigningLayout layout)
        throws Exception {
        FeatureGate.require(Set.of("raw-aes"), new EndpointPair(target, target));
        byte[] ciphertext = EsdkOps.encrypt(target.endpoint(), layout.config(), PLAINTEXT, Map.of(),
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
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair().getPublic();
    }
}
