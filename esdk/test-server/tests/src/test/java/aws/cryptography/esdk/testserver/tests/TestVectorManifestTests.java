package aws.cryptography.esdk.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.AwsKmsHierarchicalKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.esdk.testserver.client.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RawRsaKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RequiredEncryptionContextCmmConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Drives the AWS Crypto Tools test-vector-framework encrypt manifest (V5) through the
 * Test_Client: the framework corpus (keys.json + encrypt-manifest.json, vendored under
 * {@code resources/vectors/}) is parsed here, and each vector's key descriptions, algorithm
 * suite, encryption context and frame size are replayed as a cross-language round trip —
 * encrypt on one Language_Server, decrypt on another — over the full {@code pairs()} matrix.
 *
 * <p>This is the in-test-server port of the ESDK Dafny interop test-vector workflows: the
 * server's own {@code Encrypt}/{@code Decrypt} operations do the work, so no per-language
 * vector runner is needed. Only vectors whose encrypt AND decrypt key descriptions map to a
 * currently-supported keyring (Raw-AES, Raw-RSA) are emitted; the rest are skipped and
 * counted (see {@link #manifestRoundTrips()}).
 */
class TestVectorManifestTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** ESDK algorithm-suite hex id (as written in the manifest) to the modeled enum. */
    private static final Map<String, ESDKAlgorithmSuiteId> HEX_TO_SUITE = Map.ofEntries(
        Map.entry("0014", ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF),
        Map.entry("0046", ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_NO_KDF),
        Map.entry("0078", ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF),
        Map.entry("0114", ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256),
        Map.entry("0146", ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256),
        Map.entry("0178", ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256),
        Map.entry("0214", ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256),
        Map.entry("0346", ESDKAlgorithmSuiteId.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384),
        Map.entry("0378", ESDKAlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384),
        Map.entry("0478", ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY),
        Map.entry("0578", ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384));

    static List<EndpointPair> pairs() {
        return LanguageServerRegistry.shared().pairs();
    }

    @TestFactory
    List<DynamicTest> manifestRoundTrips() throws Exception {
        JsonNode keys = load("/vectors/keys.json").get("keys");
        JsonNode manifest = load("/vectors/encrypt-manifest.json");
        Map<String, Integer> plaintexts = new LinkedHashMap<>();
        manifest.get("plaintexts").fields()
            .forEachRemaining(e -> plaintexts.put(e.getKey(), e.getValue().asInt()));

        List<DynamicTest> tests = new ArrayList<>();
        for (Iterator<Map.Entry<String, JsonNode>> it = manifest.get("tests").fields(); it.hasNext(); ) {
            Map.Entry<String, JsonNode> entry = it.next();
            JsonNode scenario = entry.getValue().get("encryption-scenario");
            String label = entry.getKey()
                + (scenario == null ? "" : " (" + text(scenario, "description") + ")");

            String skip = skipReason(scenario, keys);
            if (skip != null) {
                // Surface every unmapped vector as an explicit skipped test (never silently
                // dropped), so the report shows exactly which vectors are not yet covered
                // and why.
                tests.add(dynamicTest("skipped: " + label, () -> Assumptions.abort(skip)));
                continue;
            }

            ESDKAlgorithmSuiteId suite = HEX_TO_SUITE.get(text(scenario, "algorithmSuiteId"));
            boolean committing = "0478".equals(text(scenario, "algorithmSuiteId"))
                || "0578".equals(text(scenario, "algorithmSuiteId"));
            long frame = scenario.path("frame-size").asLong();
            Map<String, String> ec = toStringMap(scenario.get("encryption-context"));
            byte[] plaintext = deterministicPlaintext(
                plaintexts.getOrDefault(text(scenario, "plaintext"), 32));
            ESDKClientConfig encConfig = configFor(
                cmmFor(scenario.get("encryptKeyDescription"), keys), committing);
            ESDKClientConfig decConfig = configFor(
                cmmFor(scenario.get("decryptKeyDescription"), keys), committing);
            Map<String, String> reproducedEc =
                toStringMap(scenario.get("reproduced-encryption-context"));

            for (EndpointPair pair : pairs()) {
                tests.add(dynamicTest(label + " " + pair, () -> {
                    byte[] ciphertext = EsdkOps.encrypt(
                        pair.encryptEndpoint(), encConfig, plaintext, ec, suite, frame);
                    byte[] recovered =
                        EsdkOps.decrypt(pair.decryptEndpoint(), decConfig, ciphertext, reproducedEc);
                    assertArrayEquals(plaintext, recovered,
                        "manifest vector " + label + " must round-trip (" + pair + ")");
                }));
            }
        }
        return tests;
    }

    /**
     * @return {@code null} if the vector can be replayed as a round trip, otherwise a
     *     human-readable reason it is skipped (surfaced via {@link Assumptions#abort} so the
     *     test report shows it as a skipped test).
     */
    private static String skipReason(JsonNode scenario, JsonNode keys) {
        if (scenario == null) {
            return "no encryption-scenario";
        }
        if (!"positive-esdk".equals(text(scenario, "type"))) {
            return "non-positive scenario: " + text(scenario, "type");
        }
        if (!HEX_TO_SUITE.containsKey(text(scenario, "algorithmSuiteId"))) {
            return "unsupported algorithm suite: " + text(scenario, "algorithmSuiteId");
        }
        if (scenario.path("frame-size").asLong() <= 0) {
            return "non-framed message";
        }
        if (cmmFor(scenario.get("encryptKeyDescription"), keys) == null) {
            return "unsupported encrypt keyring: " + descLabel(scenario.get("encryptKeyDescription"));
        }
        if (cmmFor(scenario.get("decryptKeyDescription"), keys) == null) {
            return "unsupported decrypt keyring: " + descLabel(scenario.get("decryptKeyDescription"));
        }
        return null;
    }

    private static String descLabel(JsonNode desc) {
        if (desc == null) {
            return "none";
        }
        String algorithm = text(desc, "encryption-algorithm");
        return algorithm == null ? text(desc, "type") : text(desc, "type") + "/" + algorithm;
    }

    /** Build a keyring from a framework key description, or {@code null} if unsupported here. */
    private static Keyring keyringFor(JsonNode desc, JsonNode keys) {
        if (desc == null) {
            return null;
        }
        String type = text(desc, "type");
        if ("raw".equals(type)) {
            return rawKeyringFor(desc, keys);
        }
        if ("aws-kms".equals(type)) {
            String arn = kmsArn(desc, keys);
            return arn == null ? null
                : Keyring.builder().awsKms(AwsKmsKeyringConfig.builder().kmsKeyId(arn).build()).build();
        }
        if ("aws-kms-mrk-aware".equals(type)) {
            String arn = kmsArn(desc, keys);
            return arn == null ? null
                : Keyring.builder().awsKmsMrk(AwsKmsMrkKeyringConfig.builder().kmsKeyId(arn).build()).build();
        }
        if ("aws-kms-rsa".equals(type)) {
            return kmsRsaKeyringFor(desc, keys);
        }
        if ("multi-keyring".equals(type)) {
            return multiKeyringFor(desc, keys);
        }
        if ("aws-kms-hierarchy".equals(type)) {
            // The manifest names a branch key from the vector authors' key store; for a round
            // trip we encrypt and decrypt against our own runtime key store instead, so the suite
            // and encryption context are exercised without needing that specific branch key.
            HierarchicalRuntimeConfig runtime = HierarchicalRuntimeConfig.fromRuntime();
            return Keyring.builder()
                .awsKmsHierarchical(AwsKmsHierarchicalKeyringConfig.builder()
                    .branchKeyId(runtime.branchKeyId())
                    .keyStoreTableName(runtime.keyStoreTableName())
                    .logicalKeyStoreName(runtime.logicalKeyStoreName())
                    .kmsKeyArn(runtime.kmsKeyArn())
                    .ttlSeconds(runtime.ttlSeconds())
                    .build())
                .build();
        }
        return null;
    }

    private static Keyring rawKeyringFor(JsonNode desc, JsonNode keys) {
        JsonNode key = keys.get(text(desc, "key"));
        if (key == null) {
            return null;
        }
        String namespace = text(desc, "provider-id");
        String name = text(key, "key-id");
        String algorithm = text(desc, "encryption-algorithm");
        if ("aes".equals(algorithm)) {
            AesWrappingAlg wrappingAlg = switch (key.path("bits").asInt()) {
                case 128 -> AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16;
                case 192 -> AesWrappingAlg.ALG_AES192_GCM_IV12_TAG16;
                case 256 -> AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
                default -> null;
            };
            if (wrappingAlg == null) {
                return null;
            }
            byte[] material = Base64.getDecoder().decode(text(key, "material"));
            return Keyring.builder()
                .rawAes(RawAesKeyringConfig.builder()
                    .keyNamespace(namespace)
                    .keyName(name)
                    .wrappingKey(ByteBuffer.wrap(material))
                    .wrappingAlg(wrappingAlg)
                    .build())
                .build();
        }
        if ("rsa".equals(algorithm)) {
            PaddingScheme padding = paddingFor(text(desc, "padding-algorithm"), text(desc, "padding-hash"));
            if (padding == null) {
                return null;
            }
            ByteBuffer pem = ByteBuffer.wrap(text(key, "material").getBytes(StandardCharsets.UTF_8));
            var rsa = RawRsaKeyringConfig.builder()
                .keyNamespace(namespace)
                .keyName(name)
                .paddingScheme(padding);
            if ("public".equals(text(key, "type"))) {
                rsa.publicKey(pem);
            } else {
                rsa.privateKey(pem);
            }
            return Keyring.builder().rawRsa(rsa.build()).build();
        }
        return null;
    }

    /** The KMS ARN a KMS key description names, resolved through keys.json, or {@code null}. */
    private static String kmsArn(JsonNode desc, JsonNode keys) {
        JsonNode key = keys.get(text(desc, "key"));
        return key == null ? null : text(key, "key-id");
    }

    private static Keyring kmsRsaKeyringFor(JsonNode desc, JsonNode keys) {
        JsonNode key = keys.get(text(desc, "key"));
        if (key == null) {
            return null;
        }
        var rsa = AwsKmsRsaKeyringConfig.builder().kmsKeyId(text(key, "key-id"));
        String encryptionAlgorithm = text(desc, "encryption-algorithm");
        if (encryptionAlgorithm != null) {
            KmsRsaEncryptionAlgorithm algorithm = switch (encryptionAlgorithm) {
                case "RSAES_OAEP_SHA_1" -> KmsRsaEncryptionAlgorithm.RSAES_OAEP_SHA_1;
                case "RSAES_OAEP_SHA_256" -> KmsRsaEncryptionAlgorithm.RSAES_OAEP_SHA_256;
                default -> null;
            };
            if (algorithm == null) {
                return null;
            }
            rsa.encryptionAlgorithm(algorithm);
        }
        String material = text(key, "material");
        if (material != null) {
            rsa.publicKey(ByteBuffer.wrap(material.getBytes(StandardCharsets.UTF_8)));
        }
        return Keyring.builder().awsKmsRsa(rsa.build()).build();
    }

    private static Keyring multiKeyringFor(JsonNode desc, JsonNode keys) {
        var multi = MultiKeyringConfig.builder();
        JsonNode generator = desc.get("generator");
        if (generator != null && !generator.isNull()) {
            Keyring built = keyringFor(generator, keys);
            if (built == null) {
                return null;
            }
            multi.generator(built);
        }
        List<Keyring> children = new ArrayList<>();
        JsonNode childKeyrings = desc.get("childKeyrings");
        if (childKeyrings != null) {
            for (JsonNode child : childKeyrings) {
                Keyring built = keyringFor(child, keys);
                if (built == null) {
                    return null;
                }
                children.add(built);
            }
        }
        return Keyring.builder().multi(multi.childKeyrings(children).build()).build();
    }

    private static PaddingScheme paddingFor(String algorithm, String hash) {
        if ("pkcs1".equals(algorithm)) {
            return PaddingScheme.PKCS1;
        }
        if ("oaep-mgf1".equals(algorithm)) {
            return switch (hash == null ? "" : hash) {
                case "sha1" -> PaddingScheme.OAEP_SHA1_MGF1;
                case "sha256" -> PaddingScheme.OAEP_SHA256_MGF1;
                case "sha384" -> PaddingScheme.OAEP_SHA384_MGF1;
                case "sha512" -> PaddingScheme.OAEP_SHA512_MGF1;
                default -> null;
            };
        }
        return null;
    }

    /**
     * The materials manager for a key/CMM description, or {@code null} if unsupported here. Most
     * descriptions are a keyring wrapped in a Default CMM; a {@code required-encryption-context-cmm}
     * description wraps its underlying keyring in a Required-Encryption-Context CMM.
     */
    private static CryptographicMaterialsManager cmmFor(JsonNode desc, JsonNode keys) {
        if (desc == null) {
            return null;
        }
        if ("required-encryption-context-cmm".equals(text(desc, "type"))) {
            Keyring underlying = keyringFor(desc.get("underlying"), keys);
            if (underlying == null) {
                return null;
            }
            List<String> requiredKeys = new ArrayList<>();
            JsonNode requiredKeysNode = desc.get("requiredEncryptionContextKeys");
            if (requiredKeysNode != null) {
                for (JsonNode key : requiredKeysNode) {
                    requiredKeys.add(key.asText());
                }
            }
            return CryptographicMaterialsManager.builder()
                .requiredEncryptionContext(RequiredEncryptionContextCmmConfig.builder()
                    .underlyingCMM(defaultCmm(underlying))
                    .requiredEncryptionContextKeys(requiredKeys)
                    .build())
                .build();
        }
        Keyring keyring = keyringFor(desc, keys);
        return keyring == null ? null : defaultCmm(keyring);
    }

    private static CryptographicMaterialsManager defaultCmm(Keyring keyring) {
        return CryptographicMaterialsManager.builder()
            .defaultMember(DefaultCmmConfig.builder().keyring(keyring).build())
            .build();
    }

    private static ESDKClientConfig configFor(CryptographicMaterialsManager cmm, boolean committing) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(committing
                ? ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
                : ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
            .cmm(cmm)
            .build();
    }

    private static byte[] deterministicPlaintext(int size) {
        byte[] plaintext = new byte[size];
        for (int i = 0; i < size; i++) {
            plaintext[i] = (byte) i;
        }
        return plaintext;
    }

    private static Map<String, String> toStringMap(JsonNode node) {
        Map<String, String> map = new LinkedHashMap<>();
        if (node != null) {
            node.fields().forEachRemaining(e -> map.put(e.getKey(), e.getValue().asText()));
        }
        return map;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null ? null : value.asText();
    }

    private static JsonNode load(String resource) throws Exception {
        try (InputStream in = TestVectorManifestTests.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("missing test-vector resource: " + resource);
            }
            return MAPPER.readTree(in);
        }
    }
}
