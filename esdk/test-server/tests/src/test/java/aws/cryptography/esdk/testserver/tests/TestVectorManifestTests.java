package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureDeclarations;
import aws.cryptography.testserver.tests.FeatureGate;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.TargetPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import aws.cryptography.esdk.testserver.client.model.AesWrappingAlg;
import aws.cryptography.esdk.testserver.client.model.AwsKmsEcdhKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsHierarchicalKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsMrkDiscoveryKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsMrkKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.AwsKmsRsaKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.DiscoveryFilter;
import aws.cryptography.esdk.testserver.client.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.EcdhCurveSpec;
import aws.cryptography.esdk.testserver.client.model.EphemeralPrivateKeyToStaticPublicKeyConfig;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.KmsEcdhKeyAgreementScheme;
import aws.cryptography.esdk.testserver.client.model.KmsPrivateKeyToStaticPublicKeyConfig;
import aws.cryptography.esdk.testserver.client.model.KmsPublicKeyDiscoveryConfig;
import aws.cryptography.esdk.testserver.client.model.KmsRsaEncryptionAlgorithm;
import aws.cryptography.esdk.testserver.client.model.MultiKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.PaddingScheme;
import aws.cryptography.esdk.testserver.client.model.PublicKeyDiscoveryConfig;
import aws.cryptography.esdk.testserver.client.model.RawAesKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RawEcdhKeyAgreementScheme;
import aws.cryptography.esdk.testserver.client.model.RawEcdhKeyringConfig;
import aws.cryptography.esdk.testserver.client.model.RawPrivateKeyToStaticPublicKeyConfig;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.function.Predicate;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

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
 * modeled keyring or CMM (Raw-AES, Raw-RSA, AWS-KMS, KMS-MRK, KMS-MRK-discovery, KMS-RSA,
 * hierarchical, Raw-ECDH, KMS-ECDH, multi-keyring, and the Required-Encryption-Context
 * CMM) are emitted; any other vector is skipped and surfaced as a skipped test (see
 * {@link #manifestRoundTrips()}).
 *
 * <p>Each leg is gated on its own server. A decryptor without the multi-keyring or the
 * Required-Encryption-Context CMM still decrypts those vectors: with the multi-keyring's last
 * child it supports, or with the CMM's underlying keyring and the reproduced encryption
 * context ({@link #decryptDescFor}).
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

    static List<TargetPair> pairs() {
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
            JsonNode decryptDesc = scenario.get("decryptKeyDescription");
            Map<String, String> reproducedEc =
                toStringMap(scenario.get("reproduced-encryption-context"));
            // Each leg is gated on the Feature(s) and raw-RSA padding(s) its own keyring
            // uses, so a server that does not wire a keyring is skipped visibly rather than
            // driven into it (Requirements 9.1, 9.5).
            JsonNode encryptDesc = scenario.get("encryptKeyDescription");
            Set<String> encFeatures = featuresFor(encryptDesc);
            Set<String> encPaddings = paddingNames(encryptDesc);

            // One message per encryptor, decrypted by every decryptor, as the Daily CI does
            // with each writer's manifest.
            Map<LanguageServerTarget, FutureTask<byte[]>> ciphertexts = new ConcurrentHashMap<>();
            for (TargetPair pair : pairs()) {
                tests.add(dynamicTest(label + " " + pair, () -> {
                    FeatureGate.require(encFeatures, pair.encryptTarget());
                    FeatureGate.requireRawRsaPaddings(encPaddings, pair.encryptTarget());
                    JsonNode decDesc = decryptDescFor(decryptDesc, pair.decryptTarget());
                    FeatureGate.require(featuresFor(decDesc), pair.decryptTarget());
                    FeatureGate.requireRawRsaPaddings(paddingNames(decDesc), pair.decryptTarget());
                    ESDKClientConfig decConfig = configFor(cmmFor(decDesc, keys), committing);
                    byte[] ciphertext = once(ciphertexts, pair.encryptTarget(), () -> EsdkOps.encryptWithClient(
                        pair.encryptEndpoint(), EsdkOps.sharedClient(pair.encryptEndpoint(), encConfig),
                        plaintext, ec, suite, frame));
                    Executable roundTrip = () -> {
                        byte[] recovered;
                        try {
                            recovered = EsdkOps.decryptWithClient(pair.decryptEndpoint(),
                                EsdkOps.sharedClient(pair.decryptEndpoint(), decConfig), ciphertext,
                                reproducedEc);
                        } catch (ESDKClientError e) {
                            throw new AssertionError("decrypt failed: " + e.getMessage(), e);
                        }
                        assertArrayEquals(plaintext, recovered,
                            "manifest vector " + label + " must round-trip (" + pair
                                + ", decrypt keyring " + descLabel(decDesc) + ")");
                    };
                    if (isRequiredEc(decryptDesc) && !isRequiredEc(decDesc)) {
                        // The reproduced context carries the required keys the header omits.
                        KnownBugGate.gateDeclared(REPRODUCED_ONLY_EC_BUG, pair.decryptTarget(), roundTrip);
                    } else {
                        roundTrip.execute();
                    }
                }));
            }
        }
        return tests;
    }

    private static final String REPRODUCED_ONLY_EC_BUG =
        "default-cmm-ignores-reproduced-only-encryption-context";

    private static boolean isRequiredEc(JsonNode desc) {
        return "required-encryption-context-cmm".equals(text(desc, "type"));
    }

    /** Run {@code task} the first time {@code key} is asked for; later callers get its result. */
    private static byte[] once(Map<LanguageServerTarget, FutureTask<byte[]>> results,
                               LanguageServerTarget key, Callable<byte[]> task) throws Throwable {
        FutureTask<byte[]> result = results.computeIfAbsent(key, k -> new FutureTask<>(task));
        result.run();
        try {
            return result.get();
        } catch (ExecutionException e) {
            throw e.getCause();
        }
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

    /**
     * The Feature_Catalog Feature(s) a key/CMM description depends on, so the test
     * can gate on them ({@link FeatureGate#require}) and skip on a language that
     * declares any unsupported. Recurses into multi-keyring children and the
     * Required-Encryption-Context CMM's underlying keyring so a combination must
     * support every keyring the vector actually uses. Only maps the descriptions
     * {@link #keyringFor} builds; unmapped types never reach here (they are dropped
     * by {@link #skipReason} first).
     */
    private static Set<String> featuresFor(JsonNode desc) {
        Set<String> features = new LinkedHashSet<>();
        collectFeatures(desc, features);
        return features;
    }

    private static void collectFeatures(JsonNode desc, Set<String> into) {
        if (desc == null) {
            return;
        }
        String type = text(desc, "type");
        if (type == null) {
            return;
        }
        switch (type) {
            case "raw" -> {
                String algorithm = text(desc, "encryption-algorithm");
                if ("aes".equals(algorithm)) {
                    into.add("raw-aes");
                } else if ("rsa".equals(algorithm)) {
                    into.add("raw-rsa");
                }
            }
            case "aws-kms" -> into.add("aws-kms");
            case "aws-kms-mrk-aware" -> into.add("aws-kms-mrk");
            case "aws-kms-mrk-aware-discovery" -> into.add("aws-kms-mrk-discovery");
            case "aws-kms-rsa" -> into.add("aws-kms-rsa");
            case "aws-kms-hierarchy" -> into.add("hierarchical");
            case "raw-ecdh" -> into.add("raw-ecdh");
            case "aws-kms-ecdh" -> into.add("aws-kms-ecdh");
            case "multi-keyring" -> {
                into.add("multi");
                collectFeatures(desc.get("generator"), into);
                JsonNode children = desc.get("childKeyrings");
                if (children != null) {
                    children.forEach(child -> collectFeatures(child, into));
                }
            }
            case "required-encryption-context-cmm" -> {
                into.add("required-encryption-context");
                collectFeatures(desc.get("underlying"), into);
            }
            default -> {
                // Unmapped types are dropped by skipReason before the gate runs.
            }
        }
    }

    /**
     * The decrypt description {@code target} runs for a vector: the manifest's own when the
     * target supports every Feature it uses, otherwise the narrowest description that decrypts
     * the same message on that target. A multi-keyring narrows to its last child the target
     * supports (so the decryptor walks past EDKs it cannot unwrap); a Required-Encryption-Context
     * CMM narrows to its underlying keyring, which the Default CMM runs with the reproduced
     * encryption context. Returns the manifest's description unchanged when nothing narrower
     * applies, so the Feature gate reports the skip.
     */
    static JsonNode decryptDescFor(JsonNode desc, LanguageServerTarget target) {
        JsonNode narrowed = narrow(desc, feature -> FeatureDeclarations.shared().isSupported(
            target.language(), target.majorVersion(), target.repo(), feature));
        return narrowed == null ? desc : narrowed;
    }

    private static JsonNode narrow(JsonNode desc, Predicate<String> supported) {
        if (desc == null) {
            return null;
        }
        if (featuresFor(desc).stream().allMatch(supported)) {
            return desc;
        }
        String type = text(desc, "type");
        if ("multi-keyring".equals(type)) {
            List<JsonNode> children = new ArrayList<>();
            if (desc.hasNonNull("generator")) {
                children.add(desc.get("generator"));
            }
            JsonNode childKeyrings = desc.get("childKeyrings");
            if (childKeyrings != null) {
                childKeyrings.forEach(children::add);
            }
            for (int i = children.size() - 1; i >= 0; i--) {
                JsonNode child = narrow(children.get(i), supported);
                if (child != null) {
                    return child;
                }
            }
            return null;
        }
        if ("required-encryption-context-cmm".equals(type)) {
            return narrow(desc.get("underlying"), supported);
        }
        return null;
    }

    /** The raw-RSA padding scheme names a description uses, for {@link FeatureGate#requireRawRsaPaddings}. */
    private static Set<String> paddingNames(JsonNode desc) {
        Set<String> names = new LinkedHashSet<>();
        for (PaddingScheme scheme : paddingsFor(desc)) {
            names.add(scheme.getValue());
        }
        return names;
    }

    /**
     * The raw-RSA {@link PaddingScheme}(s) a key/CMM description uses, so the
     * test can gate on them ({@link FeatureGate#requireRawRsaPaddings}) and skip
     * on a language whose declared padding capability excludes any. Recurses
     * exactly like {@link #featuresFor}; descriptions with no raw-RSA keyring
     * yield an empty set. Only maps descriptions {@link #keyringFor} builds;
     * unmapped paddings never reach here (they are dropped by
     * {@link #skipReason} first).
     */
    private static Set<PaddingScheme> paddingsFor(JsonNode desc) {
        Set<PaddingScheme> paddings = new LinkedHashSet<>();
        collectPaddings(desc, paddings);
        return paddings;
    }

    private static void collectPaddings(JsonNode desc, Set<PaddingScheme> into) {
        if (desc == null) {
            return;
        }
        String type = text(desc, "type");
        if (type == null) {
            return;
        }
        switch (type) {
            case "raw" -> {
                if ("rsa".equals(text(desc, "encryption-algorithm"))) {
                    PaddingScheme padding =
                        paddingFor(text(desc, "padding-algorithm"), text(desc, "padding-hash"));
                    if (padding != null) {
                        into.add(padding);
                    }
                }
            }
            case "multi-keyring" -> {
                collectPaddings(desc.get("generator"), into);
                JsonNode children = desc.get("childKeyrings");
                if (children != null) {
                    children.forEach(child -> collectPaddings(child, into));
                }
            }
            case "required-encryption-context-cmm" -> collectPaddings(desc.get("underlying"), into);
            default -> {
                // No other description type carries a raw-RSA padding.
            }
        }
    }

    /** Build a keyring from a framework key description, or {@code null} if unsupported here. */
    static Keyring keyringFor(JsonNode desc, JsonNode keys) {
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
        if ("aws-kms-mrk-aware-discovery".equals(type)) {
            String region = text(desc, "default-mrk-region");
            if (region == null) {
                return null;
            }
            var builder = AwsKmsMrkDiscoveryKeyringConfig.builder().region(region);
            DiscoveryFilter filter = discoveryFilterFor(desc.get("aws-kms-discovery-filter"));
            if (filter != null) {
                builder.discoveryFilter(filter);
            }
            return Keyring.builder().awsKmsMrkDiscovery(builder.build()).build();
        }
        if ("aws-kms-rsa".equals(type)) {
            return kmsRsaKeyringFor(desc, keys);
        }
        if ("multi-keyring".equals(type)) {
            return multiKeyringFor(desc, keys);
        }
        if ("raw-ecdh".equals(type)) {
            return rawEcdhKeyringFor(desc, keys);
        }
        if ("aws-kms-ecdh".equals(type)) {
            return kmsEcdhKeyringFor(desc, keys);
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

    /** Map a manifest {@code aws-kms-discovery-filter} to a modeled DiscoveryFilter, or null. */
    private static DiscoveryFilter discoveryFilterFor(JsonNode filterNode) {
        if (filterNode == null) {
            return null;
        }
        List<String> accountIds = new ArrayList<>();
        JsonNode ids = filterNode.get("account-ids");
        if (ids != null) {
            for (JsonNode id : ids) {
                accountIds.add(id.asText());
            }
        }
        return DiscoveryFilter.builder()
            .partition(text(filterNode, "partition"))
            .accountIds(accountIds)
            .build();
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

    /** The manifest's {@code ecc-curve} names (raw and KMS key sets) to the modeled curve. */
    private static final Map<String, EcdhCurveSpec> ECC_CURVES = Map.of(
        "ecc-256", EcdhCurveSpec.ECC_NIST_P256,
        "ecc-384", EcdhCurveSpec.ECC_NIST_P384,
        "ecc-521", EcdhCurveSpec.ECC_NIST_P521,
        "us-west-2-256-ecc", EcdhCurveSpec.ECC_NIST_P256,
        "us-west-2-384-ecc", EcdhCurveSpec.ECC_NIST_P384,
        "us-west-2-521-ecc", EcdhCurveSpec.ECC_NIST_P521);

    /**
     * A Raw-ECDH keyring, built as the test-vector framework builds it: {@code static} from
     * the sender key's private and recipient-public material, {@code ephemeral} and
     * {@code discovery} from the recipient key's public and private material respectively.
     */
    private static Keyring rawEcdhKeyringFor(JsonNode desc, JsonNode keys) {
        EcdhCurveSpec curve = ECC_CURVES.get(text(desc, "ecc-curve"));
        String schema = text(desc, "schema");
        if (curve == null || schema == null) {
            return null;
        }
        RawEcdhKeyAgreementScheme scheme;
        switch (schema) {
            case "static" -> {
                JsonNode sender = keys.get(text(desc, "sender"));
                if (sender == null) {
                    return null;
                }
                scheme = RawEcdhKeyAgreementScheme.builder()
                    .rawPrivateKeyToStaticPublicKey(RawPrivateKeyToStaticPublicKeyConfig.builder()
                        .senderStaticPrivateKey(utf8(text(sender, "sender-material")))
                        .recipientPublicKey(base64(text(sender, "recipient-material-public-key")))
                        .build())
                    .build();
            }
            case "ephemeral" -> {
                JsonNode recipient = keys.get(text(desc, "recipient"));
                if (recipient == null) {
                    return null;
                }
                scheme = RawEcdhKeyAgreementScheme.builder()
                    .ephemeralPrivateKeyToStaticPublicKey(EphemeralPrivateKeyToStaticPublicKeyConfig.builder()
                        .recipientPublicKey(base64(text(recipient, "recipient-material-public-key")))
                        .build())
                    .build();
            }
            case "discovery" -> {
                JsonNode recipient = keys.get(text(desc, "recipient"));
                if (recipient == null) {
                    return null;
                }
                scheme = RawEcdhKeyAgreementScheme.builder()
                    .publicKeyDiscovery(PublicKeyDiscoveryConfig.builder()
                        .recipientStaticPrivateKey(utf8(text(recipient, "recipient-material")))
                        .build())
                    .build();
            }
            default -> {
                return null;
            }
        }
        return Keyring.builder()
            .rawEcdh(RawEcdhKeyringConfig.builder().keyAgreementScheme(scheme).curveSpec(curve).build())
            .build();
    }

    /**
     * A KMS-ECDH keyring, built as the test-vector framework builds it: {@code static} from
     * the sender key's KMS key and both public keys, {@code discovery} from the recipient
     * key's KMS key.
     */
    private static Keyring kmsEcdhKeyringFor(JsonNode desc, JsonNode keys) {
        EcdhCurveSpec curve = ECC_CURVES.get(text(desc, "ecc-curve"));
        String schema = text(desc, "schema");
        if (curve == null || schema == null) {
            return null;
        }
        KmsEcdhKeyAgreementScheme scheme;
        switch (schema) {
            case "static" -> {
                JsonNode sender = keys.get(text(desc, "sender"));
                if (sender == null) {
                    return null;
                }
                scheme = KmsEcdhKeyAgreementScheme.builder()
                    .kmsPrivateKeyToStaticPublicKey(KmsPrivateKeyToStaticPublicKeyConfig.builder()
                        .senderKmsIdentifier(text(sender, "sender-material"))
                        .senderPublicKey(base64(text(sender, "sender-material-public-key")))
                        .recipientPublicKey(base64(text(sender, "recipient-material-public-key")))
                        .build())
                    .build();
            }
            case "discovery" -> {
                JsonNode recipient = keys.get(text(desc, "recipient"));
                if (recipient == null) {
                    return null;
                }
                scheme = KmsEcdhKeyAgreementScheme.builder()
                    .kmsPublicKeyDiscovery(KmsPublicKeyDiscoveryConfig.builder()
                        .recipientKmsIdentifier(text(recipient, "recipient-material"))
                        .build())
                    .build();
            }
            default -> {
                return null;
            }
        }
        return Keyring.builder()
            .awsKmsEcdh(AwsKmsEcdhKeyringConfig.builder().keyAgreementScheme(scheme).curveSpec(curve).build())
            .build();
    }

    private static ByteBuffer utf8(String value) {
        return ByteBuffer.wrap(value.getBytes(StandardCharsets.UTF_8));
    }

    private static ByteBuffer base64(String value) {
        return ByteBuffer.wrap(Base64.getDecoder().decode(value));
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
