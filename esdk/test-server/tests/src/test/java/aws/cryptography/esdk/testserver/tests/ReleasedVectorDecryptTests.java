package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureGate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKCommitmentPolicy;
import aws.cryptography.esdk.testserver.client.model.Keyring;
import aws.cryptography.esdk.testserver.client.model.MultiKeyringConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Decrypts the released {@code awses-decrypt} known-answer corpora from
 * {@code awslabs/aws-encryption-sdk-test-vectors} across every Language_Server. These vectors
 * were produced by shipped ESDK releases (the {@code python-1.3.x}/{@code 2.x} lines, written
 * through the legacy MasterKeyProvider interface), so decrypting them is the external oracle
 * that a self-referential cross-language round trip cannot be: it proves each runtime reads what
 * a real released implementation wrote, not merely what the other servers in this run wrote.
 *
 * <p>One provisioning, many decryptors: the corpora are downloaded and extracted once (a CI
 * step, or a local checkout) into a directory named by {@code ESDK_TESTSERVER_DECRYPT_VECTORS_DIR}
 * or {@code -Desdk.testserver.releasedVectors.dir}; each corpus subdirectory holds a
 * {@code manifest.json} (awses-decrypt v2) or {@code decrypt_message.json} (v1), a
 * {@code keys.json}, and {@code ciphertexts/}+{@code plaintexts/}. Every discovered vector is
 * decrypted on each target. When the directory is unset the whole factory is a single visible
 * skip.
 *
 * <p>Selection (the corpora are ~25k vectors; the RPC matrix cannot run every one on every
 * language):
 * <ul>
 *   <li>positive vectors only: a negative vector's rejection is keyed on a decryption-method the
 *       model does not carry, so it is skipped rather than mis-asserted;</li>
 *   <li>offline vectors only by default (every master key is a raw keyring); KMS-backed vectors
 *       need cross-account key access and are enabled with
 *       {@code -Desdk.testserver.releasedVectors.includeKms=true};</li>
 *   <li>capped per manifest ({@code -Desdk.testserver.releasedVectors.limitPerManifest}, default
 *       200, {@code 0} for the full corpus).</li>
 * </ul>
 * A vector whose master keys do not map to a modeled keyring is skipped. Feature-gated on the
 * keyrings each vector uses.
 */
class ReleasedVectorDecryptTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DIR_PROPERTY = "esdk.testserver.releasedVectors.dir";
    private static final String DIR_ENV = "ESDK_TESTSERVER_DECRYPT_VECTORS_DIR";

    // Released messages predate key commitment; ALLOW_DECRYPT reads committing and
    // non-committing messages alike, and this suite never encrypts.
    private static final ESDKCommitmentPolicy DECRYPT_POLICY =
        ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;

    // Released vectors span every raw-RSA padding; the AWS Encryption SDK for C supports only
    // PKCS1 and OAEP-SHA1/SHA256, so its rows for the wider OAEP hashes are visibly skipped
    // rather than counted as failures.
    private static final Map<String, Set<String>> UNSUPPORTED_RSA_PADDINGS = Map.of(
        "c", Set.of("oaep-mgf1:sha384", "oaep-mgf1:sha512"));

    @TestFactory
    List<DynamicTest> releasedVectorsDecrypt() throws Exception {
        Path root = resolveRoot();
        if (root == null) {
            return List.of(dynamicTest("skipped: released decrypt vectors not provisioned",
                () -> Assumptions.abort("set " + DIR_ENV + " or -D" + DIR_PROPERTY
                    + " to a directory of extracted awses-decrypt corpora")));
        }

        int cap = intProperty("esdk.testserver.releasedVectors.limitPerManifest", 200);
        boolean includeKms = boolProperty("esdk.testserver.releasedVectors.includeKms");
        List<LanguageServerTarget> targets = LanguageServerRegistry.shared().targets();

        List<DynamicTest> tests = new ArrayList<>();
        for (Path corpus : corpusDirs(root)) {
            Path manifestPath = manifestFile(corpus);
            if (manifestPath == null) {
                continue;
            }
            JsonNode manifest = MAPPER.readTree(manifestPath.toFile());
            int version = manifest.path("manifest").path("version").asInt();
            JsonNode keys = normalizeKeys(MAPPER.readTree(corpus.resolve("keys.json").toFile()).get("keys"));
            String corpusName = corpus.getFileName().toString();

            int emitted = 0;
            for (Iterator<Map.Entry<String, JsonNode>> it = manifest.get("tests").fields();
                    it.hasNext(); ) {
                if (cap > 0 && emitted >= cap) {
                    break;
                }
                Map.Entry<String, JsonNode> entry = it.next();
                JsonNode test = entry.getValue();
                Selection selection = select(test, version, keys, includeKms);
                if (selection == null) {
                    continue;
                }
                emitted++;

                ESDKClientConfig config = ESDKClientConfig.builder()
                    .commitmentPolicy(DECRYPT_POLICY)
                    .cmm(CryptographicMaterialsManager.builder()
                        .defaultMember(DefaultCmmConfig.builder().keyring(selection.keyring).build())
                        .build())
                    .build();
                Path ciphertextPath = corpus.resolve(selection.ciphertextRef);
                Path plaintextPath = corpus.resolve(selection.plaintextRef);
                String label = corpusName + "/" + entry.getKey();

                for (LanguageServerTarget target : targets) {
                    tests.add(dynamicTest(label + " " + target, () -> {
                        FeatureGate.require(selection.features, new TargetPair(target, target));
                        Set<String> unsupported =
                            UNSUPPORTED_RSA_PADDINGS.getOrDefault(target.language(), Set.of());
                        for (String padding : selection.rsaPaddings) {
                            if (unsupported.contains(padding)) {
                                Assumptions.abort(target.language() + " does not support raw-RSA "
                                    + padding + " (" + label + ")");
                            }
                        }
                        byte[] ciphertext = Files.readAllBytes(ciphertextPath);
                        byte[] expected = Files.readAllBytes(plaintextPath);
                        byte[] recovered = EsdkOps.decrypt(target.endpoint(), config, ciphertext);
                        assertArrayEquals(expected, recovered,
                            "released vector " + label + " must decrypt to its known plaintext ("
                                + target + ")");
                    }));
                }
            }
        }

        if (tests.isEmpty()) {
            return List.of(dynamicTest("skipped: no selectable released vectors under " + root,
                () -> Assumptions.abort("no positive, offline, mappable vectors found; adjust "
                    + "includeKms or limitPerManifest")));
        }
        return tests;
    }

    /** A vector chosen for replay: its keyring, the required Features, and its file refs. */
    private record Selection(Keyring keyring, Set<String> features, Set<String> rsaPaddings,
                             String ciphertextRef, String plaintextRef) {
    }

    /**
     * Decide whether a manifest test is replayable under the current switches and, if so, resolve
     * its keyring, features and file references; {@code null} means skip it.
     */
    private static Selection select(JsonNode test, int version, JsonNode keys, boolean includeKms) {
        String plaintextRef;
        if (version <= 1) {
            plaintextRef = fileRef(test.get("plaintext"));  // v1: positive only, plaintext inline
        } else {
            JsonNode result = test.get("result");
            if (result == null || !result.has("output")) {
                return null;  // negative vector: its rejection is keyed on decryption-method, not modeled here
            }
            plaintextRef = fileRef(result.get("output").get("plaintext"));
        }
        String ciphertextRef = fileRef(test.get("ciphertext"));
        if (plaintextRef == null || ciphertextRef == null) {
            return null;
        }

        JsonNode masterKeys = test.get("master-keys");
        if (masterKeys == null || masterKeys.isEmpty()) {
            return null;
        }
        Set<String> features = new LinkedHashSet<>();
        Set<String> rsaPaddings = new LinkedHashSet<>();
        List<Keyring> keyrings = new ArrayList<>();
        for (JsonNode masterKey : masterKeys) {
            if (!includeKms && !"raw".equals(masterKey.path("type").asText())) {
                return null;
            }
            Keyring keyring = TestVectorManifestTests.keyringFor(masterKey, keys);
            if (keyring == null) {
                return null;
            }
            keyrings.add(keyring);
            features.add(featureFor(masterKey));
            String padding = rsaPaddingLabel(masterKey);
            if (padding != null) {
                rsaPaddings.add(padding);
            }
        }

        Keyring keyring = keyrings.size() == 1
            ? keyrings.get(0)
            : Keyring.builder().multi(MultiKeyringConfig.builder().childKeyrings(keyrings).build()).build();
        return new Selection(keyring, features, rsaPaddings, ciphertextRef, plaintextRef);
    }

    /** The {@code algorithm:hash} label for a raw-RSA master key, or {@code null} if not raw-RSA. */
    private static String rsaPaddingLabel(JsonNode masterKey) {
        if (!"raw".equals(masterKey.path("type").asText())
                || !"rsa".equals(masterKey.path("encryption-algorithm").asText())) {
            return null;
        }
        return masterKey.path("padding-algorithm").asText() + ":" + masterKey.path("padding-hash").asText();
    }

    /** The Feature a master-key description depends on. */
    private static String featureFor(JsonNode masterKey) {
        String type = masterKey.path("type").asText();
        return switch (type) {
            case "raw" -> "rsa".equals(masterKey.path("encryption-algorithm").asText())
                ? "raw-rsa" : "raw-aes";
            case "aws-kms" -> "aws-kms";
            case "aws-kms-mrk-aware" -> "aws-kms-mrk";
            case "aws-kms-mrk-aware-discovery" -> "aws-kms-mrk-discovery";
            default -> type;
        };
    }

    /** Turn a {@code file://plaintexts/small} reference into the relative path {@code plaintexts/small}. */
    private static String fileRef(JsonNode node) {
        if (node == null) {
            return null;
        }
        String value = node.asText();
        return value.startsWith("file://") ? value.substring("file://".length()) : value;
    }

    /**
     * Normalize a corpus {@code keys.json} to the modern schema: the older corpora omit
     * {@code key-id} (the id is the map key name) and store {@code material} as an array of lines
     * joined by {@code line-separator}. {@link TestVectorManifestTests#keyringFor} reads a single
     * {@code key-id} and a single {@code material} string, so fill both in here.
     */
    private static JsonNode normalizeKeys(JsonNode keysNode) {
        ObjectNode out = MAPPER.createObjectNode();
        keysNode.fields().forEachRemaining(entry -> {
            ObjectNode key = entry.getValue().deepCopy();
            if (!key.has("key-id")) {
                key.put("key-id", entry.getKey());
            }
            JsonNode material = key.get("material");
            if (material != null && material.isArray()) {
                String separator = key.path("line-separator").asText("");
                StringBuilder joined = new StringBuilder();
                for (int i = 0; i < material.size(); i++) {
                    if (i > 0) {
                        joined.append(separator);
                    }
                    joined.append(material.get(i).asText());
                }
                key.put("material", joined.toString());
            }
            out.set(entry.getKey(), key);
        });
        return out;
    }

    private static Path resolveRoot() {
        String configured = System.getProperty(DIR_PROPERTY, System.getenv(DIR_ENV));
        if (configured == null || configured.isBlank()) {
            return null;
        }
        Path root = Path.of(configured);
        return Files.isDirectory(root) ? root : null;
    }

    /** Every immediate subdirectory of {@code root} that holds a decrypt manifest, name-sorted. */
    private static List<Path> corpusDirs(Path root) throws Exception {
        try (Stream<Path> entries = Files.list(root)) {
            return entries
                .filter(Files::isDirectory)
                .filter(dir -> manifestFile(dir) != null)
                .sorted()
                .collect(Collectors.toList());
        }
    }

    private static Path manifestFile(Path corpus) {
        for (String name : new String[] {"manifest.json", "decrypt_message.json"}) {
            Path candidate = corpus.resolve(name);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static int intProperty(String key, int fallback) {
        try {
            return Integer.parseInt(System.getProperty(key, Integer.toString(fallback)).trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static boolean boolProperty(String key) {
        return "true".equals(System.getProperty(key, "false").trim().toLowerCase(Locale.ROOT));
    }
}
