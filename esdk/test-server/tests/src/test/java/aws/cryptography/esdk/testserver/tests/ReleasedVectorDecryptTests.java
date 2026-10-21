package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.testserver.tests.FeatureDeclarations;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.LanguageServerTarget;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import aws.cryptography.esdk.testserver.client.model.CryptographicMaterialsManager;
import aws.cryptography.esdk.testserver.client.model.DefaultCmmConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
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
 * CI also adds the decrypt corpora the ESDK Daily CI writes through today's Java and Python
 * MasterKeyProvider APIs, so every runtime reads current MKP output too.
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
 *   <li>positive vectors must decrypt to their plaintext; negative vectors (bit flips,
 *       truncations) must be rejected with a modeled error. A negative vector that names a
 *       {@code decryption-method} the model does not carry ({@code streaming-unsigned-only}) is
 *       skipped;</li>
 *   <li>offline vectors only by default (every master key is a raw keyring); KMS-backed vectors
 *       need cross-account key access and are enabled with
 *       {@code -Desdk.testserver.releasedVectors.includeKms=true};</li>
 *   <li>every vector by default; {@code -Desdk.testserver.releasedVectors.limitPerManifest=N}
 *       caps each manifest at the first N vectors the target supports.</li>
 * </ul>
 * A vector whose master keys do not map to a modeled keyring is skipped. Feature-gated on the
 * keyrings each vector uses. A positive vector with several master keys runs on a server without
 * the multi-keyring under the last master key that server supports.
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

        int cap = intProperty("esdk.testserver.releasedVectors.limitPerManifest", 0);
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

            List<Map.Entry<String, Selection>> selections = new ArrayList<>();
            int unmodeledMethod = 0;
            for (Iterator<Map.Entry<String, JsonNode>> it = manifest.get("tests").fields();
                    it.hasNext(); ) {
                Map.Entry<String, JsonNode> entry = it.next();
                if (entry.getValue().has("decryption-method")) {
                    unmodeledMethod++;
                    continue;
                }
                Selection selection = select(entry.getValue(), version, keys, includeKms);
                if (selection != null) {
                    selections.add(Map.entry(entry.getKey(), selection));
                }
            }
            if (unmodeledMethod > 0) {
                String reason = unmodeledMethod + " " + corpusName
                    + " vectors use a decryption-method the model does not carry";
                tests.add(dynamicTest("skipped: " + reason, () -> Assumptions.abort(reason)));
            }

            // The cap counts only vectors a target can run, so vectors it would skip
            // (e.g. raw-RSA on a server without it) do not use up its budget.
            for (LanguageServerTarget target : targets) {
                int emitted = 0;
                int unsupported = 0;
                for (Map.Entry<String, Selection> chosen : selections) {
                    Selection selection = chosen.getValue();
                    Keyring keyring = keyringOn(selection, target);
                    if (keyring == null) {
                        unsupported++;
                        continue;
                    }
                    if (cap > 0 && emitted >= cap) {
                        break;
                    }
                    emitted++;
                    String label = corpusName + "/" + chosen.getKey();
                    Path ciphertextPath = corpus.resolve(selection.ciphertextRef);
                    ESDKClientConfig config = decryptConfig(keyring);
                    if (selection.plaintextRef == null) {
                        tests.add(dynamicTest(label + " " + target, () -> {
                            byte[] ciphertext = Files.readAllBytes(ciphertextPath);
                            assertThrows(ESDKClientError.class,
                                () -> EsdkOps.decrypt(target.endpoint(), config, ciphertext),
                                "negative released vector " + label + " must be rejected ("
                                    + target + ")");
                        }));
                        continue;
                    }
                    Path plaintextPath = corpus.resolve(selection.plaintextRef);
                    tests.add(dynamicTest(label + " " + target, () -> {
                        byte[] ciphertext = Files.readAllBytes(ciphertextPath);
                        byte[] expected = Files.readAllBytes(plaintextPath);
                        byte[] recovered = EsdkOps.decrypt(target.endpoint(), config, ciphertext);
                        assertArrayEquals(expected, recovered,
                            "released vector " + label + " must decrypt to its known plaintext ("
                                + target + ")");
                    }));
                }
                if (unsupported > 0) {
                    String reason = unsupported + " " + corpusName + " vectors use keyrings or raw-RSA"
                        + " paddings " + target + " does not support";
                    tests.add(dynamicTest("skipped: " + reason,
                        () -> Assumptions.abort(reason)));
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

    private static ESDKClientConfig decryptConfig(Keyring keyring) {
        return ESDKClientConfig.builder()
            .commitmentPolicy(DECRYPT_POLICY)
            .cmm(CryptographicMaterialsManager.builder()
                .defaultMember(DefaultCmmConfig.builder().keyring(keyring).build())
                .build())
            .build();
    }

    /**
     * The keyring {@code target} decrypts a vector with, or {@code null} if it supports none: every
     * master key (as a multi-keyring when there are several) when the target supports all of them,
     * otherwise, for a positive vector, the last single master key it supports.
     */
    private static Keyring keyringOn(Selection selection, LanguageServerTarget target) {
        List<MasterKey> masterKeys = selection.masterKeys;
        boolean all = masterKeys.stream().allMatch(key -> supports(target, key))
            && (masterKeys.size() == 1 || supports(target, "multi"));
        if (all) {
            if (masterKeys.size() == 1) {
                return masterKeys.get(0).keyring;
            }
            List<Keyring> children = masterKeys.stream().map(MasterKey::keyring).toList();
            return Keyring.builder()
                .multi(MultiKeyringConfig.builder().childKeyrings(children).build()).build();
        }
        if (selection.plaintextRef == null) {
            return null;
        }
        for (int i = masterKeys.size() - 1; i >= 0; i--) {
            if (supports(target, masterKeys.get(i))) {
                return masterKeys.get(i).keyring;
            }
        }
        return null;
    }

    private static boolean supports(LanguageServerTarget target, MasterKey key) {
        return supports(target, key.feature)
            && (key.rsaPadding == null || !UNSUPPORTED_RSA_PADDINGS
                .getOrDefault(target.language(), Set.of()).contains(key.rsaPadding));
    }

    private static boolean supports(LanguageServerTarget target, String feature) {
        return FeatureDeclarations.shared().isSupported(
            target.language(), target.majorVersion(), target.repo(), feature);
    }

    /** A master key's keyring, the Feature it needs, and its raw-RSA padding label (or null). */
    private record MasterKey(Keyring keyring, String feature, String rsaPadding) {
    }

    /** A vector chosen for replay; {@code plaintextRef} is {@code null} for a negative vector. */
    private record Selection(List<MasterKey> masterKeys, String ciphertextRef, String plaintextRef) {
    }

    /**
     * Decide whether a manifest test is replayable under the current switches and, if so, resolve
     * its master keys and file references; {@code null} means skip it.
     */
    private static Selection select(JsonNode test, int version, JsonNode keys, boolean includeKms) {
        String plaintextRef;
        if (version <= 1) {
            plaintextRef = fileRef(test.get("plaintext"));  // v1: positive only, plaintext inline
            if (plaintextRef == null) {
                return null;
            }
        } else {
            JsonNode result = test.get("result");
            if (result != null && result.has("output")) {
                plaintextRef = fileRef(result.get("output").get("plaintext"));
                if (plaintextRef == null) {
                    return null;
                }
            } else if (result != null && result.has("error")) {
                plaintextRef = null;
            } else {
                return null;
            }
        }
        String ciphertextRef = fileRef(test.get("ciphertext"));
        if (ciphertextRef == null) {
            return null;
        }

        JsonNode masterKeysNode = test.get("master-keys");
        if (masterKeysNode == null || masterKeysNode.isEmpty()) {
            return null;
        }
        List<MasterKey> masterKeys = new ArrayList<>();
        for (JsonNode masterKey : masterKeysNode) {
            if (!includeKms && !"raw".equals(masterKey.path("type").asText())) {
                return null;
            }
            Keyring keyring = TestVectorManifestTests.keyringFor(masterKey, keys);
            if (keyring == null) {
                return null;
            }
            masterKeys.add(new MasterKey(keyring, featureFor(masterKey), rsaPaddingLabel(masterKey)));
        }
        return new Selection(masterKeys, ciphertextRef, plaintextRef);
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
