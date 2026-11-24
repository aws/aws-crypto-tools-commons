package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import java.util.Map;

/**
 * The algorithm suite and encryption context for a test class's new materials.
 *
 * <p>When a test class implements this, {@link Mpl#newEncryptionMaterials()} and {@link Mpl#newDecryptionMaterials()} use them.
 * So each test does not repeat them.
 */
interface KeyringTestDefaults {

    AlgorithmSuiteId algorithmSuite();

    Map<String, String> encryptionContext();
}
