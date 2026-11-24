package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CreateAwsKmsKeyringInput;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.InitializeDecryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.InitializeEncryptionMaterialsInput;
import aws.cryptography.mpl.testserver.client.model.KmsClientConfig;
import aws.cryptography.mpl.testserver.client.model.MPLClientError;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.KnownBugGate;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.nio.ByteBuffer;
import java.util.List;
import org.junit.jupiter.api.function.Executable;

/**
 * One language's MPL, as a {@link KeyringTest} sees it.
 *
 * <p>Each call goes over HTTP to that language's test server, which runs it on its MPL.
 * {@link MplTestServerClients#withRetry} sends a call again only when the connection dropped.
 * An error from the MPL is never retried.
 */
final class Mpl {

    private final LanguageServerTarget languageServer;
    private final MPLTestServerClient testServer;
    /** The test class's suite and encryption context, or null when it sets none. */
    private final KeyringTestDefaults defaults;

    /**
     * @throws org.opentest4j.TestAbortedException in a dry run, which stops the test here
     */
    Mpl(LanguageServerTarget languageServer, KeyringTestDefaults defaults) {
        this.languageServer = languageServer;
        this.testServer = MplTestServerClients.forEndpoint(languageServer.endpoint());
        this.defaults = defaults;
    }

    /** The language server, such as rust-v1, whose MPL runs the calls. */
    LanguageServerTarget languageServer() {
        return languageServer;
    }

    /** The test server client, for the {@link Keyring} calls. */
    MPLTestServerClient testServer() {
        return testServer;
    }

    /** Start building a Raw AES keyring. */
    RawAesKeyringBuilder rawAesKeyring() {
        return new RawAesKeyringBuilder();
    }

    /** Start building an AWS KMS keyring. */
    AwsKmsKeyringBuilder awsKmsKeyring() {
        return new AwsKmsKeyringBuilder();
    }

    /** New encryption materials with the test class's suite and encryption context, and no data key yet. */
    EncryptionMaterials newEncryptionMaterials() {
        return newEncryptionMaterials(requireDefaults().algorithmSuite());
    }

    /** New encryption materials with {@code suite}, the test class's encryption context, and no data key yet. */
    EncryptionMaterials newEncryptionMaterials(AlgorithmSuiteId suite) {
        EncryptionMaterials materials = MplTestServerClients.withRetry(() ->
            testServer.initializeEncryptionMaterials(InitializeEncryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(requireDefaults().encryptionContext())
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new encryption materials hold no data key");
        return materials;
    }

    /** New decryption materials with the test class's suite and encryption context, and no data key yet. */
    DecryptionMaterials newDecryptionMaterials() {
        return newDecryptionMaterials(requireDefaults().algorithmSuite());
    }

    /** New decryption materials with {@code suite}, the test class's encryption context, and no data key yet. */
    DecryptionMaterials newDecryptionMaterials(AlgorithmSuiteId suite) {
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            testServer.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(requireDefaults().encryptionContext())
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new decryption materials hold no data key");
        return materials;
    }

    /**
     * Run {@code assertion}, which a known bug in some language's MPL breaks.
     * When this language's bug-config.json lists {@code bugId}, a failing assertion skips the test.
     * A passing one then fails the test, because the bug-config.json entry is out of date.
     * For other languages, the assertion runs as usual.
     */
    void knownBug(String bugId, Executable assertion) {
        KnownBugGate.gateDeclared(bugId, languageServer, assertion);
    }

    private KeyringTestDefaults requireDefaults() {
        if (defaults == null) {
            throw new IllegalStateException(
                "new materials need a suite and encryption context: implement KeyringTestDefaults in the test class");
        }
        return defaults;
    }

    /** Run {@code create}, and check that the MPL rejects the keyring settings with {@code expected}. */
    private MPLClientError createFails(Executable create, ExpectedError expected) {
        MPLClientError error = assertThrows(MPLClientError.class, create);
        MplErrors.expectError(languageServer, error).matches(expected);
        return error;
    }

    /**
     * The settings of an AWS KMS keyring. {@link #create()} sends them to the MPL.
     * A setting that the test does not set reaches the MPL as missing.
     */
    final class AwsKmsKeyringBuilder {
        private final CreateAwsKmsKeyringInput.Builder input = CreateAwsKmsKeyringInput.builder();

        private AwsKmsKeyringBuilder() {
        }

        /** A key ARN, key ID, alias name or alias ARN. */
        AwsKmsKeyringBuilder kmsKeyId(String kmsKeyId) {
            input.kmsKeyId(kmsKeyId);
            return this;
        }

        /** How the test server builds the keyring's KMS client, such as {@link FakeKms#client()}. */
        AwsKmsKeyringBuilder kmsClient(KmsClientConfig kmsClient) {
            input.kmsClient(kmsClient);
            return this;
        }

        AwsKmsKeyringBuilder grantTokens(List<String> grantTokens) {
            input.grantTokens(grantTokens);
            return this;
        }

        /** Create the keyring, which must succeed. */
        Keyring create() {
            CreateAwsKmsKeyringInput request = input.build();
            return new Keyring(Mpl.this, MplTestServerClients.withRetry(() ->
                testServer.createAwsKmsKeyring(request)).getKeyringId());
        }

        /** Create the keyring, which must fail with {@code expected}. */
        MPLClientError createFails(ExpectedError expected) {
            CreateAwsKmsKeyringInput request = input.build();
            return Mpl.this.createFails(() -> MplTestServerClients.withRetry(() ->
                testServer.createAwsKmsKeyring(request)), expected);
        }
    }

    /** The settings of a Raw AES keyring. {@link #create()} sends them to the MPL. */
    final class RawAesKeyringBuilder {
        private final CreateRawAesKeyringInput.Builder input = CreateRawAesKeyringInput.builder();

        private RawAesKeyringBuilder() {
        }

        RawAesKeyringBuilder keyNamespace(String keyNamespace) {
            input.keyNamespace(keyNamespace);
            return this;
        }

        RawAesKeyringBuilder keyName(String keyName) {
            input.keyName(keyName);
            return this;
        }

        RawAesKeyringBuilder wrappingKey(byte[] wrappingKey) {
            input.wrappingKey(ByteBuffer.wrap(wrappingKey));
            return this;
        }

        RawAesKeyringBuilder wrappingAlg(AesWrappingAlg wrappingAlg) {
            input.wrappingAlg(wrappingAlg);
            return this;
        }

        /** Create the keyring, which must succeed. */
        Keyring create() {
            CreateRawAesKeyringInput request = input.build();
            return new Keyring(Mpl.this, MplTestServerClients.withRetry(() ->
                testServer.createRawAesKeyring(request)).getKeyringId());
        }

        /** Create the keyring, which must fail with {@code expected}. */
        MPLClientError createFails(ExpectedError expected) {
            CreateRawAesKeyringInput request = input.build();
            return Mpl.this.createFails(() -> MplTestServerClients.withRetry(() ->
                testServer.createRawAesKeyring(request)), expected);
        }
    }
}
