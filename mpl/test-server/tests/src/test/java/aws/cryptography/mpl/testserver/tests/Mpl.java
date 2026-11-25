package aws.cryptography.mpl.testserver.tests;

import static org.junit.jupiter.api.Assertions.assertNull;

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
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.nio.ByteBuffer;
import java.util.List;

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
    /** A failed {@link FailureCheck} that the test has not yet marked with a known bug, or null. */
    private FailureCheck unresolved;

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
        throwUnresolvedFailure();
        return testServer;
    }

    /** Start building a Raw AES keyring. */
    RawAesKeyringBuilder rawAesKeyring() {
        throwUnresolvedFailure();
        return new RawAesKeyringBuilder();
    }

    /** Start building an AWS KMS keyring. */
    AwsKmsKeyringBuilder awsKmsKeyring() {
        throwUnresolvedFailure();
        return new AwsKmsKeyringBuilder();
    }

    /**
     * Throw the failure of a {@link FailureCheck} that the test did not mark with
     * {@link FailureCheck#unlessKnownBug}.
     * Each MPL call runs this first, and so does the end of the test.
     */
    void throwUnresolvedFailure() {
        FailureCheck check = unresolved;
        unresolved = null;
        if (check != null) {
            check.throwIfFailed();
        }
    }

    /** Keep {@code check}, which failed, until the test marks it with a known bug or makes another MPL call. */
    void keepUnresolved(FailureCheck check) {
        unresolved = check;
    }

    /** The test has decided {@code check}, so its failure is no longer kept here. */
    void forgetUnresolved(FailureCheck check) {
        if (unresolved == check) {
            unresolved = null;
        }
    }

    /** New encryption materials with the test class's suite and encryption context, and no data key yet. */
    EncryptionMaterials newEncryptionMaterials() {
        return newEncryptionMaterials(requireDefaults().algorithmSuite());
    }

    /** New encryption materials with {@code suite}, the test class's encryption context, and no data key yet. */
    EncryptionMaterials newEncryptionMaterials(AlgorithmSuiteId suite) {
        throwUnresolvedFailure();
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
        throwUnresolvedFailure();
        DecryptionMaterials materials = MplTestServerClients.withRetry(() ->
            testServer.initializeDecryptionMaterials(InitializeDecryptionMaterialsInput.builder()
                .algorithmSuiteId(suite)
                .encryptionContext(requireDefaults().encryptionContext())
                .requiredEncryptionContextKeys(List.of())
                .build())).getMaterials();
        assertNull(materials.getPlaintextDataKey(), "new decryption materials hold no data key");
        return materials;
    }

    private KeyringTestDefaults requireDefaults() {
        if (defaults == null) {
            throw new IllegalStateException(
                "new materials need a suite and encryption context: implement KeyringTestDefaults in the test class");
        }
        return defaults;
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
                testServer().createAwsKmsKeyring(request)).getKeyringId());
        }

        /** Create the keyring, which must fail with {@code expected}. */
        FailureCheck createFailsWith(ExpectedError expected) {
            CreateAwsKmsKeyringInput request = input.build();
            return FailureCheck.run(Mpl.this, () -> MplTestServerClients.withRetry(() ->
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
                testServer().createRawAesKeyring(request)).getKeyringId());
        }

        /** Create the keyring, which must fail with {@code expected}. */
        FailureCheck createFailsWith(ExpectedError expected) {
            CreateRawAesKeyringInput request = input.build();
            return FailureCheck.run(Mpl.this, () -> MplTestServerClients.withRetry(() ->
                testServer.createRawAesKeyring(request)), expected);
        }
    }
}
