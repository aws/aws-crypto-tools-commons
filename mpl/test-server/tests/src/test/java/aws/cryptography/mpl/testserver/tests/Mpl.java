package aws.cryptography.mpl.testserver.tests;

import aws.cryptography.mpl.testserver.client.client.MPLTestServerClient;
import aws.cryptography.mpl.testserver.client.model.AesWrappingAlg;
import aws.cryptography.mpl.testserver.client.model.AlgorithmSuiteId;
import aws.cryptography.mpl.testserver.client.model.CreateRawAesKeyringInput;
import aws.cryptography.mpl.testserver.client.model.DecryptionMaterials;
import aws.cryptography.mpl.testserver.client.model.EncryptionMaterials;
import aws.cryptography.testserver.tests.ExpectedError;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import java.nio.ByteBuffer;
import java.util.Map;

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
        return Materials.newEncryptionMaterials(testServer, suite, requireDefaults().encryptionContext());
    }

    /** New encryption materials with the test class's suite, {@code encryptionContext}, and no data key yet. */
    EncryptionMaterials newEncryptionMaterials(Map<String, String> encryptionContext) {
        throwUnresolvedFailure();
        return Materials.newEncryptionMaterials(testServer, requireDefaults().algorithmSuite(), encryptionContext);
    }

    /** New decryption materials with the test class's suite and encryption context, and no data key yet. */
    DecryptionMaterials newDecryptionMaterials() {
        return newDecryptionMaterials(requireDefaults().algorithmSuite());
    }

    /** New decryption materials with {@code suite}, the test class's encryption context, and no data key yet. */
    DecryptionMaterials newDecryptionMaterials(AlgorithmSuiteId suite) {
        throwUnresolvedFailure();
        return Materials.newDecryptionMaterials(testServer, suite, requireDefaults().encryptionContext());
    }

    /** New decryption materials with the test class's suite, {@code encryptionContext}, and no data key yet. */
    DecryptionMaterials newDecryptionMaterials(Map<String, String> encryptionContext) {
        throwUnresolvedFailure();
        return Materials.newDecryptionMaterials(testServer, requireDefaults().algorithmSuite(), encryptionContext);
    }

    private KeyringTestDefaults requireDefaults() {
        if (defaults == null) {
            throw new IllegalStateException(
                "new materials need a suite and encryption context: implement KeyringTestDefaults in the test class");
        }
        return defaults;
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

        /** Create the keyring, which must fail with any error. */
        FailureCheck createFails() {
            return createFailsWith(null);
        }

        /** Create the keyring, which must fail with {@code expected}. */
        FailureCheck createFailsWith(ExpectedError expected) {
            CreateRawAesKeyringInput request = input.build();
            return FailureCheck.run(Mpl.this, () -> MplTestServerClients.withRetry(() ->
                testServer.createRawAesKeyring(request)), expected);
        }
    }
}
