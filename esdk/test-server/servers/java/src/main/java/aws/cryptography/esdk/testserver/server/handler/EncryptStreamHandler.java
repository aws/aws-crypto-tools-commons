package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.ESDKAlgorithmSuiteId;
import aws.cryptography.esdk.testserver.server.model.EncryptStreamInput;
import aws.cryptography.esdk.testserver.server.model.EncryptStreamOutput;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.service.EncryptStreamOperation;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import software.amazon.smithy.java.io.datastream.DataStream;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Stream variant of encrypt for the Streaming_Capable Java server (Requirement
 * 4.5): resolves the {@code ClientId}, streams the plaintext through the real
 * ESDK Java streaming API, and returns the ciphertext stream. No stream
 * round-trip Test is exercised in this pass; the handler is implemented so the
 * wire contract is honored and ESDK failures forward as an {@code ESDKClientError}
 * (Requirement 4.10).
 */
public final class EncryptStreamHandler implements EncryptStreamOperation {

    private final ClientIdGuard guard;
    private final OperationWrapper wrapper;

    public EncryptStreamHandler(ClientIdGuard guard, OperationWrapper wrapper) {
        this.guard = guard;
        this.wrapper = wrapper;
    }

    @Override
    public EncryptStreamOutput encryptStream(EncryptStreamInput input, RequestContext context) {
        return wrapper.invoke("EncryptStream", () -> {
            EsdkClient client = guard.resolve(input.getClientId());
            ESDKAlgorithmSuiteId suite = input.getAlgorithmSuiteId();
            ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
            try (InputStream plaintext = input.getPlaintext().asInputStream()) {
                client.encryptStream(
                    plaintext,
                    ciphertext,
                    input.getEncryptionContext(),
                    suite == null ? null : suite.getValue(),
                    input.getFrameLength());
            }
            return EncryptStreamOutput.builder()
                .ciphertext(DataStream.ofBytes(ciphertext.toByteArray()))
                .build();
        });
    }
}
