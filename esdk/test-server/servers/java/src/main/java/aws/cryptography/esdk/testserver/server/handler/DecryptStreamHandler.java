package aws.cryptography.esdk.testserver.server.handler;

import aws.cryptography.esdk.testserver.server.error.OperationWrapper;
import aws.cryptography.esdk.testserver.server.model.DecryptStreamInput;
import aws.cryptography.esdk.testserver.server.model.DecryptStreamOutput;
import aws.cryptography.esdk.testserver.server.registry.EsdkClient;
import aws.cryptography.esdk.testserver.server.service.DecryptStreamOperation;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import software.amazon.smithy.java.io.datastream.DataStream;
import software.amazon.smithy.java.server.RequestContext;

/**
 * Stream variant of decrypt for the Streaming_Capable Java server (Requirement
 * 4.6): resolves the {@code ClientId}, streams the ciphertext through the real
 * ESDK Java streaming API, and returns the plaintext stream. No stream
 * round-trip Test is exercised in this pass; the handler is implemented so the
 * wire contract is honored and ESDK failures forward as an {@code ESDKClientError}
 * (Requirement 4.10).
 */
public final class DecryptStreamHandler implements DecryptStreamOperation {

    private final ClientIdGuard guard;
    private final OperationWrapper wrapper;

    public DecryptStreamHandler(ClientIdGuard guard, OperationWrapper wrapper) {
        this.guard = guard;
        this.wrapper = wrapper;
    }

    @Override
    public DecryptStreamOutput decryptStream(DecryptStreamInput input, RequestContext context) {
        return wrapper.invoke("DecryptStream", () -> {
            EsdkClient client = guard.resolve(input.getClientId());
            ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
            try (InputStream ciphertext = input.getCiphertext().asInputStream()) {
                client.decryptStream(ciphertext, plaintext, input.getEncryptionContext());
            }
            return DecryptStreamOutput.builder()
                .plaintext(DataStream.ofBytes(plaintext.toByteArray()))
                .build();
        });
    }
}
