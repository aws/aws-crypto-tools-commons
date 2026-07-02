package aws.cryptography.esdk.testserver.server.error;

import aws.cryptography.esdk.testserver.server.model.ESDKClientError;
import aws.cryptography.esdk.testserver.server.model.ESDKTestServerException;
import aws.cryptography.esdk.testserver.server.model.GenericServerError;

/**
 * Maps any {@link Throwable} raised while handling an operation onto exactly one
 * of the two modeled error shapes, by the origin of the failure (Property 8,
 * Requirements 5.5, 5.6, 6.1, 6.2).
 *
 * <p>The mapping is:
 * <ul>
 *   <li>An already-modeled {@link GenericServerError} or {@link ESDKClientError}
 *       is returned unchanged, preserving its type and message (Requirement 6.1).</li>
 *   <li>An {@link EsdkClientException} — a failure that originated inside the real
 *       ESDK client — becomes an {@link ESDKClientError} whose message is the ESDK
 *       exception's message, unmodified, and never a {@link GenericServerError}
 *       (Requirements 5.6, Property 8).</li>
 *   <li>Any other (non-modeled) exception — a TestServer-framework failure —
 *       becomes a {@link GenericServerError} with a non-empty message that includes
 *       the originating exception's description, and never an {@link ESDKClientError}
 *       (Requirements 5.5, 6.2, Property 8).</li>
 * </ul>
 *
 * <p>This is a pure function of the throwable and the operation name; it performs
 * no I/O and mutates no state, so it is exercised directly by the error-mapping
 * property tests (P8) and, through {@link OperationWrapper}, by the catch-all
 * wrapping property test (P9).
 */
public final class ErrorClassifier {

    /**
     * Classify a failure into a modeled error by its origin.
     *
     * @param operationName the operation being handled, used to build a helpful
     *     framework-error message.
     * @param failure the throwable raised by the handler.
     * @return a {@link GenericServerError} or an {@link ESDKClientError}; never
     *     {@code null}.
     */
    public ESDKTestServerException classify(String operationName, Throwable failure) {
        // (6.1) Modeled errors pass through with type and message preserved.
        if (failure instanceof GenericServerError modeled) {
            return modeled;
        }
        if (failure instanceof ESDKClientError modeled) {
            return modeled;
        }

        // (5.6, P8) ESDK-origin failures forward the ESDK message unmodified.
        if (failure instanceof EsdkClientException esdk) {
            String message = esdk.esdkMessage();
            return ESDKClientError.builder()
                .message(message == null ? "" : message)
                .build();
        }

        // (5.5, 6.2, P8) Every other failure is a framework failure -> a
        // GenericServerError with a non-empty message including the description.
        return GenericServerError.builder()
            .message("Operation '" + operationName + "' failed: " + describe(failure))
            .build();
    }

    /** Build a non-empty description of a non-modeled exception (Requirement 6.2). */
    private static String describe(Throwable failure) {
        if (failure == null) {
            return "unknown error";
        }
        String type = failure.getClass().getName();
        String message = failure.getMessage();
        return (message == null || message.isEmpty()) ? type : type + ": " + message;
    }
}
