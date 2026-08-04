package aws.cryptography.esdk.testserver.tests;

import aws.cryptography.esdk.testserver.client.model.ESDKClientConfig;
import aws.cryptography.esdk.testserver.client.model.ESDKClientError;
import java.net.URI;
import java.util.Arrays;

/**
 * Shared support for the byte-flip mutation fuzz tests: it classifies one decrypt into the three
 * outcomes the fuzz oracle distinguishes, checks the oracle, and builds a region label and hex
 * dump for reproducible failure messages.
 *
 * <p>The oracle both fuzz tests assert: for any single-byte flip of a valid message, decrypt must
 * REJECT with a modeled {@link ESDKClientError} or ACCEPT and return the exact original plaintext.
 * It must never CRASH (an unmodeled {@code GenericServerError}, or a transport failure that
 * outlives the retry) and never return altered plaintext (an authentication bypass). Accepting
 * with identical plaintext is the legitimate case where the flipped byte is a field the
 * implementation does not authenticate — the redundant on-wire frame sequence number is one such
 * field on an implementation that reconstructs it from its own counter (TAMPER-004).
 */
final class MutationFuzz {

    private MutationFuzz() {
    }

    enum Kind { REJECTED, ACCEPTED, CRASHED }

    /** The classified result of decrypting a mutated message. */
    record Outcome(Kind kind, byte[] plaintext, String detail) {
        boolean accepted() {
            return kind == Kind.ACCEPTED;
        }

        boolean crashed() {
            return kind == Kind.CRASHED;
        }
    }

    /**
     * Decrypt {@code ciphertext} on {@code endpoint}, classifying the result: a returned plaintext
     * is {@code ACCEPTED}, a modeled {@link ESDKClientError} is {@code REJECTED}, and any other
     * throwable (a {@code GenericServerError}, or a transport failure surviving the retry) is
     * {@code CRASHED}.
     */
    static Outcome decryptCapturing(URI endpoint, ESDKClientConfig config, byte[] ciphertext) {
        try {
            return new Outcome(Kind.ACCEPTED, EsdkOps.decrypt(endpoint, config, ciphertext), null);
        } catch (ESDKClientError rejected) {
            return new Outcome(Kind.REJECTED, null, rejected.getMessage());
        } catch (Throwable crashed) {
            return new Outcome(Kind.CRASHED, null,
                crashed.getClass().getSimpleName() + ": " + crashed.getMessage());
        }
    }

    /**
     * Check the oracle for one {@code outcome} of {@code message} with byte {@code index} flipped:
     * a description of the violation (crashed, or accepted with altered plaintext), or {@code null}
     * when the outcome is allowed (rejected, or accepted with the exact {@code expectedPlaintext}).
     */
    static String checkOracle(byte[] message, int index, byte[] expectedPlaintext, Outcome outcome) {
        if (outcome.crashed()) {
            return "byte " + index + " [" + regionOf(message, index)
                + "]: decrypt did not surface a modeled error — " + outcome.detail();
        }
        if (outcome.accepted() && !Arrays.equals(expectedPlaintext, outcome.plaintext())) {
            return "byte " + index + " [" + regionOf(message, index)
                + "]: decrypt ACCEPTED the mutated message and returned ALTERED plaintext "
                + "(authentication bypass)";
        }
        return null;
    }

    /** A coarse label for the message region byte {@code index} falls in, parsed best-effort. */
    static String regionOf(byte[] message, int index) {
        try {
            EsdkMessage parsed = EsdkMessage.parse(message);
            if (index < parsed.bodyStart) {
                return "header";
            }
            if (parsed.footerOffset >= 0 && index >= parsed.footerOffset) {
                return "footer";
            }
            for (EsdkMessage.Frame frame : parsed.frames) {
                if (index >= frame.sequenceNumberOffset() && index < frame.ivOffset()) {
                    return "body:sequence-number";
                }
            }
            return "body";
        } catch (RuntimeException e) {
            return "offset";
        }
    }

    /** Lowercase hex of {@code bytes}, so a failing message can be replayed verbatim. */
    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
