package aws.cryptography.esdk.testserver.tests;

import java.net.URI;

/**
 * An (encrypt target, decrypt target) pair for a round trip: encrypt on the
 * encrypt endpoint, decrypt on the decrypt endpoint, assert the recovered
 * plaintext matches (Requirement 4.4). Each side is a
 * {@link LanguageServerTarget}, so a pair names a specific cross-language (really
 * cross-{@code (language, majorVersion)}) combination — for example encrypt on
 * {@code java-v3}, decrypt on {@code python-v4}. Same-target pairs (e.g.
 * {@code java-v3 -> java-v3}) are included for completeness.
 *
 * <p>The lifecycle of any managed (in-process) server lives in
 * {@link LanguageServerRegistry}; a pair is a plain value object whose endpoints
 * are the targets' endpoint URLs.
 */
public record EndpointPair(LanguageServerTarget encryptTarget, LanguageServerTarget decryptTarget) {

    /** @return the base endpoint URL to run {@code CreateClient}/encrypt against. */
    public URI encryptEndpoint() {
        return encryptTarget.endpoint();
    }

    /** @return the base endpoint URL to run {@code CreateClient}/decrypt against. */
    public URI decryptEndpoint() {
        return decryptTarget.endpoint();
    }

    /** @return {@code true} when BOTH endpoints drive the ESDK streaming API. */
    public boolean isStreamingCapable() {
        return LanguageServerRegistry.isStreamingCapable(encryptTarget)
            && LanguageServerRegistry.isStreamingCapable(decryptTarget);
    }

    @Override
    public String toString() {
        return encryptTarget.label() + "->" + decryptTarget.label();
    }
}
