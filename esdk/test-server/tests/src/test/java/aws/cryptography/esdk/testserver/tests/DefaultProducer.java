package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.LanguageServerRegistry;
import aws.cryptography.testserver.tests.FeatureDeclarations;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Resolves the language that produces the message for a decrypt-only Test. Many behaviors are only
 * observed on decrypt (tamper rejection, mutation fuzzing, known-answer replay); they still need
 * one language to produce a valid message to decrypt, and which one is immaterial to what is being
 * tested. This picks that producer: the configured default language when it supports the required
 * Features, otherwise the first declared language that does.
 *
 * <p>The default is {@code java}, overridable with {@code -Desdk.testserver.defaultProducer=<lang>}
 * or {@code ESDK_TESTSERVER_DEFAULT_PRODUCER=<lang>} (matched against the language name, e.g.
 * {@code python}). A source the configured default cannot produce — the hierarchical keyring,
 * which the Java server does not build — falls back to the first language that declares it.
 */
final class DefaultProducer {

    static final String PRODUCER_PROPERTY = "esdk.testserver.defaultProducer";
    static final String PRODUCER_ENV = "ESDK_TESTSERVER_DEFAULT_PRODUCER";
    private static final String DEFAULT_LANGUAGE = "java";

    private DefaultProducer() {
    }

    /** The configured default producer language, lowercased; {@code java} unless overridden. */
    static String language() {
        String configured = System.getProperty(PRODUCER_PROPERTY, System.getenv(PRODUCER_ENV));
        if (configured == null || configured.isBlank()) {
            return DEFAULT_LANGUAGE;
        }
        return configured.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * The endpoint of the language that produces a message requiring {@code features}: the
     * configured default when it declares them all, else the first declared language that does.
     *
     * @throws IllegalStateException when no declared language supports {@code features}
     */
    static URI producerFor(Set<String> features) {
        FeatureDeclarations declarations = FeatureDeclarations.shared();
        List<LanguageServerTarget> targets = LanguageServerRegistry.shared().targets();
        String preferred = language();
        LanguageServerTarget fallback = null;
        for (LanguageServerTarget target : targets) {
            boolean supported =
                features.stream().allMatch(f -> declarations.isSupported(target.language(), f));
            if (!supported) {
                continue;
            }
            if (target.language().equals(preferred)) {
                return target.endpoint();
            }
            if (fallback == null) {
                fallback = target;
            }
        }
        if (fallback != null) {
            return fallback.endpoint();
        }
        throw new IllegalStateException(
            "no declared language produces a message requiring features " + features);
    }
}
