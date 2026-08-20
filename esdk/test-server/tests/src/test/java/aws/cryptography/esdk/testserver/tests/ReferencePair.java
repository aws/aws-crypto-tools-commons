package aws.cryptography.esdk.testserver.tests;
import aws.cryptography.testserver.tests.TargetPair;
import aws.cryptography.testserver.tests.LanguageServerTarget;
import aws.cryptography.testserver.tests.FeatureGate;

import java.net.URI;

/**
 * A single-sided Test row: the run's reference implementation on the encrypt
 * (producer) leg — or its capability substitute when {@code substituted} — and
 * one configured target on the decrypt leg. Composed by
 * {@link ReferenceImplementation#decryptSide}: a decrypt-side Test iterates one
 * row per configured target instead of the full pairwise matrix, because its
 * assertion reads only the decryptor.
 *
 * <p>The display form names both roles so findings stay attributable —
 * {@code ref:java-v3->python-v4} — and marks a substituted reference —
 * {@code ref(sub):go-v1->python-v4} — so the report can count substituted rows.
 */
public record ReferencePair(
        LanguageServerTarget encryptTarget,
        LanguageServerTarget decryptTarget,
        boolean substituted) {

    /** @return the base endpoint URL the reference produces the message on. */
    public URI encryptEndpoint() {
        return encryptTarget.endpoint();
    }

    /** @return the base endpoint URL of the decryptor under test. */
    public URI decryptEndpoint() {
        return decryptTarget.endpoint();
    }

    /**
     * @return this row as an {@link TargetPair}, for {@link FeatureGate} and
     *     the shared encrypt/decrypt helpers.
     */
    public TargetPair asEndpointPair() {
        return new TargetPair(encryptTarget, decryptTarget);
    }

    @Override
    public String toString() {
        return "ref" + (substituted ? "(sub)" : "") + ":"
            + encryptTarget.label() + "->" + decryptTarget.label();
    }
}
