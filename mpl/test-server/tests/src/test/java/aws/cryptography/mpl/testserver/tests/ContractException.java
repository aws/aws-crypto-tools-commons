package aws.cryptography.mpl.testserver.tests;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Skip this {@link KeyringContract} test for this keyring, because the keyring does not follow the rule.
 *
 * <p>Put it on an override of the contract test, next to {@link KeyringTest}; the override's body can be empty.
 * Each run is a visible skip with the message {@code keyring contract exception: <reason>}.
 * feature-gate-log.jsonl records the run as skipped, so the test's spec annotations get no credit.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@interface ContractException {

    /** Why the keyring does not follow the rule, such as the line of its own spec that says so. */
    String reason();
}
