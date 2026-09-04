package aws.cryptography.esdk.testserver.orchestrator.config;

/**
 * One entry in the commons bug ledger ({@code config/bug-config.json}): the
 * authoritative catalog of every known bug across the product's language
 * implementations. Unlike the Feature_Catalog, the ledger records only that a
 * bug exists — not which languages exhibit it (each Language_Server lists the
 * bugs it currently has in its own {@code bug-config.json}), and languages never
 * declare a bug's <em>absence</em>.
 *
 * @param id          the stable bug id, referenced by a server's bug-config.json
 * @param description a short human-readable description
 * @param ticketId    the tracking ticket id, or blank when none is filed yet
 */
public record BugLedgerEntry(String id, String description, String ticketId) {
}
