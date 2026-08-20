package aws.cryptography.testserver.orchestrator.source;

/**
 * The identity of one resolvable component of a run (design
 * "Resolution_Record"): a language's library source ({@code library:<lang>}),
 * a language's Language_Server implementation ({@code server:<lang>}), or the
 * Commons_Repository clone of a Language_Repository_Run ({@code commons}).
 *
 * @param kind     which component of the run this identifies
 * @param language the language, or {@code null} for the {@link Kind#COMMONS}
 *                 component
 */
public record ComponentId(Kind kind, String language) {

    /** The three component kinds of Requirement 5.1. */
    public enum Kind { LIBRARY, SERVER, COMMONS }

    public ComponentId {
        if (kind == null) {
            throw new IllegalArgumentException("kind is required");
        }
        if (kind == Kind.COMMONS) {
            if (language != null) {
                throw new IllegalArgumentException("the commons component carries no language");
            }
        } else if (language == null || language.isBlank()) {
            throw new IllegalArgumentException(kind + " components require a language");
        }
    }

    /** The {@code library:<lang>} component. */
    public static ComponentId library(String language) {
        return new ComponentId(Kind.LIBRARY, language);
    }

    /** The {@code server:<lang>} component. */
    public static ComponentId server(String language) {
        return new ComponentId(Kind.SERVER, language);
    }

    /** The {@code commons} component of a Language_Repository_Run. */
    public static ComponentId commons() {
        return new ComponentId(Kind.COMMONS, null);
    }

    /** The design's canonical id: {@code library:<lang>} / {@code server:<lang>} / {@code commons}. */
    @Override
    public String toString() {
        return switch (kind) {
            case LIBRARY -> "library:" + language;
            case SERVER -> "server:" + language;
            case COMMONS -> "commons";
        };
    }
}
