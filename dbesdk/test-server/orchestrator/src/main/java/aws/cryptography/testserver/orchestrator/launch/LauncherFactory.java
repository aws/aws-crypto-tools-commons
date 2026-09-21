package aws.cryptography.testserver.orchestrator.launch;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Per-language {@link Launcher} dispatch (task 6.4): the orchestrator asks the
 * factory for the launch plan of each effective Configuration_Entry's language
 * — {@code java} → {@code JavaLaunchPlan}, {@code rust} →
 * {@code RustLaunchPlan} in the shipped wiring. A language with no launcher
 * yields {@link Optional#empty()}, which the pipeline turns into a run abort
 * naming the language (Requirement 2.5) — support is never assumed.
 */
@FunctionalInterface
public interface LauncherFactory {

    /** The launcher for {@code language}, or empty when none is wired. */
    Optional<Launcher> launcherFor(String language);

    /** Dispatch from an explicit language → launcher map. */
    static LauncherFactory fromMap(Map<String, Launcher> byLanguage) {
        Map<String, Launcher> launchers = new LinkedHashMap<>(byLanguage);
        return language -> Optional.ofNullable(launchers.get(language));
    }

    /** One launcher for every language (test doubles). */
    static LauncherFactory uniform(Launcher launcher) {
        return language -> Optional.of(launcher);
    }
}
