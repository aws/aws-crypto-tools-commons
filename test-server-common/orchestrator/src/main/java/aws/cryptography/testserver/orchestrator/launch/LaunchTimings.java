package aws.cryptography.testserver.orchestrator.launch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Wall-clock timings for each build/launch step, printed as they complete and
 * summarized once every server is up. Written to the GitHub Actions job summary
 * when {@code GITHUB_STEP_SUMMARY} is set.
 */
public final class LaunchTimings {

    /** One timed step. */
    public record Timing(String language, String step, Duration duration) {
    }

    private static final ConcurrentLinkedQueue<Timing> TIMINGS = new ConcurrentLinkedQueue<>();

    private LaunchTimings() {
    }

    /** Record and print the time elapsed since {@code startedAt}. */
    public static void log(String language, String step, Instant startedAt) {
        Timing timing = new Timing(language, step, Duration.between(startedAt, Instant.now()));
        TIMINGS.add(timing);
        System.out.println("[launch-timing] " + language + " | " + step + " | "
            + seconds(timing.duration()));
    }

    /** Print every recorded timing, slowest first, and append it to the job summary. */
    public static void printSummary(String title) {
        List<Timing> sorted = new ArrayList<>(TIMINGS);
        sorted.sort(Comparator.comparing(Timing::duration).reversed());
        StringBuilder text = new StringBuilder("==== " + title + " (slowest first) ====\n");
        StringBuilder markdown = new StringBuilder("### " + title + "\n\n"
            + "| language | step | seconds |\n|---|---|---:|\n");
        for (Timing timing : sorted) {
            text.append(String.format(Locale.ROOT, "  %8s  %-12s %s%n",
                seconds(timing.duration()), timing.language(), timing.step()));
            markdown.append("| ").append(timing.language()).append(" | ")
                .append(timing.step().replace("|", "\\|")).append(" | ")
                .append(seconds(timing.duration())).append(" |\n");
        }
        System.out.print(text);
        String summaryFile = System.getenv("GITHUB_STEP_SUMMARY");
        if (summaryFile != null && !summaryFile.isBlank()) {
            try {
                Files.writeString(Path.of(summaryFile), markdown.append('\n').toString(),
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                System.out.println("    (could not write the job summary: " + e.getMessage() + ")");
            }
        }
    }

    private static String seconds(Duration duration) {
        return String.format(Locale.ROOT, "%.1fs", duration.toMillis() / 1000.0);
    }
}
