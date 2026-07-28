package aws.cryptography.esdk.testserver.orchestrator.launch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Shape tests for {@link CloseResult} (design "Launcher contract"): STOPPED
 * carries no language; STILL_RUNNING must name the language whose server was
 * not stopped (Requirement 2.11).
 */
class CloseResultTest {

    @Test
    @DisplayName("stopped() is STOPPED and carries no language")
    void stoppedShape() {
        CloseResult result = CloseResult.stopped();
        assertEquals(CloseResult.Status.STOPPED, result.status());
        assertNull(result.language(), "a STOPPED result carries no language");
        assertTrue(result.isStopped());
    }

    @Test
    @DisplayName("stillRunning(language) is STILL_RUNNING and names the language (Req 2.11)")
    void stillRunningShape() {
        CloseResult result = CloseResult.stillRunning("python");
        assertEquals(CloseResult.Status.STILL_RUNNING, result.status());
        assertEquals("python", result.language(), "the cleanup failure must name the language");
        assertFalse(result.isStopped());
    }

    @Test
    @DisplayName("a STILL_RUNNING result without a language is rejected")
    void stillRunningRequiresLanguage() {
        assertThrows(IllegalArgumentException.class, () -> CloseResult.stillRunning(null));
        assertThrows(IllegalArgumentException.class, () -> CloseResult.stillRunning(" "));
    }
}
