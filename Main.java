import javax.swing.*;

/**
 * Fraud Internship Detector
 * -------------------------
 * Entry point. Launches the login screen on the Swing event-dispatch thread.
 *
 * Compile:  javac *.java
 * Run:      java Main
 */
public class Main {
    public static void main(String[] args) {
        // Use the platform look-and-feel so the app feels native.
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Fall back to default look-and-feel silently.
        }

        SwingUtilities.invokeLater(() -> new LoginFrame().setVisible(true));
    }
}
