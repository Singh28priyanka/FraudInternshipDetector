import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.regex.Pattern;

/**
 * Login / registration screen.
 * Collects an email and password, validates them against the {@link UserStore},
 * and opens the {@link DetectorFrame} on success.
 */
public class LoginFrame extends JFrame {

    private static final Pattern EMAIL =
            Pattern.compile("^[\\w.+-]+@[\\w-]+\\.[\\w.-]+$");

    private static final Color BG       = new Color(0x0F172A); // slate-900
    private static final Color CARD     = new Color(0x1E293B); // slate-800
    private static final Color ACCENT   = new Color(0x38BDF8); // sky-400
    private static final Color TEXT     = new Color(0xE2E8F0); // slate-200
    private static final Color SUBTLE   = new Color(0x94A3B8); // slate-400

    private final JTextField emailField = new JTextField();
    private final JPasswordField passwordField = new JPasswordField();
    private final JLabel message = new JLabel(" ");

    public LoginFrame() {
        setTitle("Fraud Internship Detector — Login");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(440, 560);
        setMinimumSize(new Dimension(400, 520));
        setLocationRelativeTo(null);
        setContentPane(buildContent());
    }

    private JComponent buildContent() {
        JPanel root = new JPanel(new GridBagLayout());
        root.setBackground(BG);

        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(CARD);
        card.setBorder(new EmptyBorder(32, 36, 32, 36));

        JLabel shield = new JLabel("🛡");
        shield.setFont(new Font("SansSerif", Font.PLAIN, 44));
        shield.setForeground(ACCENT);
        shield.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel title = new JLabel("Fraud Internship Detector");
        title.setFont(new Font("SansSerif", Font.BOLD, 20));
        title.setForeground(TEXT);
        title.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitle = new JLabel("Sign in to check internship links for scams");
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        subtitle.setForeground(SUBTLE);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        card.add(shield);
        card.add(Box.createVerticalStrut(8));
        card.add(title);
        card.add(Box.createVerticalStrut(4));
        card.add(subtitle);
        card.add(Box.createVerticalStrut(24));

        card.add(fieldLabel("Email"));
        card.add(Box.createVerticalStrut(6));
        styleField(emailField);
        card.add(emailField);
        card.add(Box.createVerticalStrut(16));

        card.add(fieldLabel("Password"));
        card.add(Box.createVerticalStrut(6));
        styleField(passwordField);
        card.add(passwordField);
        card.add(Box.createVerticalStrut(20));

        JButton loginBtn = primaryButton("Login");
        loginBtn.addActionListener(e -> doLogin());
        card.add(loginBtn);
        card.add(Box.createVerticalStrut(10));

        JButton registerBtn = secondaryButton("Create an account");
        registerBtn.addActionListener(e -> doRegister());
        card.add(registerBtn);

        card.add(Box.createVerticalStrut(14));
        message.setFont(new Font("SansSerif", Font.PLAIN, 12));
        message.setForeground(new Color(0xF87171));
        message.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(message);

        // Submit on Enter from the password field.
        passwordField.addActionListener(e -> doLogin());

        root.add(card);
        return root;
    }

    // ----- actions -----

    private void doLogin() {
        String email = emailField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (!validInput(email, password)) return;

        if (UserStore.validate(email, password)) {
            openDetector(email);
        } else if (!UserStore.exists(email)) {
            showError("No account found. Click \"Create an account\" first.");
        } else {
            showError("Incorrect password. Please try again.");
        }
    }

    private void doRegister() {
        String email = emailField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (!validInput(email, password)) return;
        if (password.length() < 6) {
            showError("Password must be at least 6 characters.");
            return;
        }

        if (UserStore.register(email, password)) {
            message.setForeground(new Color(0x4ADE80));
            message.setText("Account created! You can log in now.");
        } else {
            showError("That email is already registered. Try logging in.");
        }
    }

    private boolean validInput(String email, String password) {
        if (email.isEmpty() || password.isEmpty()) {
            showError("Please enter both email and password.");
            return false;
        }
        if (!EMAIL.matcher(email).matches()) {
            showError("Please enter a valid email address.");
            return false;
        }
        return true;
    }

    private void openDetector(String email) {
        DetectorFrame detector = new DetectorFrame(email);
        detector.setVisible(true);
        dispose();
    }

    private void showError(String text) {
        message.setForeground(new Color(0xF87171));
        message.setText(text);
    }

    // ----- styling helpers -----

    private JLabel fieldLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("SansSerif", Font.PLAIN, 12));
        l.setForeground(SUBTLE);
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setMaximumSize(new Dimension(Integer.MAX_VALUE, l.getPreferredSize().height));
        return l;
    }

    private void styleField(JTextField field) {
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        field.setFont(new Font("SansSerif", Font.PLAIN, 14));
        field.setForeground(TEXT);
        field.setCaretColor(TEXT);
        field.setBackground(new Color(0x0F172A));
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x334155), 1, true),
                new EmptyBorder(8, 12, 8, 12)));
        field.setAlignmentX(Component.LEFT_ALIGNMENT);
    }

    private JButton primaryButton(String text) {
        JButton b = new JButton(text);
        b.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        b.setAlignmentX(Component.CENTER_ALIGNMENT);
        b.setFont(new Font("SansSerif", Font.BOLD, 14));
        b.setForeground(new Color(0x0F172A));
        b.setBackground(ACCENT);
        b.setFocusPainted(false);
        b.setBorder(new EmptyBorder(10, 16, 10, 16));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return b;
    }

    private JButton secondaryButton(String text) {
        JButton b = new JButton(text);
        b.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        b.setAlignmentX(Component.CENTER_ALIGNMENT);
        b.setFont(new Font("SansSerif", Font.PLAIN, 13));
        b.setForeground(ACCENT);
        b.setBackground(CARD);
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createLineBorder(new Color(0x334155), 1, true));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return b;
    }
}
