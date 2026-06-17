import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * Main screen shown after login.
 * Provides the "paste a link" section and displays the fraud analysis report.
 */
public class DetectorFrame extends JFrame {

    private static final Color BG     = new Color(0x0F172A);
    private static final Color CARD   = new Color(0x1E293B);
    private static final Color ACCENT = new Color(0x38BDF8);
    private static final Color TEXT   = new Color(0xE2E8F0);
    private static final Color SUBTLE = new Color(0x94A3B8);

    private final FraudDetector detector = new FraudDetector();
    private final String userEmail;

    private final JTextField linkField = new JTextField();
    private final JButton analyzeBtn = new JButton("Analyze Link");
    private final JEditorPane report = new JEditorPane();

    public DetectorFrame(String userEmail) {
        this.userEmail = userEmail;
        setTitle("Fraud Internship Detector");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(720, 680);
        setMinimumSize(new Dimension(620, 560));
        setLocationRelativeTo(null);
        setContentPane(buildContent());
    }

    private JComponent buildContent() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG);
        root.setBorder(new EmptyBorder(20, 24, 20, 24));

        root.add(buildHeader(), BorderLayout.NORTH);
        root.add(buildCenter(), BorderLayout.CENTER);
        return root;
    }

    private JComponent buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(BG);
        header.setBorder(new EmptyBorder(0, 0, 16, 0));

        JLabel title = new JLabel("🛡  Fraud Internship Detector");
        title.setFont(new Font("SansSerif", Font.BOLD, 20));
        title.setForeground(TEXT);

        JLabel user = new JLabel(userEmail + "   ");
        user.setFont(new Font("SansSerif", Font.PLAIN, 12));
        user.setForeground(SUBTLE);

        JButton logout = new JButton("Logout");
        logout.setFont(new Font("SansSerif", Font.PLAIN, 12));
        logout.setFocusPainted(false);
        logout.setForeground(ACCENT);
        logout.setBackground(CARD);
        logout.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x334155), 1, true),
                new EmptyBorder(4, 12, 4, 12)));
        logout.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        logout.addActionListener(e -> {
            new LoginFrame().setVisible(true);
            dispose();
        });

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setBackground(BG);
        right.add(user);
        right.add(logout);

        header.add(title, BorderLayout.WEST);
        header.add(right, BorderLayout.EAST);
        return header;
    }

    private JComponent buildCenter() {
        JPanel center = new JPanel(new BorderLayout(0, 16));
        center.setBackground(BG);

        center.add(buildLinkSection(), BorderLayout.NORTH);
        center.add(buildReportSection(), BorderLayout.CENTER);
        return center;
    }

    /** The "paste the link here" section. */
    private JComponent buildLinkSection() {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(CARD);
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        JLabel heading = new JLabel("Paste the internship / company link");
        heading.setFont(new Font("SansSerif", Font.BOLD, 15));
        heading.setForeground(TEXT);
        heading.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel hint = new JLabel("Example: https://careers.example.com/summer-internship");
        hint.setFont(new Font("SansSerif", Font.PLAIN, 12));
        hint.setForeground(SUBTLE);
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);

        linkField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        linkField.setForeground(TEXT);
        linkField.setCaretColor(TEXT);
        linkField.setBackground(BG);
        linkField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        linkField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x334155), 1, true),
                new EmptyBorder(10, 12, 10, 12)));
        linkField.setAlignmentX(Component.LEFT_ALIGNMENT);
        linkField.addActionListener(e -> runAnalysis());

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        buttonRow.setBackground(CARD);
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttonRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));

        analyzeBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
        analyzeBtn.setForeground(new Color(0x0F172A));
        analyzeBtn.setBackground(ACCENT);
        analyzeBtn.setFocusPainted(false);
        analyzeBtn.setBorder(new EmptyBorder(10, 22, 10, 22));
        analyzeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        analyzeBtn.addActionListener(e -> runAnalysis());

        JButton clearBtn = new JButton("Clear");
        clearBtn.setFont(new Font("SansSerif", Font.PLAIN, 13));
        clearBtn.setForeground(SUBTLE);
        clearBtn.setBackground(CARD);
        clearBtn.setFocusPainted(false);
        clearBtn.setBorder(BorderFactory.createLineBorder(new Color(0x334155), 1, true));
        clearBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        clearBtn.addActionListener(e -> {
            linkField.setText("");
            showWelcome();
        });

        buttonRow.add(analyzeBtn);
        buttonRow.add(clearBtn);

        card.add(heading);
        card.add(Box.createVerticalStrut(4));
        card.add(hint);
        card.add(Box.createVerticalStrut(14));
        card.add(linkField);
        card.add(Box.createVerticalStrut(14));
        card.add(buttonRow);
        return card;
    }

    /** The scrollable HTML report area. */
    private JComponent buildReportSection() {
        report.setContentType("text/html");
        report.setEditable(false);
        report.setBackground(CARD);
        report.setBorder(new EmptyBorder(16, 18, 16, 18));
        showWelcome();

        JScrollPane scroll = new JScrollPane(report);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(0x334155), 1, true));
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        return scroll;
    }

    // ----- analysis flow -----

    private void runAnalysis() {
        String link = linkField.getText().trim();
        if (link.isEmpty()) {
            report.setText(htmlWrap("<p style='color:#F87171'>Please paste a link first.</p>"));
            return;
        }

        analyzeBtn.setEnabled(false);
        analyzeBtn.setText("Analyzing…");
        report.setText(htmlWrap("<p style='color:#94A3B8'>Checking the website, please wait…</p>"));

        // Run off the UI thread so the window stays responsive while fetching.
        new SwingWorker<AnalysisResult, Void>() {
            @Override
            protected AnalysisResult doInBackground() {
                return detector.analyze(link);
            }

            @Override
            protected void done() {
                try {
                    renderResult(get());
                } catch (Exception ex) {
                    report.setText(htmlWrap(
                            "<p style='color:#F87171'>Something went wrong: "
                            + escape(ex.getMessage()) + "</p>"));
                } finally {
                    analyzeBtn.setEnabled(true);
                    analyzeBtn.setText("Analyze Link");
                }
            }
        }.execute();
    }

    private void renderResult(AnalysisResult r) {
        AnalysisResult.Verdict v = r.verdict();
        String color = switch (v) {
            case GENUINE -> "#4ADE80";
            case SUSPICIOUS -> "#FBBF24";
            case SCAM -> "#F87171";
        };

        StringBuilder b = new StringBuilder();
        b.append("<div style='font-family:sans-serif;'>");

        // Verdict banner
        b.append("<div style='font-size:22px;font-weight:bold;color:").append(color).append(";'>")
         .append(v.icon).append("  ").append(v.label).append("</div>");
        b.append("<div style='color:#94A3B8;font-size:12px;margin-top:4px;'>")
         .append("Risk score: <b style='color:").append(color).append("'>")
         .append(r.riskScore()).append(" / 100</b></div>");

        // Risk meter
        b.append("<div style='margin:12px 0;background:#0F172A;height:14px;width:100%;'>")
         .append("<div style='background:").append(color).append(";height:14px;width:")
         .append(r.riskScore()).append("%;'></div></div>");

        b.append("<div style='color:#64748B;font-size:11px;word-wrap:break-word;'>")
         .append("Checked: ").append(escape(r.url())).append("<br>")
         .append(escape(r.fetchNote())).append("</div><br>");

        // Live real-world checks (domain age, SSL, blacklist)
        if (!r.infoNotes().isEmpty()) {
            b.append("<div style='font-weight:bold;color:#38BDF8;font-size:14px;'>🔎 Live checks</div>");
            b.append(listHtml(r.infoNotes(), "#BAE6FD", ""));
            b.append("<br>");
        }

        // Red flags
        b.append("<div style='font-weight:bold;color:#F87171;font-size:14px;'>")
         .append("⚠ Warning signs (").append(r.redFlags().size()).append(")</div>");
        b.append(listHtml(r.redFlags(), "#FCA5A5",
                "No major warning signs were detected."));

        // Trust signals
        b.append("<br><div style='font-weight:bold;color:#4ADE80;font-size:14px;'>")
         .append("✓ Trust signals (").append(r.trustSignals().size()).append(")</div>");
        b.append(listHtml(r.trustSignals(), "#86EFAC",
                "No clear trust signals were found."));

        // Advice
        b.append("<br><div style='background:#0F172A;padding:12px;color:#CBD5E1;font-size:12px;'>")
         .append(adviceFor(v))
         .append("</div>");

        b.append("<div style='color:#475569;font-size:10px;margin-top:12px;'>")
         .append("This is an automated heuristic check, not legal proof. Always verify offers independently.")
         .append("</div>");

        b.append("</div>");
        report.setText(htmlWrap(b.toString()));
        report.setCaretPosition(0);
    }

    private String adviceFor(AnalysisResult.Verdict v) {
        return switch (v) {
            case GENUINE -> "<b>Looks reasonable.</b> Still confirm the company on LinkedIn, "
                    + "and never pay a fee or share OTP / bank details to get an internship.";
            case SUSPICIOUS -> "<b>Be careful.</b> Some warning signs were found. Research the "
                    + "company name, look for reviews, and do not send money or documents yet.";
            case SCAM -> "<b>High risk — likely a scam.</b> Do NOT pay any fee, share personal "
                    + "documents, or give OTP/bank details. Genuine internships never ask for money.";
        };
    }

    private String listHtml(List<String> items, String color, String emptyText) {
        if (items.isEmpty()) {
            return "<div style='color:#64748B;font-size:12px;margin-top:4px;'>"
                    + emptyText + "</div>";
        }
        StringBuilder sb = new StringBuilder("<ul style='margin:6px 0 0 0;padding-left:18px;'>");
        for (String item : items) {
            sb.append("<li style='color:").append(color)
              .append(";font-size:12px;margin-bottom:4px;'>")
              .append(escape(item)).append("</li>");
        }
        return sb.append("</ul>").toString();
    }

    private void showWelcome() {
        report.setText(htmlWrap(
                "<div style='font-family:sans-serif;color:#94A3B8;'>"
                + "<div style='font-size:16px;color:#E2E8F0;font-weight:bold;'>How it works</div>"
                + "<p style='font-size:13px;'>Paste an internship or company link above and click "
                + "<b style='color:#38BDF8;'>Analyze Link</b>. The tool checks the web address and "
                + "the page content for common scam patterns and gives you a risk score.</p>"
                + "<p style='font-size:12px;color:#64748B;'>Remember: a genuine internship will never "
                + "ask you to pay a registration / training fee or share your OTP or bank password.</p>"
                + "</div>"));
    }

    // ----- small html helpers -----

    private String htmlWrap(String inner) {
        return "<html><body style='background:#1E293B;margin:0;'>" + inner + "</body></html>";
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
