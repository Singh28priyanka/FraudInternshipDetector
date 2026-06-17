import java.util.ArrayList;
import java.util.List;

/**
 * Holds the outcome of analysing one internship link:
 * a risk score (0-100), the verdict band, and the human-readable
 * red flags and trust signals that were found.
 */
public class AnalysisResult {

    public enum Verdict {
        GENUINE("Likely Genuine", "✅"),
        SUSPICIOUS("Suspicious", "⚠"),
        SCAM("Likely Scam", "🚫");

        public final String label;
        public final String icon;

        Verdict(String label, String icon) {
            this.label = label;
            this.icon = icon;
        }
    }

    private final String url;
    private int riskScore;                       // 0 (safe) .. 100 (definitely scam)
    private final List<String> redFlags = new ArrayList<>();
    private final List<String> trustSignals = new ArrayList<>();
    private final List<String> infoNotes = new ArrayList<>();  // neutral facts (domain age, SSL, …)
    private boolean reachable = true;
    private String fetchNote = "";

    public AnalysisResult(String url) {
        this.url = url;
    }

    /** Adds risk points and records the reason. Score is clamped to 0-100. */
    public void addRisk(int points, String reason) {
        riskScore = Math.min(100, Math.max(0, riskScore + points));
        redFlags.add(reason);
    }

    /** Records a positive/legitimacy signal and reduces risk slightly. */
    public void addTrust(int points, String reason) {
        riskScore = Math.min(100, Math.max(0, riskScore - points));
        trustSignals.add(reason);
    }

    /** Records a neutral factual finding (e.g. domain age, SSL details). */
    public void addInfo(String note) {
        infoNotes.add(note);
    }

    public Verdict verdict() {
        if (riskScore >= 60) return Verdict.SCAM;
        if (riskScore >= 30) return Verdict.SUSPICIOUS;
        return Verdict.GENUINE;
    }

    public String url()                  { return url; }
    public int riskScore()               { return riskScore; }
    public List<String> redFlags()       { return redFlags; }
    public List<String> trustSignals()   { return trustSignals; }
    public List<String> infoNotes()      { return infoNotes; }
    public boolean isReachable()         { return reachable; }
    public String fetchNote()            { return fetchNote; }

    public void setReachable(boolean reachable) { this.reachable = reachable; }
    public void setFetchNote(String note)       { this.fetchNote = note; }
}
