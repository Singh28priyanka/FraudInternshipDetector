import com.sun.net.httpserver.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Web version of the Fraud Internship Detector.
 *
 * Runs a tiny HTTP server (no external libraries) so the app is reachable in a
 * browser at http://localhost:8080. It reuses the same {@link FraudDetector}
 * engine and {@link UserStore} accounts as the desktop Swing app.
 *
 * Run:  javac *.java  &&  java WebServer
 */
public class WebServer {

    /** Ports to try in order. Pass one as the first argument to override. */
    private static final int[] PORT_CHOICES = {8090, 8095, 9000, 5000, 8088, 0};
    private static final FraudDetector DETECTOR = new FraudDetector();

    /** Accepts only well-formed emails: text@domain.tld (tld is 2+ letters). */
    private static final java.util.regex.Pattern EMAIL_PATTERN =
            java.util.regex.Pattern.compile("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$");

    // Very small in-memory session store: cookie token -> user email.
    private static final Map<String, String> SESSIONS = new ConcurrentHashMap<>();
    private static int tokenSeq = 1000;

    public static void main(String[] args) throws IOException {
        HttpServer server = bind(args);
        int port = server.getAddress().getPort();
        server.createContext("/", WebServer::handleHome);
        // /register now uses the same smart handler (it auto-creates accounts).
        server.createContext("/register", WebServer::handleLogin);
        server.createContext("/login", WebServer::handleLogin);
        server.createContext("/logout", WebServer::handleLogout);
        server.createContext("/analyze", WebServer::handleAnalyze);
        server.setExecutor(null);
        server.start();

        System.out.println("=================================================");
        System.out.println(" Fraud Internship Detector is running!");
        System.out.println(" Open this link in your browser:");
        System.out.println();
        System.out.println("     http://localhost:" + port);
        System.out.println();
        System.out.println(" Press Ctrl+C to stop the server.");
        System.out.println("=================================================");
    }

    /**
     * Binds the server to all network interfaces (0.0.0.0) so it can be reached
     * from other devices / the internet, not just this computer.
     *
     * Port priority: PORT environment variable (used by cloud hosts like Render,
     * Railway, Fly.io) -> first CLI argument -> {@link #PORT_CHOICES}.
     */
    private static HttpServer bind(String[] args) throws IOException {
        int[] choices = PORT_CHOICES;
        String envPort = System.getenv("PORT");
        if (envPort != null && envPort.matches("\\d+")) {
            choices = new int[]{Integer.parseInt(envPort.trim())};
        } else if (args.length > 0) {
            try {
                choices = new int[]{Integer.parseInt(args[0].trim())};
            } catch (NumberFormatException ignored) { /* fall back to defaults */ }
        }
        IOException last = null;
        for (int port : choices) {
            try {
                // "0.0.0.0" = listen on every interface, so the tunnel / cloud
                // host / other computers on your Wi-Fi can connect.
                return HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
            } catch (IOException e) {
                last = e;
                System.out.println("Port " + port + " is busy, trying the next one…");
            }
        }
        throw new IOException("No free port found. Try: java WebServer <port>", last);
    }

    // ---------- routes ----------

    /** Login page, or the detector page if already signed in. */
    private static void handleHome(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) { send(ex, 405, "Method not allowed"); return; }
        String user = currentUser(ex);
        send(ex, 200, user == null ? loginPage(null, null) : appPage(user, null));
    }

    /**
     * Single sign-in action: validates the email, then either logs the user in
     * (existing account) or creates the account automatically (new email).
     */
    private static void handleLogin(HttpExchange ex) throws IOException {
        Map<String, String> form = readForm(ex);
        String email = form.getOrDefault("email", "").trim().toLowerCase();
        String pass = form.getOrDefault("password", "");

        // Only allow properly formatted email addresses.
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            send(ex, 200, loginPage("Please enter a valid email like name@example.com", null));
            return;
        }
        if (pass.length() < 6) {
            send(ex, 200, loginPage("Password must be at least 6 characters.", null));
            return;
        }

        if (UserStore.exists(email)) {
            // Existing account → password must match.
            if (!UserStore.validate(email, pass)) {
                send(ex, 200, loginPage("Incorrect password for this email. Please try again.", null));
                return;
            }
        } else {
            // New email → create the account on the spot.
            UserStore.register(email, pass);
        }

        startSession(ex, email);
        redirect(ex, "/");
    }

    private static void startSession(HttpExchange ex, String email) {
        String token = "t" + (tokenSeq++) + "-" + email.hashCode();
        SESSIONS.put(token, email);
        ex.getResponseHeaders().add("Set-Cookie",
                "session=" + token + "; Path=/; HttpOnly");
    }

    private static void handleLogout(HttpExchange ex) throws IOException {
        String token = cookie(ex, "session");
        if (token != null) SESSIONS.remove(token);
        ex.getResponseHeaders().add("Set-Cookie", "session=; Path=/; Max-Age=0");
        redirect(ex, "/");
    }

    private static void handleAnalyze(HttpExchange ex) throws IOException {
        String user = currentUser(ex);
        if (user == null) { redirect(ex, "/"); return; }

        Map<String, String> form = readForm(ex);
        String link = form.getOrDefault("link", "").trim();
        if (link.isEmpty()) {
            send(ex, 200, appPage(user, "<p style='color:#F87171'>Please paste a link first.</p>"));
            return;
        }
        AnalysisResult r = DETECTOR.analyze(link);
        send(ex, 200, appPage(user, reportHtml(r)));
    }

    // ---------- HTML pages ----------

    private static String loginPage(String error, String info) {
        String banner = "";
        if (error != null) banner = "<div class='msg err'>" + esc(error) + "</div>";
        if (info != null)  banner = "<div class='msg ok'>" + esc(info) + "</div>";

        return page("Login", """
            <div class="card auth">
              <div class="logo">🛡</div>
              <h1>Fraud Internship Detector</h1>
              <p class="sub">Sign in to check internship links for scams</p>
              %s
              <form method="post" action="/login">
                <label>Email</label>
                <input type="email" name="email" placeholder="you@example.com"
                  pattern="[A-Za-z0-9._%%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}"
                  title="Enter a valid email like name@example.com" required>
                <label>Password (at least 6 characters)</label>
                <input type="password" name="password" placeholder="••••••"
                  minlength="6" required>
                <button class="primary" type="submit">Continue</button>
              </form>
              <p class="hint">New here? Just enter your email + password and click
                <b>Continue</b> — your account is created automatically.</p>
            </div>
            """.formatted(banner));
    }

    private static String appPage(String user, String reportBlock) {
        String report = reportBlock != null ? reportBlock : """
            <div class="welcome">
              <h3>How it works</h3>
              <p>Paste an internship or company link above and click <b>Analyze Link</b>.
                 The tool checks the web address and the page content for common scam
                 patterns and gives you a risk score.</p>
              <p class="muted">A genuine internship will never ask you to pay a registration /
                 training fee or share your OTP or bank password.</p>
            </div>
            """;

        return page("Detector", """
            <div class="topbar">
              <div class="brand">🛡 Fraud Internship Detector</div>
              <div class="userbox"><span>%s</span>
                <a class="logout" href="/logout">Logout</a></div>
            </div>
            <div class="card">
              <h2>Paste the internship / company link</h2>
              <p class="sub">Example: https://careers.example.com/summer-internship</p>
              <form method="post" action="/analyze" class="linkform">
                <input type="text" name="link" class="link"
                  placeholder="https://..." autofocus>
                <button class="primary" type="submit">Analyze Link</button>
              </form>
            </div>
            <div class="card report">%s</div>
            """.formatted(esc(user), report));
    }

    private static String reportHtml(AnalysisResult r) {
        AnalysisResult.Verdict v = r.verdict();
        String color = switch (v) {
            case GENUINE -> "#4ADE80";
            case SUSPICIOUS -> "#FBBF24";
            case SCAM -> "#F87171";
        };

        StringBuilder b = new StringBuilder();
        b.append("<div class='verdict' style='color:").append(color).append("'>")
         .append(v.icon).append(" ").append(v.label).append("</div>");
        b.append("<div class='score'>Risk score: <b style='color:").append(color)
         .append("'>").append(r.riskScore()).append(" / 100</b></div>");
        b.append("<div class='meter'><div class='fill' style='width:").append(r.riskScore())
         .append("%;background:").append(color).append("'></div></div>");
        b.append("<div class='checked'>Checked: ").append(esc(r.url()))
         .append("<br>").append(esc(r.fetchNote())).append("</div>");

        if (!r.infoNotes().isEmpty()) {
            b.append("<h3 class='info'>🔎 Live checks</h3>");
            b.append(list(r.infoNotes(), "infoitem", ""));
        }

        b.append("<h3 class='flag'>⚠ Warning signs (").append(r.redFlags().size()).append(")</h3>");
        b.append(list(r.redFlags(), "flagitem", "No major warning signs were detected."));

        b.append("<h3 class='trust'>✓ Trust signals (").append(r.trustSignals().size()).append(")</h3>");
        b.append(list(r.trustSignals(), "trustitem", "No clear trust signals were found."));

        String advice = switch (v) {
            case GENUINE -> "<b>Looks reasonable.</b> Still confirm the company on LinkedIn, and never pay a fee or share OTP / bank details to get an internship.";
            case SUSPICIOUS -> "<b>Be careful.</b> Some warning signs were found. Research the company, look for reviews, and do not send money or documents yet.";
            case SCAM -> "<b>High risk — likely a scam.</b> Do NOT pay any fee, share documents, or give OTP/bank details. Genuine internships never ask for money.";
        };
        b.append("<div class='advice'>").append(advice).append("</div>");
        b.append("<div class='disclaimer'>This is an automated heuristic check, not legal proof. Always verify offers independently.</div>");
        return b.toString();
    }

    private static String list(List<String> items, String cls, String empty) {
        if (items.isEmpty()) return "<p class='muted'>" + empty + "</p>";
        StringBuilder sb = new StringBuilder("<ul>");
        for (String s : items) sb.append("<li class='").append(cls).append("'>").append(esc(s)).append("</li>");
        return sb.append("</ul>").toString();
    }

    /** Wraps body content in the full HTML document with shared CSS. */
    private static String page(String title, String body) {
        return """
            <!DOCTYPE html><html><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>%s · Fraud Internship Detector</title>
            <style>
              * { box-sizing: border-box; }
              body { margin:0; font-family:-apple-system,Segoe UI,Roboto,sans-serif;
                     background:#0F172A; color:#E2E8F0; min-height:100vh;
                     display:flex; flex-direction:column; align-items:center; padding:24px; }
              .card { background:#1E293B; border:1px solid #334155; border-radius:14px;
                      padding:24px; width:100%%; max-width:680px; margin-bottom:18px; }
              .auth { max-width:420px; margin-top:6vh; text-align:center; }
              .logo { font-size:46px; color:#38BDF8; }
              h1 { font-size:22px; margin:6px 0 2px; }
              h2 { font-size:17px; margin:0 0 4px; }
              .sub { color:#94A3B8; font-size:13px; margin:0 0 16px; }
              label { display:block; text-align:left; color:#94A3B8; font-size:12px;
                      margin:12px 0 6px; }
              input { width:100%%; padding:11px 12px; border-radius:9px;
                      border:1px solid #334155; background:#0F172A; color:#E2E8F0;
                      font-size:14px; }
              .link { font-family:monospace; }
              button { width:100%%; padding:12px; border:0; border-radius:9px; font-size:14px;
                       font-weight:700; cursor:pointer; margin-top:14px; }
              .primary { background:#38BDF8; color:#0F172A; }
              .ghost { background:transparent; color:#38BDF8; border:1px solid #334155; }
              .hint { color:#64748B; font-size:11px; margin-top:14px; }
              .msg { padding:9px 12px; border-radius:8px; font-size:13px; margin-bottom:6px; }
              .err { background:#3f1d1d; color:#FCA5A5; }
              .ok  { background:#14331f; color:#86EFAC; }
              .topbar { width:100%%; max-width:680px; display:flex; justify-content:space-between;
                        align-items:center; margin-bottom:16px; }
              .brand { font-size:19px; font-weight:700; }
              .userbox { font-size:12px; color:#94A3B8; display:flex; gap:12px; align-items:center; }
              .logout { color:#38BDF8; text-decoration:none; border:1px solid #334155;
                        padding:5px 12px; border-radius:8px; }
              .linkform { display:flex; gap:10px; margin-top:14px; }
              .linkform .link { flex:1; }
              .linkform button { width:auto; margin-top:0; padding:12px 22px; white-space:nowrap; }
              .verdict { font-size:24px; font-weight:800; }
              .score { color:#94A3B8; font-size:13px; margin-top:4px; }
              .meter { background:#0F172A; height:14px; border-radius:7px; overflow:hidden; margin:12px 0; }
              .fill { height:14px; }
              .checked { color:#64748B; font-size:11px; word-break:break-all; }
              .flag { color:#F87171; font-size:15px; margin:18px 0 6px; }
              .trust { color:#4ADE80; font-size:15px; margin:18px 0 6px; }
              .info { color:#38BDF8; font-size:15px; margin:18px 0 6px; }
              ul { margin:6px 0 0; padding-left:20px; }
              .flagitem { color:#FCA5A5; font-size:13px; margin-bottom:5px; }
              .trustitem { color:#86EFAC; font-size:13px; margin-bottom:5px; }
              .infoitem { color:#BAE6FD; font-size:13px; margin-bottom:5px; }
              .muted { color:#64748B; font-size:13px; }
              .advice { background:#0F172A; padding:13px; border-radius:9px; color:#CBD5E1;
                        font-size:13px; margin-top:18px; }
              .disclaimer { color:#475569; font-size:11px; margin-top:12px; }
              .welcome h3 { margin:0 0 8px; } .welcome p { font-size:13px; color:#94A3B8; }

              /* ----- Mobile / small screens ----- */
              @media (max-width: 560px) {
                body { padding:14px; }
                .card { padding:18px; border-radius:12px; }
                .auth { margin-top:3vh; }
                h1 { font-size:20px; }
                .topbar { flex-direction:column; align-items:flex-start; gap:8px; }
                .brand { font-size:17px; }
                /* Stack the link box above the button so both are full width. */
                .linkform { flex-direction:column; }
                .linkform button { width:100%%; padding:14px; }
                input, button { font-size:16px; }   /* 16px stops iOS auto-zoom */
                .verdict { font-size:21px; }
              }
            </style></head><body>%s</body></html>
            """.formatted(esc(title), body);
    }

    // ---------- helpers ----------

    private static String currentUser(HttpExchange ex) {
        String token = cookie(ex, "session");
        return token == null ? null : SESSIONS.get(token);
    }

    private static String cookie(HttpExchange ex, String name) {
        List<String> headers = ex.getRequestHeaders().get("Cookie");
        if (headers == null) return null;
        for (String header : headers) {
            for (String part : header.split(";")) {
                String[] kv = part.trim().split("=", 2);
                if (kv.length == 2 && kv[0].equals(name)) return kv[1];
            }
        }
        return null;
    }

    private static Map<String, String> readForm(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) return Map.of();
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> map = new HashMap<>();
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) continue;
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String val = kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            map.put(key, val);
        }
        return map;
    }

    private static void send(HttpExchange ex, int status, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private static void redirect(HttpExchange ex, String location) throws IOException {
        ex.getResponseHeaders().add("Location", location);
        ex.sendResponseHeaders(303, -1);
        ex.close();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
