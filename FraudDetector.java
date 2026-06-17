import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

/**
 * The core fraud-detection engine.
 *
 * It scores an internship link using two kinds of checks:
 *   1. URL / domain heuristics  (no network needed)
 *   2. Page-content heuristics   (fetches the page and scans the text)
 *
 * The score is a rough risk estimate, NOT a guarantee. It is meant to warn
 * students about common scam patterns so they look closer before paying or
 * sharing personal documents.
 */
public class FraudDetector {

    /** Cheap/abused top-level domains often used for throwaway scam sites. */
    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
            "xyz", "top", "club", "online", "site", "website", "work", "click",
            "link", "gq", "cf", "ml", "ga", "tk", "buzz", "fit", "rest", "loan",
            "country", "kim", "men", "stream", "download", "racing", "win"
    ));

    /** Free hosting / page builders — fine for hobby sites, red flag for a "company". */
    private static final String[] FREE_HOSTS = {
            "blogspot.", "wordpress.com", "weebly.com", "wixsite.com", "wix.com",
            "000webhost", "github.io", "netlify.app", "glitch.me", "godaddysites.com",
            "mystrikingly.com", "webflow.io", "carrd.co", "yolasite.com"
    };

    /** URL shorteners hide the real destination. */
    private static final String[] SHORTENERS = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
            "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.me"
    };

    /** Phrases strongly associated with internship / job scams. */
    private static final String[][] SCAM_PHRASES = {
            {"registration fee", "20"}, {"registration charge", "20"},
            {"security deposit", "22"},  {"refundable deposit", "20"},
            {"processing fee", "18"},    {"training fee", "18"},
            {"pay to apply", "22"},      {"application fee", "18"},
            {"pay ", "6"},               {"upfront payment", "20"},
            {"100% guaranteed", "15"},   {"guaranteed job", "15"},
            {"guaranteed placement", "15"}, {"guaranteed income", "12"},
            {"no experience required", "8"}, {"no interview", "10"},
            {"work from home", "5"},     {"earn money from home", "10"},
            {"earn upto", "8"},          {"earn up to", "8"},
            {"per day", "6"},            {"per week", "5"},
            {"limited seats", "8"},      {"hurry", "6"}, {"act now", "6"},
            {"western union", "25"},     {"gift card", "22"},
            {"bitcoin", "15"},           {"crypto payment", "15"},
            {"send your aadhaar", "18"}, {"share your otp", "30"},
            {"bank details", "10"},      {"contact on whatsapp", "12"},
            {"whatsapp only", "15"},     {"telegram", "8"},
            {"selected candidate", "5"}, {"congratulations you", "8"}
    };

    /** Phrases that suggest a more legitimate, established organisation. */
    private static final String[][] TRUST_PHRASES = {
            {"privacy policy", "6"},     {"terms and conditions", "5"},
            {"terms of service", "5"},   {"about us", "4"},
            {"careers", "4"},            {"company registration", "8"},
            {"cin:", "8"},               {"gstin", "6"},
            {"linkedin.com/company", "8"}, {"glassdoor", "6"},
            {"registered office", "8"},  {"equal opportunity", "5"},
            {"stipend", "3"}
    };

    private static final Pattern IP_HOST =
            Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    /** Personal/free email providers — odd for an official recruiting domain. */
    private static final String[] FREE_EMAIL = {
            "@gmail.", "@yahoo.", "@hotmail.", "@outlook.", "@rediffmail.", "@ymail."
    };

    /**
     * Runs the full analysis. Network failures are handled gracefully —
     * URL-only checks still run so the user always gets a verdict.
     */
    public AnalysisResult analyze(String rawUrl) {
        String input = rawUrl == null ? "" : rawUrl.trim();
        // Be forgiving: add https:// if the user pasted a bare domain.
        if (!input.matches("(?i)^[a-z]+://.*")) {
            input = "https://" + input;
        }

        AnalysisResult result = new AnalysisResult(input);

        URL parsed;
        try {
            parsed = URI.create(input).toURL();
        } catch (Exception e) {
            result.addRisk(40, "The link is not a valid web address.");
            return result;
        }

        analyzeUrl(parsed, result);
        // Real-world checks against live registry / certificate / blacklist data.
        RealWorldChecks.run(parsed, result);
        analyzeContent(parsed, result);
        return result;
    }

    // ---------- URL / domain heuristics ----------

    private void analyzeUrl(URL url, AnalysisResult r) {
        String host = url.getHost() == null ? "" : url.getHost().toLowerCase();
        String full = url.toString().toLowerCase();

        if ("http".equalsIgnoreCase(url.getProtocol())) {
            r.addRisk(12, "Uses insecure HTTP (no HTTPS encryption).");
        } else {
            r.addTrust(3, "Uses a secure HTTPS connection.");
        }

        if (IP_HOST.matcher(host).matches()) {
            r.addRisk(25, "The site is hosted on a raw IP address instead of a domain name.");
        }

        for (String s : SHORTENERS) {
            if (host.equals(s) || host.endsWith("." + s)) {
                r.addRisk(20, "Uses a link shortener (" + s + ") that hides the real destination.");
                break;
            }
        }

        for (String f : FREE_HOSTS) {
            if (host.contains(f)) {
                r.addRisk(15, "Hosted on a free website builder (" + f + "), unusual for a real company.");
                break;
            }
        }

        String tld = host.contains(".") ? host.substring(host.lastIndexOf('.') + 1) : "";
        if (SUSPICIOUS_TLDS.contains(tld)) {
            r.addRisk(14, "Uses a cheap/often-abused domain ending (." + tld + ").");
        }

        // Lots of hyphens or digits in the domain is a common phishing trait.
        String domain = host.startsWith("www.") ? host.substring(4) : host;
        long hyphens = domain.chars().filter(c -> c == '-').count();
        if (hyphens >= 2) {
            r.addRisk(8, "Domain name contains several hyphens (" + hyphens + ").");
        }
        long digits = domain.chars().filter(Character::isDigit).count();
        if (digits >= 4) {
            r.addRisk(6, "Domain name contains many digits.");
        }

        // Brand names used as a subdomain to look official, e.g. google.scam-site.xyz
        String[] brands = {"google", "amazon", "microsoft", "infosys", "tcs", "wipro",
                "internshala", "linkedin", "naukri", "accenture"};
        for (String brand : brands) {
            if (domain.contains(brand) && !domain.startsWith(brand + ".")
                    && !domain.equals(brand + ".com")) {
                r.addRisk(10, "Domain imitates a well-known brand name (\"" + brand + "\").");
                break;
            }
        }

        // Suspicious words baked into the URL path.
        for (String word : new String[]{"register-fee", "payment", "deposit", "verify-otp"}) {
            if (full.contains(word)) {
                r.addRisk(8, "The link itself references \"" + word + "\".");
            }
        }
    }

    // ---------- Page content heuristics ----------

    private void analyzeContent(URL url, AnalysisResult r) {
        String body = fetch(url, r);
        if (body == null) {
            return; // fetch() already recorded why and adjusted risk.
        }

        String text = body.toLowerCase();

        for (String[] entry : SCAM_PHRASES) {
            if (text.contains(entry[0])) {
                r.addRisk(Integer.parseInt(entry[1]),
                        "Page mentions \"" + entry[0].trim() + "\" — a common scam signal.");
            }
        }

        for (String[] entry : TRUST_PHRASES) {
            if (text.contains(entry[0])) {
                r.addTrust(Integer.parseInt(entry[1]),
                        "Page includes \"" + entry[0].trim() + "\" (a sign of a real organisation).");
            }
        }

        // Contact only via personal/free email is suspicious for a recruiter.
        for (String fe : FREE_EMAIL) {
            if (text.contains(fe)) {
                r.addRisk(10, "Recruiter contact uses a personal email address (" + fe.substring(1) + "...).");
                break;
            }
        }

        // A real careers page almost always has an apply form; a one-line
        // "send money / contact WhatsApp" page does not.
        if (text.length() < 600) {
            r.addRisk(8, "The page has very little content — typical of a throwaway scam page.");
        }
    }

    /** Fetches page HTML with short timeouts. Returns null if unreachable. */
    private String fetch(URL url, AnalysisResult r) {
        try {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(8))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(url.toURI())
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent",
                            "Mozilla/5.0 (compatible; InternshipFraudDetector/1.0)")
                    .GET()
                    .build();

            HttpResponse<String> response =
                    client.send(request, HttpResponse.BodyHandlers.ofString());

            int code = response.statusCode();
            if (code >= 400) {
                r.addRisk(12, "Server returned an error (HTTP " + code + ").");
                r.setReachable(false);
                r.setFetchNote("Site responded with HTTP " + code + ".");
                return null;
            }
            r.setFetchNote("Fetched page successfully (HTTP " + code + ").");
            return response.body();

        } catch (IOException | InterruptedException | java.net.URISyntaxException e) {
            r.setReachable(false);
            r.addRisk(10, "The website could not be reached — it may be offline or fake.");
            r.setFetchNote("Could not connect: " + e.getClass().getSimpleName()
                    + ". Only the link itself was analysed.");
            return null;
        }
    }
}
