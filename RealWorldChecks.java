import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Real-world verification that queries live, authoritative data sources —
 * not just keyword guessing:
 *
 *   1. Domain age      via RDAP (official registry data, no API key needed).
 *   2. SSL certificate inspected directly from the server's TLS handshake.
 *   3. Google Safe Browsing — Google's live phishing/scam blacklist
 *      (optional: enabled when the GSB_API_KEY environment variable is set).
 *
 * Every check has short timeouts and fails gracefully, so the app never hangs
 * or crashes if a service is slow or unreachable.
 */
public class RealWorldChecks {

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(6))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    /** Common second-level labels, so we extract the right registrable domain. */
    private static final Set<String> SECOND_LEVELS =
            Set.of("co", "com", "net", "org", "ac", "gov", "edu", "gob", "or", "ne");

    /** Runs all real-world checks against the given URL. */
    public static void run(URL url, AnalysisResult r) {
        String host = url.getHost() == null ? "" : url.getHost().toLowerCase();
        boolean isIp = host.matches("\\d{1,3}(\\.\\d{1,3}){3}");

        if (!host.isEmpty() && !isIp) {
            checkDomainAge(host, r);
            checkCertificate(host, r);
        }
        checkSafeBrowsing(url.toString(), r);
    }

    // ---------- 1. Domain age (RDAP) ----------

    private static void checkDomainAge(String host, AnalysisResult r) {
        String domain = registrableDomain(host);
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://rdap.org/domain/" + domain))
                    .timeout(Duration.ofSeconds(13))
                    .header("Accept", "application/rdap+json")
                    .GET().build();

            HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                r.addInfo("Domain age: registry lookup unavailable for ."
                        + domain.substring(domain.lastIndexOf('.') + 1) + " (skipped).");
                return;
            }

            Instant registered = parseRegistrationDate(resp.body());
            if (registered == null) {
                r.addInfo("Domain age: registration date not published by the registry.");
                return;
            }

            long days = Duration.between(registered, Instant.now()).toDays();
            String when = registered.atOffset(ZoneOffset.UTC).toLocalDate().toString();
            r.addInfo("Domain " + domain + " was registered on " + when
                    + " (" + humanAge(days) + " ago).");

            // Newer = riskier. Brand-new domains are the #1 sign of a scam site.
            if (days < 30) {
                r.addRisk(35, "Domain is extremely new (under 1 month old) — a major scam indicator.");
            } else if (days < 90) {
                r.addRisk(25, "Domain is very new (under 3 months old).");
            } else if (days < 180) {
                r.addRisk(15, "Domain is fairly new (under 6 months old).");
            } else if (days < 365) {
                r.addRisk(8, "Domain is less than a year old.");
            } else if (days > 365 * 5) {
                r.addTrust(15, "Domain has existed for over 5 years (well-established).");
            } else if (days > 365 * 2) {
                r.addTrust(10, "Domain has existed for over 2 years.");
            }
        } catch (Exception e) {
            r.addInfo("Domain age: could not be checked (" + e.getClass().getSimpleName() + ").");
        }
    }

    private static Instant parseRegistrationDate(String json) {
        // RDAP lists events; the "registration" event holds the creation date.
        // The two fields can appear in either order, so try both.
        Pattern[] patterns = {
            Pattern.compile("\"eventAction\"\\s*:\\s*\"registration\"\\s*,\\s*\"eventDate\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"eventDate\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"eventAction\"\\s*:\\s*\"registration\"")
        };
        for (Pattern p : patterns) {
            Matcher m = p.matcher(json);
            if (m.find()) {
                return parseInstant(m.group(1));
            }
        }
        return null;
    }

    private static Instant parseInstant(String s) {
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (Exception ignore) {
            try {
                return LocalDate.parse(s.substring(0, 10)).atStartOfDay().toInstant(ZoneOffset.UTC);
            } catch (Exception ignore2) {
                return null;
            }
        }
    }

    // ---------- 2. SSL certificate ----------

    private static void checkCertificate(String host, AnalysisResult r) {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, 443), 6000);
            socket.setSoTimeout(6000);

            // Enable SNI + hostname verification so we validate the real cert.
            SSLParameters params = socket.getSSLParameters();
            params.setServerNames(List.of(new SNIHostName(host)));
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);

            socket.startHandshake();
            X509Certificate cert =
                    (X509Certificate) socket.getSession().getPeerCertificates()[0];
            cert.checkValidity(); // throws if expired / not yet valid

            String issuer = cert.getIssuerX500Principal().getName();
            String subject = cert.getSubjectX500Principal().getName();
            if (issuer.equals(subject)) {
                r.addRisk(20, "Uses a self-signed SSL certificate (not from a trusted authority).");
            } else {
                r.addTrust(4, "Has a valid SSL certificate from a trusted authority.");
            }
            r.addInfo("SSL certificate is valid until "
                    + cert.getNotAfter().toInstant().atOffset(ZoneOffset.UTC).toLocalDate() + ".");
        } catch (java.security.cert.CertificateException e) {
            r.addRisk(25, "The site's SSL certificate is invalid, expired, or untrusted.");
        } catch (javax.net.ssl.SSLException e) {
            r.addRisk(18, "Secure (HTTPS) connection could not be verified — certificate problem.");
        } catch (Exception e) {
            r.addInfo("SSL certificate: could not be checked (" + e.getClass().getSimpleName() + ").");
        }
    }

    // ---------- 3. Google Safe Browsing (optional) ----------

    private static void checkSafeBrowsing(String url, AnalysisResult r) {
        String key = safeBrowsingKey();
        if (key == null || key.isBlank()) {
            r.addInfo("Google Safe Browsing: not configured "
                    + "(add your key to gsb_key.txt or set GSB_API_KEY to enable).");
            return;
        }
        try {
            String body = """
                {"client":{"clientId":"fraud-internship-detector","clientVersion":"1.0"},
                 "threatInfo":{
                   "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                   "platformTypes":["ANY_PLATFORM"],
                   "threatEntryTypes":["URL"],
                   "threatEntries":[{"url":"%s"}]}}""".formatted(jsonEscape(url));

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + key))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                r.addInfo("Google Safe Browsing: lookup failed (HTTP " + resp.statusCode() + ").");
                return;
            }
            if (resp.body().contains("\"matches\"")) {
                r.addRisk(50, "Listed on Google Safe Browsing as a dangerous / phishing site.");
            } else {
                r.addTrust(8, "Not listed on Google Safe Browsing's threat database.");
            }
        } catch (Exception e) {
            r.addInfo("Google Safe Browsing: could not be checked (" + e.getClass().getSimpleName() + ").");
        }
    }

    // ---------- helpers ----------

    /**
     * Finds the Google Safe Browsing API key. Looks first in a local
     * "gsb_key.txt" file (easiest for setup), then the GSB_API_KEY env var.
     */
    private static String safeBrowsingKey() {
        try {
            java.nio.file.Path f = java.nio.file.Paths.get("gsb_key.txt");
            if (java.nio.file.Files.exists(f)) {
                String key = java.nio.file.Files.readString(f).trim();
                if (!key.isEmpty()) return key;
            }
        } catch (Exception ignored) { /* fall through to env var */ }
        return System.getenv("GSB_API_KEY");
    }

    /** Reduces a host like "careers.sub.example.co.uk" to "example.co.uk". */
    static String registrableDomain(String host) {
        if (host.startsWith("www.")) host = host.substring(4);
        String[] parts = host.split("\\.");
        if (parts.length <= 2) return host;
        String secondLast = parts[parts.length - 2];
        if (SECOND_LEVELS.contains(secondLast)) {
            return parts[parts.length - 3] + "." + secondLast + "." + parts[parts.length - 1];
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private static String humanAge(long days) {
        if (days < 1) return "less than a day";
        if (days < 60) return days + " day" + (days == 1 ? "" : "s");
        if (days < 730) return (days / 30) + " months";
        return (days / 365) + " years";
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
