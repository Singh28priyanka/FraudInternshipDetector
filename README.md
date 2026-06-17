# 🛡 Fraud Internship Detector

**🔗 Live app: https://fraud-internship-detector.onrender.com**
*(Free hosting — the first visit after a quiet period may take ~30–60s to wake up.)*

A Java app that helps students check whether an internship offer or company
website is **genuine** or a **scam**. You log in, paste the link of the site,
and the app analyses it and returns a risk score with the exact warning signs
it found. It runs both as a **website** and as a **desktop (Swing) app**.

> ⚠️ This is an automated heuristic tool, **not** legal proof. It flags common
> scam patterns so you look closer before paying money or sharing documents.

## Features

- **Login page** with email + password (create an account, then sign in).
  Passwords are stored hashed (SHA-256) in a local `users.txt`, never in plain text.
- **Paste-a-link section** — paste any internship / company URL.
- **Fraud analysis engine** that checks:
  - **Real-world live data** (not just keywords):
    - **Domain age** via RDAP — official registry data, no API key. Brand-new
      domains (days/weeks old) are the strongest scam signal.
    - **SSL certificate** inspected from the live TLS handshake — validity,
      trusted issuer, self-signed detection.
    - **Google Safe Browsing** — Google's live phishing/scam blacklist
      (optional; enabled by setting the `GSB_API_KEY` environment variable).
  - The web address: HTTP vs HTTPS, raw-IP hosts, link shorteners, free site
    builders, cheap/abused domain endings, brand-imitation domains, suspicious
    URL paths.
  - The page content: scam phrases ("registration fee", "security deposit",
    "guaranteed job", "share your OTP", "pay on WhatsApp", …) and trust signals
    ("privacy policy", "company registration", "LinkedIn company page", …).
- **Result report**: a verdict (✅ Likely Genuine / ⚠ Suspicious / 🚫 Likely Scam),
  a 0–100 risk score with meter, the list of red flags, trust signals, and advice.

## Requirements

- Java 17 or newer (uses the built-in `java.net.http` client and switch expressions).
  Check with: `java -version`

No external libraries or build tools are needed.

## Run it

There are two ways to use the app — a **browser (localhost) version** and a
**desktop window version**. Both share the same accounts and detection engine.

### 🌐 Web version (opens at a localhost link)

**macOS / Linux**
```bash
./web.sh
```
**Windows**
```bat
web.bat
```
**Or manually**
```bash
javac *.java
java WebServer            # then open the printed link in your browser
java WebServer 9000       # optional: choose a specific port
```
Then open the link it prints, e.g. **http://localhost:8090**, in your browser.
(If 8090 is busy it automatically tries the next free port.)

### 🖥 Desktop window version (Swing)

**macOS / Linux**
```bash
./run.sh
```
**Windows**
```bat
run.bat
```
**Or manually**
```bash
javac *.java
java Main
```

## Optional: turn on Google Safe Browsing

The app already checks domain age and SSL with no setup. To also check Google's
live blacklist of known phishing/scam sites:

1. Get a free API key from the Google Cloud console (enable the
   **Safe Browsing API**).
2. Set it before running:
   ```bash
   export GSB_API_KEY=your_key_here     # macOS/Linux
   ./web.sh
   ```
   ```bat
   set GSB_API_KEY=your_key_here        REM Windows
   web.bat
   ```

Without a key, this one check is simply skipped (the report says so).

## How to use

1. On the login screen, enter an email + password and click **Create an account**.
2. Click **Login**.
3. Paste an internship/company link into the box and click **Analyze Link**.
4. Read the verdict, risk score, and the warning signs / trust signals.

## Project structure

| File | Purpose |
|------|---------|
| `WebServer.java` | **Web version** — serves the app at a localhost link. |
| `Main.java` | Desktop entry point; launches the login window. |
| `LoginFrame.java` | Desktop login / registration UI. |
| `DetectorFrame.java` | Desktop main screen: paste-link section + report. |
| `FraudDetector.java` | The detection engine (URL + content heuristics). |
| `AnalysisResult.java` | Result model: score, verdict, flags, signals. |
| `UserStore.java` | File-backed user accounts (hashed passwords). |

## Golden rule for students

A **genuine internship never asks you to pay** a registration / training /
security fee, and never needs your OTP or bank password. If a link does — treat
it as a scam, no matter how official it looks.
