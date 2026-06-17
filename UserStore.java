import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Very small file-backed user store for the login page.
 *
 * Credentials are saved to "users.txt" next to the app as:
 *     email<TAB>sha256(password)
 *
 * NOTE: This is a learning/demo project. SHA-256 with no salt is good enough
 * to avoid storing plain-text passwords, but a real product should use a
 * dedicated password hash such as bcrypt/argon2.
 */
public class UserStore {

    private static final Path FILE = Paths.get("users.txt");

    /** Returns true if the email is already registered. */
    public static boolean exists(String email) {
        return readAll().containsKey(normalize(email));
    }

    /**
     * Registers a new user.
     * @return true on success, false if the email already exists.
     */
    public static boolean register(String email, String password) {
        email = normalize(email);
        Map<String, String> users = readAll();
        if (users.containsKey(email)) {
            return false;
        }
        users.put(email, hash(password));
        writeAll(users);
        return true;
    }

    /** Returns true if the email/password pair matches a stored user. */
    public static boolean validate(String email, String password) {
        String stored = readAll().get(normalize(email));
        return stored != null && stored.equals(hash(password));
    }

    // ----- helpers -----

    private static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private static Map<String, String> readAll() {
        Map<String, String> users = new LinkedHashMap<>();
        if (!Files.exists(FILE)) {
            return users;
        }
        try {
            for (String line : Files.readAllLines(FILE, StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab > 0) {
                    users.put(line.substring(0, tab), line.substring(tab + 1));
                }
            }
        } catch (IOException e) {
            System.err.println("Could not read users file: " + e.getMessage());
        }
        return users;
    }

    private static void writeAll(Map<String, String> users) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : users.entrySet()) {
            sb.append(e.getKey()).append('\t').append(e.getValue()).append('\n');
        }
        try {
            Files.write(FILE, sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            System.err.println("Could not save users file: " + e.getMessage());
        }
    }

    private static String hash(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            // SHA-256 is always available; this should never happen.
            throw new RuntimeException(e);
        }
    }
}
