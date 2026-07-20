package com.example.chatbot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.x.chatxdk.Chat;
import com.x.chatxdk.Types.PublicKeyRegistrationPayload;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * One-time public-key registration for a bot identity.
 *
 * <p>Registering a public key is a rare, rate-limited write (only a few per 24h
 * per user) that establishes the identity every message is signed and encrypted
 * against. This is re-runnable: if it is interrupted after generating keys but
 * before the server confirms, running it again resumes the same identity instead
 * of minting a new one.
 *
 * <p>Flow:
 * <ol>
 *   <li>Refuse if this identity is already registered (unless {@code --force}).</li>
 *   <li>Generate the keypair once; persist the private-key blob AND the (public)
 *       registration body to disk BEFORE any network call, so an error never
 *       loses the identity and a retry re-sends the same registration.</li>
 *   <li>Before POSTing, check whether this exact public key is already on the
 *       account (a prior POST can apply server-side even after erroring) and
 *       adopt it instead of re-registering — a duplicate POST wastes the budget.</li>
 *   <li>POST the registration; stop cleanly on 429 rather than retrying.</li>
 *   <li>Record the registered key version; optionally back the keys up with a PIN.</li>
 * </ol>
 *
 * <pre>mvn exec:java -Dexec.mainClass=com.example.chatbot.Register -Dexec.args="--confirm"</pre>
 */
public final class Register {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path STATE_DIR = Path.of("state");
    private static final Path BLOB_PATH = STATE_DIR.resolve("private_keys.b64");
    private static final Path MARKER_PATH = STATE_DIR.resolve("registration.json");

    public static void main(String[] args) throws Exception {
        loadDotenv();
        List<String> argList = Arrays.asList(args);
        boolean force = argList.contains("--force");
        if (!argList.contains("--confirm") && !force) {
            System.out.println("This registers a bot identity (a rate-limited, one-time action).");
            System.out.println("Re-run with --confirm when ready:  "
                    + "mvn exec:java -Dexec.mainClass=com.example.chatbot.Register -Dexec.args=--confirm");
            System.exit(1);
            return;
        }
        register(force);
    }

    private static void register(boolean force) throws Exception {
        String token = env("X_ACCESS_TOKEN");
        if (token == null || token.isEmpty()) {
            System.err.println("set X_ACCESS_TOKEN (OAuth2 user token) in the environment or .env");
            System.exit(1);
            return;
        }
        String pin = env("CHAT_PIN");

        JsonNode marker = readMarker();
        if (marker.path("registered").asBoolean(false) && !force) {
            System.err.println("Already registered (version " + marker.path("version").asText("?")
                    + "). Pass --force only if you intend to create a NEW identity.");
            System.exit(1);
            return;
        }

        XChatClient api = new XChatClient(token, envOr("X_API_BASE_URL", "https://api.x.com"));
        String userId = env("CHAT_BOT_USER_ID");
        if (userId == null || userId.isEmpty()) {
            userId = api.getMyUserId();
        }

        try (Chat chat = new Chat()) {
            JsonNode body;
            String version;

            // Resume an interrupted run with the SAME identity; only generate a
            // fresh one when there is no saved blob. Persisting the blob and the
            // registration body before the network POST is what makes a failed
            // POST or Juicebox step safe to retry without wasting the budget.
            boolean resuming = Files.exists(BLOB_PATH) && marker.has("body") && !force;
            if (resuming) {
                chat.importKeys(Base64.getDecoder().decode(Files.readString(BLOB_PATH).trim()));
                body = marker.get("body");
                version = marker.path("version").asText("1");
                System.out.println("Resuming the saved identity (" + BLOB_PATH + ").");
            } else {
                PublicKeyRegistrationPayload payload = chat.generateKeypairs();
                version = payload.version == null ? "1" : payload.version;
                // Only public material goes into the body, so it is safe to
                // persist and re-send on a later run.
                ObjectNode pk = MAPPER.createObjectNode();
                pk.put("public_key", payload.publicKey.publicKey);
                pk.put("signing_public_key", payload.publicKey.signingPublicKey);
                pk.put("identity_public_key_signature", payload.publicKey.identityPublicKeySignature);
                pk.put("signing_public_key_signature", payload.publicKey.signingPublicKeySignature);
                pk.put("registration_method", payload.publicKey.registrationMethod);
                ObjectNode b = MAPPER.createObjectNode();
                b.set("public_key", pk);
                b.put("version", version);
                b.put("generate_version", payload.generateVersion);
                body = b;

                byte[] exported = chat.exportKeys();
                if (exported == null) {
                    throw new IllegalStateException("exportKeys returned nothing — no identity to save");
                }
                saveBlob(Base64.getEncoder().encodeToString(exported));

                ObjectNode m = MAPPER.createObjectNode();
                m.put("registered", false);
                m.put("user_id", userId);
                m.put("version", version);
                m.set("body", body);
                writeMarker(m);
                System.out.println("Generated a new identity; private keys saved to " + BLOB_PATH + ".");
            }

            String ourPublicKey = body.path("public_key").path("public_key").asText();

            // Reconcile: if our exact public key is already on the account, adopt
            // it rather than POSTing again (a prior POST may have applied after
            // erroring).
            JsonNode already = null;
            for (JsonNode k : api.getPublicKeys(userId)) {
                if (!ourPublicKey.isEmpty() && ourPublicKey.equals(k.path("public_key").asText())) {
                    already = k;
                    break;
                }
            }
            if (already != null) {
                version = already.path("public_key_version").asText(version);
                System.out.println("Public key already registered on the account (version "
                        + version + "); skipping POST.");
            } else {
                System.out.println("Registering public key version " + version + " …");
                try {
                    JsonNode resp = api.addUserPublicKey(userId, body);
                    JsonNode data = resp.path("data");
                    if (data.isArray()) {
                        data = data.isEmpty() ? MAPPER.createObjectNode() : data.get(0);
                    }
                    String v = data.path("public_key_version").asText("");
                    if (!v.isEmpty()) {
                        version = v;
                    }
                } catch (XChatClient.RateLimited limited) {
                    String when = limited.resetEpoch != null
                            ? Instant.ofEpochSecond(limited.resetEpoch).toString()
                            : "the next window";
                    System.err.println("Registration is rate limited (429). The daily budget is exhausted; "
                            + "wait until " + when + " and re-run — the saved identity resumes, so no budget is wasted.");
                    System.exit(1);
                    return;
                }
            }

            chat.setIdentity(userId, version);
            ObjectNode done = MAPPER.createObjectNode();
            done.put("registered", true);
            done.put("user_id", userId);
            done.put("version", version);
            done.put("registered_at", Instant.now().toString());
            writeMarker(done);

            // Optional Juicebox backup. The private-key blob is already saved, so
            // this is best-effort: a failure here does not lose the identity.
            if (pin != null && !pin.isEmpty()) {
                try {
                    XChatClient.JuiceboxConfigResult jb = api.getJuiceboxConfig(userId);
                    chat.setup(pin, jb.configJson());
                    System.out.println("Stored the keys in Juicebox under the PIN.");
                } catch (Exception err) {
                    System.err.println("Juicebox backup failed (keys are still saved locally): " + err.getMessage());
                }
            }

            String blob = Files.readString(BLOB_PATH).trim();
            System.out.println();
            System.out.println("Registration complete.");
            System.out.println("  version:      " + version);
            System.out.println("  private keys: " + BLOB_PATH + " (mode 600)");
            System.out.println("Add these to .env to run the bot:");
            System.out.println("  CHAT_PRIVATE_KEYS_B64=" + blob);
            System.out.println("  CHAT_SIGNING_KEY_VERSION=" + version);
        }
    }

    private static JsonNode readMarker() {
        try {
            return MAPPER.readTree(Files.readString(MARKER_PATH));
        } catch (Exception e) {
            return MAPPER.createObjectNode();
        }
    }

    private static void writeMarker(JsonNode marker) throws Exception {
        Files.createDirectories(STATE_DIR);
        Files.writeString(MARKER_PATH,
                MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(marker) + "\n");
    }

    /** Write the exported private keys to disk (owner-only where POSIX allows). */
    private static void saveBlob(String blob) throws Exception {
        Files.createDirectories(STATE_DIR);
        Files.writeString(BLOB_PATH, blob + "\n");
        try {
            Files.setPosixFilePermissions(BLOB_PATH, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystem (e.g. Windows) — best effort.
        }
    }

    // Reads an environment variable, falling back to a system property set by
    // the .env loader (the JVM cannot mutate the process environment).
    private static String env(String key) {
        String v = System.getenv(key);
        return (v == null || v.isEmpty()) ? System.getProperty(key) : v;
    }

    private static String envOr(String key, String fallback) {
        String v = env(key);
        return (v == null || v.isEmpty()) ? fallback : v;
    }

    /** Tiny .env loader so the example has no extra dependencies. */
    private static void loadDotenv() throws Exception {
        Path path = Path.of(".env");
        if (!Files.exists(path)) {
            return;
        }
        for (String line : Files.readAllLines(path)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#") || !t.contains("=")) {
                continue;
            }
            int idx = t.indexOf('=');
            String key = t.substring(0, idx).trim();
            String value = t.substring(idx + 1).trim();
            if (System.getenv(key) == null) {
                System.setProperty(key, value);
            }
        }
    }
}
