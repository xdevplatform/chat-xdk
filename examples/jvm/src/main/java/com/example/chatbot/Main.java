package com.example.chatbot;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Open-source, standalone chat-xdk example bot on the JVM.
 *
 * <p>Flow (encrypt on send, decrypt on receive): load keys -&gt; batch-decrypt the backlog
 * -&gt; poll for new events -&gt; decrypt each -&gt; reply -&gt; encrypt + sign -&gt; send.
 *
 * <pre>mvn exec:java -Dexec.mainClass=com.example.chatbot.Main</pre>
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        loadDotenv();

        try (ChatCore core = new ChatCore()) {
            String privateKeys = env("CHAT_PRIVATE_KEYS_B64");
            if (privateKeys == null || privateKeys.isEmpty()) {
                ChatCore.Generated gen = core.generateAndRegister();
                ObjectMapper mapper = new ObjectMapper();
                System.out.println("No CHAT_PRIVATE_KEYS_B64 set — generated a new identity.\n");
                System.out.println("1) Register this public key with the X API (one-time provisioning):");
                System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(gen.registration().publicKey));
                System.out.println("\n2) Save this in your .env so the bot reuses the identity:");
                System.out.println("CHAT_PRIVATE_KEYS_B64=" + gen.privateKeysB64());
                return;
            }

            String version = envOr("CHAT_SIGNING_KEY_VERSION", "1");
            core.loadKeys(privateKeys, version);

            String accessToken = env("X_ACCESS_TOKEN");
            String conversationId = env("CHAT_CONVERSATION_ID");
            if (accessToken == null || conversationId == null) {
                System.out.println("Set X_ACCESS_TOKEN and CHAT_CONVERSATION_ID in .env to run the bot.");
                return;
            }

            XChatClient api = new XChatClient(accessToken, envOr("X_API_BASE_URL", "https://api.x.com"));
            String botUserId = env("CHAT_BOT_USER_ID");
            if (botUserId == null || botUserId.isEmpty()) {
                botUserId = api.getMyUserId();
            }

            new Bot(core, api, botUserId).run(conversationId, 3000);
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
        if (!Files.exists(path)) return;
        for (String line : Files.readAllLines(path)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#") || !t.contains("=")) continue;
            int idx = t.indexOf('=');
            String key = t.substring(0, idx).trim();
            String value = t.substring(idx + 1).trim();
            if (System.getenv(key) == null) {
                System.setProperty(key, value);
            }
        }
    }
}
