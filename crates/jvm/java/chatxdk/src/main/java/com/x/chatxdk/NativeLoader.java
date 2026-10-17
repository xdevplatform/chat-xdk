package com.x.chatxdk;

import com.sun.jna.Native;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * Loads the {@code chat_xdk_dotnet} cdylib for JNA.
 *
 * <p>Published JARs embed per-platform natives under {@code /native/<rid>/}. On first use the
 * matching library is extracted to a temp directory and loaded by absolute path. When no embedded
 * library is present (local development), falls back to the normal JNA search path ({@code
 * jna.library.path}, {@code java.library.path}, and the process environment).
 */
final class NativeLoader {

    private static final String LIB_BASENAME = "chat_xdk_dotnet";

    private NativeLoader() {}

    static ChatNative load() {
        try {
            Path extracted = extractBundledLibrary();
            if (extracted != null) {
                return Native.load(extracted.toAbsolutePath().toString(), ChatNative.class);
            }
        } catch (IOException | UnsatisfiedLinkError e) {
            // Fall through to system / jna.library.path lookup.
        }
        return Native.load(LIB_BASENAME, ChatNative.class);
    }

    /**
     * @return absolute path to an extracted library, or {@code null} if this JAR has no embedded
     *     native for the current platform
     */
    private static Path extractBundledLibrary() throws IOException {
        String rid = detectRid();
        if (rid == null) {
            return null;
        }
        String fileName = libraryFileName(rid);
        String resource = "/native/" + rid + "/" + fileName;
        InputStream in = NativeLoader.class.getResourceAsStream(resource);
        if (in == null) {
            return null;
        }
        Path dir = Files.createTempDirectory("chatxdk-native-");
        Path out = dir.resolve(fileName);
        try (InputStream stream = in) {
            Files.copy(stream, out, StandardCopyOption.REPLACE_EXISTING);
        }
        out.toFile().setReadable(true);
        out.toFile().setExecutable(true);
        out.toFile().deleteOnExit();
        dir.toFile().deleteOnExit();
        return out;
    }

    /** RID labels aligned with the .NET / CI matrix: osx-arm64, osx-x64, linux-x64, linux-arm64, win-x64. */
    static String detectRid() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        boolean arm = arch.equals("aarch64") || arch.equals("arm64");
        boolean x64 = arch.equals("x86_64") || arch.equals("amd64") || arch.equals("x64");

        if (os.contains("mac")) {
            if (arm) {
                return "osx-arm64";
            }
            if (x64) {
                return "osx-x64";
            }
        } else if (os.contains("linux")) {
            if (arm) {
                return "linux-arm64";
            }
            if (x64) {
                return "linux-x64";
            }
        } else if (os.contains("win")) {
            if (x64) {
                return "win-x64";
            }
        }
        return null;
    }

    static String libraryFileName(String rid) {
        switch (rid) {
            case "osx-arm64":
            case "osx-x64":
                return "lib" + LIB_BASENAME + ".dylib";
            case "linux-x64":
                return "lib" + LIB_BASENAME + ".so";
            case "win-x64":
                return LIB_BASENAME + ".dll";
            default:
                throw new IllegalArgumentException("unsupported rid: " + rid);
        }
    }
}
