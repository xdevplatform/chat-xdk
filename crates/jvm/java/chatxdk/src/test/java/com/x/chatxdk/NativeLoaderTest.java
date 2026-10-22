package com.x.chatxdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Which bundled native NativeLoader picks for the os.name / os.arch a JVM reports. */
class NativeLoaderTest {

    /** Every platform the release jar bundles a native for resolves to that native's file. */
    @Test
    void releasedPlatformsResolveToTheirBundledLibrary() {
        String[][] platforms = {
            {"Mac OS X", "aarch64", "osx-arm64", "libchat_xdk_dotnet.dylib"},
            {"Mac OS X", "x86_64", "osx-x64", "libchat_xdk_dotnet.dylib"},
            {"Linux", "amd64", "linux-x64", "libchat_xdk_dotnet.so"},
            {"Linux", "aarch64", "linux-arm64", "libchat_xdk_dotnet.so"},
            {"Windows 11", "amd64", "win-x64", "chat_xdk_dotnet.dll"},
        };
        for (String[] p : platforms) {
            String rid = NativeLoader.detectRid(p[0], p[1]);
            assertEquals(p[2], rid, p[0] + " " + p[1]);
            assertEquals(p[3], NativeLoader.libraryFileName(rid), rid);
        }
    }

    /** With no bundled native, load() falls back to the JNA search path instead of failing. */
    @Test
    void otherPlatformsHaveNoBundledLibrary() {
        assertNull(NativeLoader.detectRid("Windows 11", "aarch64"));
        assertNull(NativeLoader.detectRid("Linux", "arm"));
        assertNull(NativeLoader.detectRid("FreeBSD", "amd64"));
    }
}
