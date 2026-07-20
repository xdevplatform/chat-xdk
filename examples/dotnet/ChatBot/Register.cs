using System.Text.Json;
using ChatXdk;

namespace ChatBot;

/// <summary>
/// One-time public-key registration for a bot identity.
///
/// <para>Registering a public key is a rare, rate-limited write (only a few per
/// 24h per user) that establishes the identity every message is signed and
/// encrypted against. This is re-runnable: if it is interrupted after generating
/// keys but before the server confirms, running it again resumes the same
/// identity instead of minting a new one.</para>
///
/// <para>Flow:</para>
/// <list type="number">
///   <item>Refuse if this identity is already registered (unless <c>--force</c>).</item>
///   <item>Generate the keypair once; persist the private-key blob AND the
///     (public) registration body to disk BEFORE any network call, so an error
///     never loses the identity and a retry re-sends the same registration.</item>
///   <item>Before POSTing, check whether this exact public key is already on the
///     account (a prior POST can apply server-side even after erroring) and adopt
///     it instead of re-registering — a duplicate POST wastes the daily budget.</item>
///   <item>POST the registration; stop cleanly on 429 rather than retrying.</item>
///   <item>Record the registered key version; optionally back the keys up with a PIN.</item>
/// </list>
///
/// <para>Reachable via <c>dotnet run --project ChatBot register</c>.</para>
/// </summary>
public static class Register
{
    private const string StateDir = "state";
    private static string BlobPath => Path.Combine(StateDir, "private_keys.b64");
    private static string MarkerPath => Path.Combine(StateDir, "registration.json");

    public static async Task RunAsync(string[] args)
    {
        var force = args.Contains("--force");
        if (!args.Contains("--confirm") && !force)
        {
            Console.WriteLine("This registers a bot identity (a rate-limited, one-time action).");
            Console.WriteLine("Re-run with --confirm when ready:  dotnet run --project ChatBot register --confirm");
            Environment.Exit(1);
            return;
        }

        var token = Environment.GetEnvironmentVariable("X_ACCESS_TOKEN");
        if (string.IsNullOrEmpty(token))
        {
            Console.Error.WriteLine("set X_ACCESS_TOKEN (OAuth2 user token) in the environment or .env");
            Environment.Exit(1);
            return;
        }
        var pin = Environment.GetEnvironmentVariable("CHAT_PIN");

        var marker = ReadMarker();
        if (marker.TryGetProperty("registered", out var reg) && reg.ValueKind == JsonValueKind.True && !force)
        {
            var v = marker.TryGetProperty("version", out var mv) ? mv.GetString() : "?";
            Console.Error.WriteLine($"Already registered (version {v}). Pass --force only if you intend to create a NEW identity.");
            Environment.Exit(1);
            return;
        }

        var api = new XChatClient(token, Environment.GetEnvironmentVariable("X_API_BASE_URL") ?? "https://api.x.com");
        var userId = Environment.GetEnvironmentVariable("CHAT_BOT_USER_ID");
        if (string.IsNullOrEmpty(userId))
            userId = await api.GetMyUserIdAsync();

        using var chat = new Chat();

        // Resume an interrupted run with the SAME identity; only generate a fresh
        // one when there is no saved blob. Persisting the blob and the
        // registration body before the network POST is what makes a failed POST
        // or Juicebox step safe to retry without wasting the daily budget.
        object bodyToPost;
        string ourPublicKey;
        string version;
        var resuming = File.Exists(BlobPath)
            && marker.TryGetProperty("body", out _)
            && !force;
        if (resuming)
        {
            chat.ImportKeys(Convert.FromBase64String(File.ReadAllText(BlobPath).Trim()));
            var savedBody = marker.GetProperty("body");
            bodyToPost = savedBody;
            ourPublicKey = savedBody.GetProperty("public_key").GetProperty("public_key").GetString() ?? "";
            version = marker.TryGetProperty("version", out var mv) ? mv.GetString() ?? "1" : "1";
            Console.WriteLine($"Resuming the saved identity ({BlobPath}).");
        }
        else
        {
            var payload = chat.GenerateKeypairs();
            version = payload.Version ?? "1";
            ourPublicKey = payload.PublicKey.PublicKey;
            // Only public material goes into the body, so it is safe to persist
            // and re-send on a later run.
            var body = new Dictionary<string, object?>
            {
                ["public_key"] = new Dictionary<string, object?>
                {
                    ["public_key"] = payload.PublicKey.PublicKey,
                    ["signing_public_key"] = payload.PublicKey.SigningPublicKey,
                    ["identity_public_key_signature"] = payload.PublicKey.IdentityPublicKeySignature,
                    ["signing_public_key_signature"] = payload.PublicKey.SigningPublicKeySignature,
                    ["registration_method"] = payload.PublicKey.RegistrationMethod,
                },
                ["version"] = version,
                ["generate_version"] = payload.GenerateVersion,
            };
            bodyToPost = body;
            var exported = chat.ExportKeys() ?? throw new InvalidOperationException("export_keys returned nothing — no identity to save");
            SaveBlob(Convert.ToBase64String(exported));
            WriteMarker(new Dictionary<string, object?>
            {
                ["registered"] = false,
                ["user_id"] = userId,
                ["version"] = version,
                ["body"] = body,
            });
            Console.WriteLine($"Generated a new identity; private keys saved to {BlobPath}.");
        }

        // Reconcile: if our exact public key is already on the account, adopt it
        // rather than POSTing again (a prior POST may have applied after erroring).
        var existing = await api.GetPublicKeysAsync(userId);
        var already = existing.FirstOrDefault(k =>
            k.TryGetProperty("public_key", out var pk) && pk.GetString() == ourPublicKey);
        if (already.ValueKind == JsonValueKind.Object)
        {
            if (already.TryGetProperty("public_key_version", out var av))
                version = av.ValueKind == JsonValueKind.String ? av.GetString() ?? version : av.ToString();
            Console.WriteLine($"Public key already registered on the account (version {version}); skipping POST.");
        }
        else
        {
            Console.WriteLine($"Registering public key version {version} …");
            try
            {
                var resp = await api.AddUserPublicKeyAsync(userId, bodyToPost);
                version = VersionFromResponse(resp) ?? version;
            }
            catch (RateLimitedException limited)
            {
                var when = limited.ResetEpoch is long epoch
                    ? DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime.ToString("o")
                    : "the next window";
                Console.Error.WriteLine(
                    "Registration is rate limited (429). The daily budget is exhausted; " +
                    $"wait until {when} and re-run — the saved identity resumes, so no budget is wasted.");
                Environment.Exit(1);
                return;
            }
        }

        chat.SetIdentity(userId, version);
        WriteMarker(new Dictionary<string, object?>
        {
            ["registered"] = true,
            ["user_id"] = userId,
            ["version"] = version,
            ["registered_at"] = DateTimeOffset.UtcNow.ToString("o"),
        });

        // Optional Juicebox backup. The private-key blob is already saved, so
        // this is best-effort: a failure here does not lose the identity.
        if (!string.IsNullOrEmpty(pin))
        {
            try
            {
                var (configJson, _) = await api.GetJuiceboxConfigAsync(userId);
                chat.Setup(pin, configJson);
                Console.WriteLine("Stored the keys in Juicebox under the PIN.");
            }
            catch (Exception err)
            {
                Console.Error.WriteLine($"Juicebox backup failed (keys are still saved locally): {err.Message}");
            }
        }

        var blob = File.ReadAllText(BlobPath).Trim();
        Console.WriteLine();
        Console.WriteLine("Registration complete.");
        Console.WriteLine($"  version:      {version}");
        Console.WriteLine($"  private keys: {BlobPath} (mode 600)");
        Console.WriteLine("Add these to .env to run the bot:");
        Console.WriteLine($"  CHAT_PRIVATE_KEYS_B64={blob}");
        Console.WriteLine($"  CHAT_SIGNING_KEY_VERSION={version}");
    }

    private static JsonElement ReadMarker()
    {
        // An Object-kind element (not default/Undefined) so callers can use
        // TryGetProperty without a ValueKind guard on the first run.
        if (!File.Exists(MarkerPath)) return EmptyObject();
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(MarkerPath));
            return doc.RootElement.Clone();
        }
        catch
        {
            return EmptyObject();
        }
    }

    private static JsonElement EmptyObject()
    {
        using var doc = JsonDocument.Parse("{}");
        return doc.RootElement.Clone();
    }

    private static void WriteMarker(Dictionary<string, object?> marker)
    {
        Directory.CreateDirectory(StateDir);
        File.WriteAllText(MarkerPath,
            JsonSerializer.Serialize(marker, new JsonSerializerOptions { WriteIndented = true }) + "\n");
    }

    /// <summary>Write the exported private keys to disk (owner-only on unix).</summary>
    private static void SaveBlob(string blob)
    {
        Directory.CreateDirectory(StateDir);
        File.WriteAllText(BlobPath, blob + "\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(BlobPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static string? VersionFromResponse(JsonElement resp)
    {
        if (resp.ValueKind != JsonValueKind.Object || !resp.TryGetProperty("data", out var data))
            return null;
        if (data.ValueKind == JsonValueKind.Array)
            data = data.EnumerateArray().FirstOrDefault();
        if (data.ValueKind != JsonValueKind.Object)
            return null;
        if (data.TryGetProperty("public_key_version", out var pv) && pv.ValueKind == JsonValueKind.String)
            return pv.GetString();
        return null;
    }
}
