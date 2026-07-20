using System.Text.Json;
using ChatBot;

// Open-source, standalone chat-xdk example bot in .NET.
//
// Flow (encrypt on send, decrypt on receive): load keys -> batch-decrypt the backlog ->
// poll for new events -> decrypt each -> reply -> encrypt + sign -> send.
//
//   dotnet run

LoadDotenv();

// One-time public-key registration: `dotnet run --project ChatBot register`.
if (args.Length > 0 && args[0] == "register")
{
    await Register.RunAsync(args.Skip(1).ToArray());
    return;
}

string? EnvOr(string key) => Environment.GetEnvironmentVariable(key);

using var core = new ChatCore();

var privateKeys = EnvOr("CHAT_PRIVATE_KEYS_B64");
if (string.IsNullOrEmpty(privateKeys))
{
    var (registration, blob) = core.GenerateAndRegister();
    Console.WriteLine("No CHAT_PRIVATE_KEYS_B64 set — generated a new identity.\n");
    Console.WriteLine("1) Register this public key with the X API (one-time provisioning):");
    Console.WriteLine(JsonSerializer.Serialize(registration.PublicKey, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine("\n2) Save this in your .env so the bot reuses the identity:");
    Console.WriteLine($"CHAT_PRIVATE_KEYS_B64={blob}");
    return;
}

core.LoadKeys(privateKeys, EnvOr("CHAT_SIGNING_KEY_VERSION") ?? "1");

var accessToken = EnvOr("X_ACCESS_TOKEN");
var conversationId = EnvOr("CHAT_CONVERSATION_ID");
if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(conversationId))
{
    Console.WriteLine("Set X_ACCESS_TOKEN and CHAT_CONVERSATION_ID in .env to run the bot.");
    return;
}

var api = new XChatClient(accessToken, EnvOr("X_API_BASE_URL") ?? "https://api.x.com");
var botUserId = EnvOr("CHAT_BOT_USER_ID");
if (string.IsNullOrEmpty(botUserId))
    botUserId = await api.GetMyUserIdAsync();

var bot = new Bot(core, api, botUserId);
await bot.RunAsync(conversationId, TimeSpan.FromSeconds(3));

// Tiny .env loader so the example has no extra dependencies.
static void LoadDotenv()
{
    if (!File.Exists(".env")) return;
    foreach (var line in File.ReadAllLines(".env"))
    {
        var t = line.Trim();
        if (t.Length == 0 || t.StartsWith('#') || !t.Contains('=')) continue;
        var idx = t.IndexOf('=');
        var key = t[..idx].Trim();
        var value = t[(idx + 1)..].Trim();
        if (Environment.GetEnvironmentVariable(key) is null)
            Environment.SetEnvironmentVariable(key, value);
    }
}
