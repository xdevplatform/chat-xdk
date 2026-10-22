// A local GET /2/chat/features for the tests, and the internal hooks that point chats at it.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace ChatXdk.Tests
{
    internal static class FeatureTestEnvironment
    {
        /// <summary>Nothing listens here: a chat no test points at a server of its own fetches
        /// from this endpoint, fails, and stays on v0.</summary>
        internal const string Offline = "http://127.0.0.1:9/2/chat/features";

#pragma warning disable CA2255 // This is the test assembly's own setup, not a library's.
        [ModuleInitializer]
        internal static void KeepFeatureFetchesOffTheNetwork() => FeatureDriver.SetDefaultEndpoint(Offline);
#pragma warning restore CA2255

        private static readonly Lazy<FeatureServer> V1Server = new(() => new FeatureServer(), LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>
        /// Turn v1_send on for <paramref name="chat"/> as the X API would: point its feature
        /// fetch at a local server that answers it, then send until a send is v1.
        /// </summary>
        internal static void EnableV1Send(Chat chat)
        {
            chat.ConfigureFeatures(V1Server.Value.Endpoint, TimeSpan.FromSeconds(2), TimeSpan.FromHours(1), TimeSpan.FromMilliseconds(50));
            var send = new EncryptMessageParams("feature-switches", "turn v1 on")
            {
                SenderId = "1",
                SigningKeyVersion = "1",
                ConversationKey = new byte[32],
                ConversationKeyVersion = "1",
            };
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (chat.EncryptMessage(send).SignatureInfo.SignatureVersion != "10")
            {
                Assert.True(DateTime.UtcNow < deadline, "v1_send never turned on");
                Thread.Sleep(10);
            }
        }
    }

    /// <summary>
    /// A local GET /2/chat/features that records each request's bucket. It speaks just
    /// enough HTTP over a <see cref="TcpListener"/> for one request per connection, and
    /// handles a client that gives up mid-request itself.
    /// </summary>
    internal sealed class FeatureServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly object _sync = new();
        private readonly List<string?> _buckets = new();
        private int _status = 200;
        private string _body;
        private int _delayMs;

        // Each server gets an endpoint of its own: the core reuses an answer
        // per endpoint and bucket for 5 minutes, and a server can get the port
        // of one that came before it.
        private static int s_lastId;

        public string Endpoint { get; }

        public FeatureServer(string body = "{\"features\":{\"v1_send\":true}}")
        {
            _body = body;
            _listener.Start();
            Endpoint = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/{Interlocked.Increment(ref s_lastId)}/2/chat/features";
            _ = Task.Run(AcceptAsync);
        }

        public void Set(int status, string body, int delayMs = 0)
        {
            lock (_sync)
            {
                _status = status;
                _body = body;
                _delayMs = delayMs;
            }
        }

        public List<string?> Buckets
        {
            get
            {
                lock (_sync) return new List<string?>(_buckets);
            }
        }

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token);
                }
                catch (Exception)
                {
                    return;
                }
                _ = Task.Run(() => HandleAsync(client));
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    var stream = client.GetStream();
                    var target = (await ReadRequestHeadAsync(stream)).Split(' ')[1];
                    string? bucket = null;
                    var query = target.IndexOf('?');
                    if (query >= 0)
                    {
                        foreach (var pair in target[(query + 1)..].Split('&'))
                        {
                            if (pair.StartsWith("bucket=", StringComparison.Ordinal)) bucket = pair["bucket=".Length..];
                        }
                    }
                    // The answer is fixed when the request is recorded, so a test that sees the
                    // request can change the next answer.
                    int status;
                    string body;
                    int delayMs;
                    lock (_sync)
                    {
                        _buckets.Add(bucket);
                        status = _status;
                        body = _body;
                        delayMs = _delayMs;
                    }
                    if (delayMs > 0) await Task.Delay(delayMs, _stop.Token);
                    var bytes = Encoding.UTF8.GetBytes(body);
                    var head = $"HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\n"
                        + $"Content-Length: {bytes.Length}\r\nConnection: close\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(head), _stop.Token);
                    await stream.WriteAsync(bytes, _stop.Token);
                }
                catch (Exception)
                {
                    // The client gave up (timeout or Dispose), or the server stopped.
                }
            }
        }

        /// <summary>The request line and headers, up to the blank line that ends them.</summary>
        private async Task<string> ReadRequestHeadAsync(NetworkStream stream)
        {
            var head = new List<byte>();
            var buffer = new byte[1024];
            while (head.Count < 16 * 1024)
            {
                var read = await stream.ReadAsync(buffer, _stop.Token);
                if (read == 0) break;
                head.AddRange(buffer.AsSpan(0, read).ToArray());
                var text = Encoding.ASCII.GetString(head.ToArray());
                if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) return text;
            }
            throw new IOException("incomplete request");
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
        }
    }
}
