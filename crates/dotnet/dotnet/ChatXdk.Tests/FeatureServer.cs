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
        /// <summary>Nothing listens here: a chat no test points at a server of its own reads
        /// its feature switches from this endpoint, fails, and stays on v0.</summary>
        internal const string Offline = "http://127.0.0.1:9/2/chat/features";

#pragma warning disable CA2255 // This is the test assembly's own setup, not a library's.
        [ModuleInitializer]
        internal static void KeepFeatureReadsOffTheNetwork() => FeatureFetch.SetDefaultEndpoint(Offline);
#pragma warning restore CA2255

        private static readonly Lazy<FeatureServer> V1Server = new(() => new FeatureServer(), LazyThreadSafetyMode.ExecutionAndPublication);

        /// <summary>
        /// A chat whose feature switches turn v1_send on, as the X API would: it reads them
        /// from a local server that answers so. <see cref="WaitForV1"/> waits for the answer.
        /// </summary>
        internal static Chat V1Chat() => new(null, V1Server.Value.Endpoint, TimeSpan.FromSeconds(2));

        /// <summary>Send from <paramref name="chat"/>, which has keys, until a send is v1.</summary>
        internal static void WaitForV1(Chat chat)
        {
            var send = new EncryptMessageParams("feature-switches", "wait for v1")
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
    /// A local GET /2/chat/features that records each request's query string and head. Its
    /// <see cref="RedirectTarget"/> path answers that v1_send is on, for the tests that check a
    /// redirect to it is not followed. A request for another path, such as a retry of a server
    /// that had this port before, gets a 404 and is not recorded. It speaks just
    /// enough HTTP over a <see cref="TcpListener"/> for one request per connection, and
    /// handles a client that gives up mid-request itself.
    /// </summary>
    internal sealed class FeatureServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly object _sync = new();
        private readonly List<string> _queries = new();
        private readonly List<string> _heads = new();
        private int _status = 200;
        private string _body;
        private int _delayMs;
        private string? _location;
        private string? _setCookie;
        private int _followed;

        internal const string RedirectTarget = "/followed/2/chat/features";

        // Each server gets an endpoint of its own: chats created while a GET
        // for their endpoint is in flight share it, and a server can get the
        // port of one that came before it.
        private static int s_lastId;

        private readonly string _path;

        public string Endpoint { get; }

        public FeatureServer(string body = "{\"features\":{\"v1_send\":true}}")
        {
            _body = body;
            _listener.Start();
            _path = $"/{Interlocked.Increment(ref s_lastId)}/2/chat/features";
            Endpoint = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}{_path}";
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

        public List<string> Queries
        {
            get
            {
                lock (_sync) return new List<string>(_queries);
            }
        }

        /// <summary>The request line and headers of each request to the endpoint.</summary>
        public List<string> RequestHeads
        {
            get
            {
                lock (_sync) return new List<string>(_heads);
            }
        }

        /// <summary>How many requests reached <see cref="RedirectTarget"/>.</summary>
        public int FollowedRedirects
        {
            get
            {
                lock (_sync) return _followed;
            }
        }

        /// <summary>Answer each request with a redirect to <see cref="RedirectTarget"/> on this server.</summary>
        public void Redirect()
        {
            lock (_sync)
            {
                _status = 302;
                _location = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}{RedirectTarget}";
            }
        }

        public void SetCookie(string cookie)
        {
            lock (_sync) _setCookie = cookie;
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
                    var requestHead = await ReadRequestHeadAsync(stream);
                    var target = requestHead.Split(' ')[1];
                    if (target == RedirectTarget)
                    {
                        lock (_sync) _followed++;
                        await WriteResponseAsync(stream, 200, "{\"features\":{\"v1_send\":true}}", "");
                        return;
                    }
                    var queryStart = target.IndexOf('?');
                    var query = queryStart >= 0 ? target[(queryStart + 1)..] : "";
                    if ((queryStart >= 0 ? target[..queryStart] : target) != _path)
                    {
                        await WriteResponseAsync(stream, 404, "", "");
                        return;
                    }
                    // The answer is fixed when the request is recorded, so a test that sees the
                    // request can change the next answer.
                    int status;
                    string body;
                    int delayMs;
                    var extraHeaders = "";
                    lock (_sync)
                    {
                        _queries.Add(query);
                        _heads.Add(requestHead);
                        status = _status;
                        body = _body;
                        delayMs = _delayMs;
                        if (_location != null) extraHeaders += $"Location: {_location}\r\n";
                        if (_setCookie != null) extraHeaders += $"Set-Cookie: {_setCookie}\r\n";
                    }
                    if (delayMs > 0) await Task.Delay(delayMs, _stop.Token);
                    await WriteResponseAsync(stream, status, body, extraHeaders);
                }
                catch (Exception)
                {
                    // The client gave up (timeout or Dispose), or the server stopped.
                }
            }
        }

        private async Task WriteResponseAsync(NetworkStream stream, int status, string body, string extraHeaders)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            var head = $"HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\n{extraHeaders}"
                + $"Content-Length: {bytes.Length}\r\nConnection: close\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(head), _stop.Token);
            await stream.WriteAsync(bytes, _stop.Token);
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
