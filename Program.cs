using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.IO.Pipelines;
using System.IO.Pipes;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.AspNetCore;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Https.Internal;
using System.Buffers;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using System.IO;
using System.Security.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using System.Reflection;
using Yarp.ReverseProxy.Forwarder;
using System.Diagnostics;

namespace TestProxy
{

    
    public class Startup
    {
        static Assembly KestrelAssembly = typeof(KestrelServer).Assembly;
        static Type ReflectedHttpsConnectionMiddleware = KestrelAssembly.GetType("Microsoft.AspNetCore.Server.Kestrel.Https.Internal.HttpsConnectionMiddleware");
        //YES - valid
        static ConstructorInfo constructorInfoObj = ReflectedHttpsConnectionMiddleware.GetConstructor(BindingFlags.Instance | BindingFlags.Public, null, CallingConventions.HasThis, new Type[] { typeof(ConnectionDelegate), typeof(HttpsConnectionAdapterOptions) }, null);
        //var constructorInfoObj = Activator.CreateInstance(ReflectedHttpsConnectionMiddleware, BindingFlags.Instance, new object[] { context, sslOpts });
        static MethodInfo OnConnectionAsync = ReflectedHttpsConnectionMiddleware.GetMethod("OnConnectionAsync");
        

        static Dictionary<String, X509Certificate2> certificates = new Dictionary<String, X509Certificate2>();
        static X509Certificate2 CACert = X509Certificate2.CreateFromPemFile("c:\\testcerts\\ca_cert_and_key.pem");



        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpForwarder();
        }

        public void Configure(IApplicationBuilder app, IHttpForwarder forwarder)
        {
            var httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false,
                ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
            });
            //var transformer = new CustomTransformer(); // or HttpTransformer.Default;
            var transformer = HttpTransformer.Default; // or HttpTransformer.Default;
            var requestConfig = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };
           
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async (context) =>
                {
                    await context.Response.WriteAsync("Map Test Successful" + context.Request.Host);
                }
                ).RequireHost("localhost");
                endpoints.Map("/{**catch-all}", async httpContext =>
                {
                    Console.WriteLine("Hello - " + String.Format("isHttps: {0} - {1}://{2}",
                                httpContext.Request.IsHttps,
                                httpContext.Request.IsHttps ? "https" : "http",
                                httpContext.Request.Host));
                    var error = await forwarder.SendAsync(httpContext,
                            String.Format("{0}://{1}",
                                httpContext.Request.IsHttps ? "https" : "http",
                                httpContext.Request.Host),
                        httpClient, requestConfig, transformer);
                    // Check if the operation was successful
                    if (error != ForwarderError.None)
                    {
                        var errorFeature = httpContext.GetForwarderErrorFeature();
                        var exception = errorFeature.Exception;
                    }
                });
            });
        }
    }


    public class Program
    {
      

        public class ReplacementContext : IDuplexPipe
        {
            public PipeReader Input { get; set; }
            public PipeWriter Output { get; set; }
            public ReplacementContext(SslStream stream)
            {

                Input = PipeReader.Create(stream);
                Output = PipeWriter.Create(stream);
            }
        }


        static Dictionary<String, X509Certificate2> certificates = new Dictionary<String, X509Certificate2>();
        static X509Certificate2 CACert = X509Certificate2.CreateFromPemFile("c:\\testcerts\\ca_cert_and_key.pem");

        static X509Certificate2 MakeCert(string host)
        {
            RSA rsa = RSA.Create(2048);
            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={host}");
            var req = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(host);
            var sanExtension = sanBuilder.Build();
            req.CertificateExtensions.Add(sanExtension);
            X509Certificate2 cert = req.Create(CACert, DateTimeOffset.Now.AddMinutes(-1), DateTimeOffset.Now.AddYears(1), RandomNumberGenerator.GetBytes(16));
            cert = cert.CopyWithPrivateKey(rsa);
            Console.WriteLine("Made a cert for: " + cert.SubjectName.Name);
            return new X509Certificate2(cert.Export(X509ContentType.Pkcs12));  //won't work on Windows without this export - underlying SSLStream borks unless in this format. Will listen and appear absolutely normal, but won't provide certificate during handshake
            // https://github.com/dotnet/runtime/issues/23749
        }
        private async Task HandleConnectRedux(ConnectionContext context, ConnectionDelegate next)
        {
            /*
            context.
            if (context.Request.Method == "CONNECT")
            {
                HttpsConnectionAdapterOptions sslOpts = new HttpsConnectionAdapterOptions();
                if (!certificates.ContainsKey(context.Request.Host.Host))
                {
                    sslOpts.ServerCertificate = MakeCert(context.Request.Host.Host);
                    certificates[context.Request.Host.Host] = sslOpts.ServerCertificate;
                }
                else
                {
                    sslOpts.ServerCertificate = (X509Certificate2)context.Items["certificate"];
                }
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync("");

                ConnectionDelegate ConnDel = async context =>
                {
                    await context.invok;
                };
                //object MiddlewareInstance = constructorInfoObj.Invoke(new object[] { next, sslOpts });
                object MiddlewareInstance = (constructorInfoObj.Invoke(new object[] { (next, sslOpts }));
                var task = (Task)OnConnectionAsync.Invoke(MiddlewareInstance, new object[] { context });
                await task.ConfigureAwait(false);

                await next(context);
            */
            }
        //I think this is broken. Keeping it in case I need / want it
        private async Task HandleConnectPeek(ConnectionContext connection)
        {
            Socket socket = connection.Features.Get<IConnectionSocketFeature>().Socket;

            byte[] buffer = new byte[8192];
            string method;
            string message;
            //string method;
            int count = 0;
            count = socket.Receive(buffer, SocketFlags.Peek);
            if (count == 0)
            {
                return;
            }
            method = Encoding.ASCII.GetString(buffer, 0, 7);

            //socket.Receive(buffer, -1*count, SocketFlags.None);
            //socket.Receive(buffer, 0, SocketFlags.None);
            Console.WriteLine("got 7: " + method);
            Console.WriteLine("is it a connect?" + method + "CONNECT");
            if (method == "CONNECT")
            {
                message = Encoding.ASCII.GetString(buffer);
                while (message.IndexOf("\r\n\r\n") == -1)
                {
                    count = socket.Receive(buffer);
                    if (count == 0 || message.Length > 8191)
                    {
                        Console.WriteLine("connect message too large or it broke, ignoring");
                        return; // message broke
                    }
                    Console.WriteLine("got message bytes inner: " + count);
                    message += Encoding.ASCII.GetString(buffer);
                }
                Console.WriteLine("see end of message :: " + message);
                int Cull = message.IndexOf("Host: ");
                Console.WriteLine("first cull point is: " + Cull);
                if (Cull == -1) { return; } // bad message
                message = message.Substring(Cull + 6, message.Length - Cull - 6);
                Cull = message.IndexOf(":");
                if (Cull == -1) { return; } // bad message
                message = message.Substring(0, Cull);
                Console.WriteLine("target host is: " + message);

                if (socket.Available != 0 && socket.Available < 8193)
                {
                    Console.WriteLine("had to drain socket");
                    socket.Receive(buffer); // clear socket
                }
                if (socket.Available > 8192)
                {
                    return; // huge message, ignore
                }


            }
            Console.WriteLine("Not a connect ------");
            return;
        }

        private async static Task HandleConnectPipeline(ConnectionContext context)
        {
            /*
            * First idea was to get and upgrade the underlying socket from IConnectionSocketFeature
            * and recv() using PEEK, get info we need then wrap an SSLStream around it.
            * 
            * THIS. DOES. NOT. WORK. In fact, pretty much all socket operations fail
            * abysmally.
            * 
            * So does using streams and changing the seek position. Underlying socket
            * doesn't support it at all.
            * 
            * Magic is to use the pipereader, read data, then winding back the cursor
            * using AdvanceTo(buff.Buffer.Start)
            */

            //PipeReader input = context.Transport.Input;
            PipeReader input = context.Transport.Input;
            //Stream output = context.Transport.Output.AsStream();
            Socket socket = context.Features.Get<IConnectionSocketFeature>()?.Socket;
            byte[] method = new byte[7];
            byte[] readbuffer = new byte[8192];
            string message = "";
            ReadResult methodmessage;

            int count = 0;
            count = socket.Receive(method, 7, SocketFlags.Peek);
            
            if (count != 7) {
                Thread.Sleep(25); 
                count = socket.Receive(method, 7, SocketFlags.Peek);
            }
            
            Console.WriteLine("?? is connect " + Encoding.ASCII.GetString(method));
            if (Encoding.ASCII.GetString(method) == "CONNECT")
            {
                Console.WriteLine("we have a connect here");

                var result = await input.ReadAsync();
                message += Encoding.ASCII.GetString(result.Buffer);
                while (message.IndexOf("\r\n\r\n") == -1) {
                    Thread.Sleep(25);
                    result = await input.ReadAsync();
                    message += Encoding.ASCII.GetString(result.Buffer);
                }
                    
                int Cull = message.IndexOf("Host: ");
                Console.WriteLine("first cull point is: "+Cull);
                if (Cull == -1) { return ; } // bad message
                message = message.Substring(Cull+6, message.Length-Cull-6);
                Cull = message.IndexOf(":");
                if (Cull == -1) { return; } // bad message
                message = message.Substring(0, Cull);
                Console.WriteLine("target host is: "+message);

                if (!certificates.ContainsKey(message))
                {
                    certificates[message] = MakeCert(message);
                }
                context.Items["certificate"] = certificates[message];

                socket.Send(ASCIIEncoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"));

            }
            /* HTTP2: The client connection preface starts with a sequence of 24 octets,
                which in hex notation is:

                0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a
                        
                That is, the connection preface starts with the string "PRI *
                HTTP/2.0\r\n\r\nSM\r\n\r\n").  This sequence MUST be followed by a
                SETTINGS frame (Section 6.5), which MAY be empty.
                https://www.rfc-editor.org/rfc/rfc7540#section-4.1
                */
        }

        static async Task HandleMapTest(HttpContext context)
        {

            Console.WriteLine("Request: ISHTTPS:{0} {1} {2} {3} ", context.Request.IsHttps, context.Request.Method, context.Request.Host, context.Request.Path);
            await context.Response.WriteAsync("Map Test Successful" + context.Request.Host);
        }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpForwarder();
        }

        public static void Main(string[] args)
        {
        Assembly KestrelAssembly = typeof(KestrelServer).Assembly;
        Type ReflectedHttpsConnectionMiddleware = KestrelAssembly.GetType("Microsoft.AspNetCore.Server.Kestrel.Https.Internal.HttpsConnectionMiddleware");
        //YES - valid
        var constructorInfoObj = ReflectedHttpsConnectionMiddleware.GetConstructor(BindingFlags.Instance | BindingFlags.Public, null, CallingConventions.HasThis, new Type[] { typeof(ConnectionDelegate), typeof(HttpsConnectionAdapterOptions) }, null);
        //var constructorInfoObj = Activator.CreateInstance(ReflectedHttpsConnectionMiddleware, BindingFlags.Instance, new object[] { context, sslOpts });
        MethodInfo OnConnectionAsync = ReflectedHttpsConnectionMiddleware.GetMethod("OnConnectionAsync");
        

        

        var builder = WebHost.CreateDefaultBuilder(args);
            builder.ConfigureLogging(logging =>
            {
                logging.AddConsole();
            });
            builder.SuppressStatusMessages(false)
                .UseKestrel((context, options) =>
                    options.Listen(System.Net.IPAddress.Any, 5027, listenOptions =>
                    {
                        listenOptions.Use(async (context, next) =>
                        {
                            if(context.Features.Get<ITlsConnectionFeature>() == null)
                            {
                                byte[] methodbuf = new byte[8192];
                                Console.WriteLine("Have a new connection!");
                                ReadResult wibble = await context.Transport.Input.ReadAsync();
                                string message = Encoding.ASCII.GetString(wibble.Buffer);
                                if (message.IndexOf("CONNECT") != -1)
                                {
                                    context.Transport.Input.AdvanceTo(wibble.Buffer.End);
                                    Console.WriteLine("{0} - It's a connect!", context.ConnectionId);
                                    context.Items["upgrade"] = true;
                                    HttpsConnectionAdapterOptions sslOpts = new HttpsConnectionAdapterOptions();
                                    ConnectionDelegate beee = async context =>
                                    {
                                        await next();
                                    };
                                    Console.WriteLine("{0} - Seen end of message?", context.ConnectionId);
                                    Console.WriteLine("{0} RAWMESSAGE: " + message);
                                    Console.WriteLine("{0} RAWMESSAGE222222: ", message);
                                    Console.WriteLine("{0} - Seen end of connect message!", context.ConnectionId);
                                    int Cull = message.IndexOf("Host: ");
                                    Console.WriteLine("first cull point is: " + Cull);
                                    if (Cull == -1) { next.Invoke(); } // bad message
                                    message = message.Substring(Cull + 6, message.Length - Cull - 6);
                                    Cull = message.IndexOf(":");
                                    if (Cull == -1) { next.Invoke(); } // bad message
                                    message = message.Substring(0, Cull);
                                    Console.WriteLine("target host is: " + message);
                                    context.Items["certificate"] = MakeCert(message);

                                    //Socket socket = context.Features.Get<IConnectionSocketFeature>().Socket;
                                    //socket.Send(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"));
                                    await context.Transport.Output.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"));

                                    //listenOptions.UseHttps((X509Certificate2)context.Items["certificate"]);
                                    sslOpts.ServerCertificate = (X509Certificate2)context.Items["certificate"];
                                    Console.WriteLine("test test test");
                                    //listenOptions = sslOptions.UseHttps((X509Certificate2)context.Items["certificate"]);
                                    object MiddlewareInstance = (constructorInfoObj.Invoke(new object[] { listenOptions.Build(), sslOpts })); ;
                                    Console.WriteLine("22222test test test");
                                    var task = (Task)OnConnectionAsync.Invoke(MiddlewareInstance, new object[] { context });
                                    await task;
                                    //await context.Transport.Input.CompleteAsync();
                                    //await context.Transport.Output.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n"));
                                }
                                else
                                {
                                    context.Transport.Input.AdvanceTo(wibble.Buffer.Start);
                                }
                            }
                            await next.Invoke();
                        });
                    }))
                .UseStartup<Startup>();



            var app = builder.Build();

            app.Run();
        }
    }
}