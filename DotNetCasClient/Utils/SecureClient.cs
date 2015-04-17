using System;
using System.Collections.Specialized;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DotNetCasClient.Utils
{
    /// <summary>
    /// For establishing SSL connection with remote web service and returning response in SecureString object.
    /// </summary>
    public sealed class SecureClient
    {
        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            // throw new Exception(sslPolicyErrors.ToString());
            return false;
        }

        ///  <summary>
        ///  Sends HTTPS request over raw SSL connection using TcpClient() and returns response body in SecureString object.
        ///  
        ///  Caution: This method uses blocking ReadByte() to marshal response stream into SecureString one byte at a time.
        ///  </summary>
        /// <param name="uri">Request Uri</param>
        /// <param name="body">
        ///      Raw HTTP request including headers and parameters as described below
        /// 
        ///      For "POST" requests:
        /// 
        ///      POST /bin/login HTTP/1.1
        ///      Host: www.example.com
        ///      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
        ///      Pragma: no-cache
        ///      Content-Type: application/x-www-form-urlencoded
        ///      User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36
        ///      Content-Length: 37
        ///      Connection: close
        ///      Cache-Control: no-cache
        /// 
        ///      User=Peter+Lee&pw=123456&action=login
        ///      [enter twice to create a blank line]
        ///      
        ///      For "GET" requests:
        ///      
        ///      GET /index.html HTTP/1.1
        ///      Host: www.example.com
        ///      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
        ///      Pragma: no-cache
        ///      User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.118 Safari/537.36
        ///      Cache-Control: no-cache
        ///      Connection: close
        ///      [enter twice to create a blank line]
        /// </param>
        /// <param name="timeout">Maximum amount of time a single ReadByte() or Write() operation can block the caller (default: 1000ms)</param>
        /// <returns>SecureString containing HTTP response</returns>
        ///  <exception cref="AuthenticationException">Authentication failed</exception>
        public static SecureString SecureHttpRequest(Uri uri, string body, int timeout = 1000)
        {
            // Prepare secureMessage
            var secureResponse = new SecureString();

            using (var client = new TcpClient(uri.Host, uri.Port))
            {
                using (var sslStream = new SslStream(client.GetStream(), false, ValidateServerCertificate, null))
                {
                    // Set timeouts
                    sslStream.WriteTimeout = timeout;
                    sslStream.ReadTimeout = timeout;

                    // Authenticate
                    try
                    {
                        sslStream.AuthenticateAsClient(uri.Host);
                    }
                    catch (AuthenticationException e)
                    {
                        sslStream.Close();
                        client.Close();

                        throw;
                    }

                    // Pin byte in memory
                    var b = -1;
                    var byteGcHandler = GCHandle.Alloc(b, GCHandleType.Pinned);

                    try
                    {
                        // Send
                        sslStream.Write(Encoding.UTF8.GetBytes(body));
                        sslStream.Flush();

                        do
                        {
                            // Caution: ReadByte() will block application if no bytes are received!
                            // Ensure request is properly formatted (e.g. two '\n' chars terminating rawHttpRequest)
                            // Force short ReadTimeout to fast fail
                            // Ensure HTTP header "Connection" is set to close or connection will remain opened (i.e. keep-alive)
                            b = sslStream.ReadByte();
                            if (b == -1) break;

                            // Append to secureMessage and scrub char
                            secureResponse.AppendChar(Convert.ToChar(b));
                        } while (b != -1);
                    }

                    // Ensure cleanup
                    finally
                    {
                        // Scrub byte
                        b = 0;

                        // Explicitly close streams
                        sslStream.Close();
                        client.Close();

                        // Free GC handlers
                        byteGcHandler.Free();

                        // Make secureMessage read-only
                        secureResponse.MakeReadOnly();
                    }

                    return secureResponse;
                }
            }
        }
    }
}
