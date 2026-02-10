/**
 * Hook native connect() to redirect connections through our proxy.
 *
 * Based on httptoolkit/frida-interception-and-unpinning (MIT License)
 * Intercepts native-level socket connections and redirects HTTPS (port 443)
 * traffic to our proxy.
 */

(function () {
    var proxyHost = globalThis.HTTPTOOLKIT_PROXY_HOST || '127.0.0.1';
    var proxyPort = globalThis.HTTPTOOLKIT_PROXY_PORT || 8080;

    // Hook libc connect() to redirect outgoing connections
    try {
        var connectPtr = Module.findExportByName('libc.so', 'connect');
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function (args) {
                    var sockfd = args[0].toInt32();
                    var addr = args[1];
                    var addrLen = args[2].toInt32();

                    // Only intercept AF_INET (IPv4)
                    var family = addr.readU16();
                    if (family !== 2) return; // AF_INET = 2

                    var port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();

                    // Redirect HTTPS traffic (port 443) to our proxy
                    if (port === 443) {
                        // Rewrite the destination to our proxy
                        var proxyIp = proxyHost.split('.').map(Number);
                        addr.add(2).writeU8((proxyPort >> 8) & 0xFF);
                        addr.add(3).writeU8(proxyPort & 0xFF);
                        addr.add(4).writeU8(proxyIp[0] || 127);
                        addr.add(5).writeU8(proxyIp[1] || 0);
                        addr.add(6).writeU8(proxyIp[2] || 0);
                        addr.add(7).writeU8(proxyIp[3] || 1);
                    }
                }
            });
            console.log('[proxy-mcp] Native connect() hook installed');
        }
    } catch (e) {
        console.log('[proxy-mcp] Native connect hook failed: ' + e);
    }
})();
