/**
 * Override Android proxy settings to route traffic through our MITM proxy.
 *
 * Based on httptoolkit/frida-interception-and-unpinning (MIT License)
 * Hooks java.net.ProxySelector to return our proxy for all connections.
 */

if (Java.available) {
    Java.perform(function () {
        try {
            var ProxySelector = Java.use('java.net.ProxySelector');
            var Proxy = Java.use('java.net.Proxy');
            var ProxyType = Java.use('java.net.Proxy$Type');
            var InetSocketAddress = Java.use('java.net.InetSocketAddress');
            var ArrayList = Java.use('java.util.ArrayList');
            var URI = Java.use('java.net.URI');

            var proxyHost = globalThis.HTTPTOOLKIT_PROXY_HOST || '127.0.0.1';
            var proxyPort = globalThis.HTTPTOOLKIT_PROXY_PORT || 8080;

            var proxyAddress = InetSocketAddress.$new(proxyHost, proxyPort);
            var httpProxy = Proxy.$new(ProxyType.HTTP.value, proxyAddress);

            // Override the default ProxySelector
            var CustomProxySelector = Java.registerClass({
                name: 'com.httptoolkit.ProxySelector',
                superClass: ProxySelector,
                methods: {
                    select: function (uri) {
                        var list = ArrayList.$new();
                        list.add(httpProxy);
                        return list;
                    },
                    connectFailed: function (uri, socketAddress, ioException) {
                        // Ignore failures
                    }
                }
            });

            ProxySelector.setDefault(CustomProxySelector.$new());
            console.log('[proxy-mcp] Android proxy override installed: ' + proxyHost + ':' + proxyPort);
        } catch (e) {
            console.log('[proxy-mcp] Proxy override failed: ' + e);
        }
    });
}
