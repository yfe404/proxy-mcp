/**
 * SSL/TLS certificate unpinning for Android apps.
 *
 * Based on httptoolkit/frida-interception-and-unpinning (MIT License)
 * Hooks TrustManagerImpl, OkHttp CertificatePinner, and various other
 * common pinning implementations to accept our CA certificate.
 */

if (Java.available) {
    Java.perform(function () {
        // --- TrustManagerImpl (Android system) ---
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                return untrustedChain;
            };
            console.log('[proxy-mcp] Unpinned TrustManagerImpl.verifyChain');
        } catch (e) { /* Not available */ }

        // --- OkHttp3 CertificatePinner ---
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCerts) {
                // Do nothing — accept all
            };
            console.log('[proxy-mcp] Unpinned okhttp3.CertificatePinner.check');
        } catch (e) { /* Not available */ }

        try {
            var CertificatePinner2 = Java.use('okhttp3.CertificatePinner');
            CertificatePinner2.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function (hostname, func) {
                // Do nothing
            };
            console.log('[proxy-mcp] Unpinned okhttp3.CertificatePinner.check$okhttp');
        } catch (e) { /* Not available */ }

        // --- Apache HTTP legacy ---
        try {
            var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () {
                // Accept all
            };
            console.log('[proxy-mcp] Unpinned Apache AbstractVerifier');
        } catch (e) { /* Not available */ }

        // --- Appcelerator Titanium PinningTrustManager ---
        try {
            var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            PinningTrustManager.checkServerTrusted.implementation = function () {
                // Accept all
            };
            console.log('[proxy-mcp] Unpinned Appcelerator PinningTrustManager');
        } catch (e) { /* Not available */ }

        // --- SSLContext default init with permissive TrustManager ---
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.registerClass({
                name: 'com.httptoolkit.TrustAllManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () { return []; }
                }
            });

            var TrustManagers = [TrustManager.$new()];

            // Hook SSLContext.init to inject our permissive TrustManager
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
                this.init(km, TrustManagers, sr);
            };
            console.log('[proxy-mcp] Installed permissive TrustManager via SSLContext.init');
        } catch (e) { /* Not available */ }

        // --- WebView SSL error handler ---
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function (webView, handler, error) {
                handler.proceed();
            };
            console.log('[proxy-mcp] Unpinned WebViewClient SSL errors');
        } catch (e) { /* Not available */ }

        // --- Network Security Config pinning ---
        try {
            var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
            NetworkSecurityTrustManager.checkPins.implementation = function (chain) {
                // Skip pin check
            };
            console.log('[proxy-mcp] Unpinned NetworkSecurityTrustManager.checkPins');
        } catch (e) { /* Not available */ }
    });
}
