/**
 * Inject our CA certificate into the running app's trust store at runtime.
 *
 * Based on httptoolkit/frida-interception-and-unpinning (MIT License)
 * This adds our cert to the app's TrustManager without needing system-level
 * cert injection (useful for non-rooted devices with Frida).
 */

if (Java.available) {
    Java.perform(function () {
        try {
            var certPem = globalThis.HTTPTOOLKIT_CERT_PEM;
            if (!certPem) {
                console.log('[proxy-mcp] No CERT_PEM configured, skipping runtime cert injection');
                return;
            }

            var CertificateFactory = Java.use('java.security.cert.CertificateFactory');
            var X509Certificate = Java.use('java.security.cert.X509Certificate');
            var KeyStore = Java.use('java.security.KeyStore');
            var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
            var String = Java.use('java.lang.String');

            // Parse our PEM cert
            var cf = CertificateFactory.getInstance('X.509');
            var certBytes = String.$new(certPem).getBytes();
            var certInputStream = ByteArrayInputStream.$new(certBytes);
            var cert = cf.generateCertificate(certInputStream);

            // Create a KeyStore containing our cert
            var ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry('proxy-mcp-ca', cert);

            // Add system certs too
            var systemKs = KeyStore.getInstance('AndroidCAStore');
            systemKs.load(null, null);
            var aliases = systemKs.aliases();
            while (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();
                var systemCert = systemKs.getCertificate(alias);
                if (systemCert !== null) {
                    ks.setCertificateEntry(alias, systemCert);
                }
            }

            // Create TrustManager with combined store
            var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            console.log('[proxy-mcp] Runtime certificate injection prepared');
        } catch (e) {
            console.log('[proxy-mcp] Runtime cert injection failed: ' + e);
        }
    });
}
