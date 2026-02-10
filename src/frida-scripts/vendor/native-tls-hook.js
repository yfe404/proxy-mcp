/**
 * Hook native TLS verification to accept our CA certificate.
 *
 * Based on httptoolkit/frida-interception-and-unpinning (MIT License)
 * Patches BoringSSL/OpenSSL certificate verification functions to always succeed.
 */

(function () {
    // Hook BoringSSL's SSL_CTX_set_custom_verify (used by Chrome, Cronet)
    try {
        var ssl_ctx_set_custom_verify = Module.findExportByName('libssl.so', 'SSL_CTX_set_custom_verify');
        if (ssl_ctx_set_custom_verify) {
            Interceptor.attach(ssl_ctx_set_custom_verify, {
                onEnter: function (args) {
                    // Replace callback with null to disable custom verification
                    args[2] = ptr(0);
                }
            });
            console.log('[proxy-mcp] Hooked SSL_CTX_set_custom_verify');
        }
    } catch (e) { /* Not available */ }

    // Hook SSL_set_custom_verify
    try {
        var ssl_set_custom_verify = Module.findExportByName('libssl.so', 'SSL_set_custom_verify');
        if (ssl_set_custom_verify) {
            Interceptor.attach(ssl_set_custom_verify, {
                onEnter: function (args) {
                    args[2] = ptr(0);
                }
            });
            console.log('[proxy-mcp] Hooked SSL_set_custom_verify');
        }
    } catch (e) { /* Not available */ }

    // Hook X509_verify_cert to always return success
    try {
        var x509_verify = Module.findExportByName('libcrypto.so', 'X509_verify_cert');
        if (!x509_verify) {
            x509_verify = Module.findExportByName('libssl.so', 'X509_verify_cert');
        }
        if (x509_verify) {
            Interceptor.attach(x509_verify, {
                onLeave: function (retval) {
                    retval.replace(1); // Always return success
                }
            });
            console.log('[proxy-mcp] Hooked X509_verify_cert');
        }
    } catch (e) { /* Not available */ }

    // Hook SSL_get_verify_result to return X509_V_OK
    try {
        var ssl_get_verify = Module.findExportByName('libssl.so', 'SSL_get_verify_result');
        if (ssl_get_verify) {
            Interceptor.attach(ssl_get_verify, {
                onLeave: function (retval) {
                    retval.replace(0); // X509_V_OK = 0
                }
            });
            console.log('[proxy-mcp] Hooked SSL_get_verify_result');
        }
    } catch (e) { /* Not available */ }
})();
