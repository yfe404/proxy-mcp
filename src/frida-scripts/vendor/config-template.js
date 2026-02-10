/**
 * Configuration template for httptoolkit Frida interception scripts.
 * Tokens are replaced by bundle.ts before injection.
 *
 * Based on: https://github.com/httptoolkit/frida-interception-and-unpinning (MIT)
 */

// These values are substituted at bundle time:
const PROXY_HOST = '{{PROXY_HOST}}';
const PROXY_PORT = {{PROXY_PORT}};

const CERT_PEM = `{{CERT_PEM}}`;

// Export for use by other scripts
globalThis.HTTPTOOLKIT_PROXY_HOST = PROXY_HOST;
globalThis.HTTPTOOLKIT_PROXY_PORT = PROXY_PORT;
globalThis.HTTPTOOLKIT_CERT_PEM = CERT_PEM;
