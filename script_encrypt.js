// 对象输出模式: true为仅输出JSON.stringify(obj, null, 4); false为递归至多三层输出参数值;
var simpleOnly = false;
// 递归输出对象的最大深度
var maxDepth = 3;
// 绕过TracerPid检测
var ByPassTracerPid = function () {
    var fgetsPtr = Module.findExportByName('libc.so', 'fgets');
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = Memory.readUtf8String(buffer);
        if (bufstr.indexOf('TracerPid:') > -1) {
            Memory.writeUtf8String(buffer, 'TracerPid:\t0');
            // console.log('tracerpid replaced: ' + Memory.readUtf8String(buffer));
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']));
};

Java.perform(function () {
    // console.log("---");
    // console.log("Unpinning Android app...");

    /// -- Generic hook to protect against SSLPeerUnverifiedException -- ///

    // In some cases, with unusual cert pinning approaches, or heavy obfuscation, we can't
    // match the real method & package names. This is a problem! Fortunately, we can still
    // always match built-in types, so here we spot all failures that use the built-in cert
    // error type (notably this includes OkHttp), and after the first failure, we dynamically
    // generate & inject a patch to completely disable the method that threw the error.
    try {
        const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverif~iedException');
        UnverifiedCertError.$init.implementation = function (str) {
            // console.log('  --> Unexpected SSL verification failure, adding dynamic patch...');

            try {
                const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                const exceptionStackIndex = stackTrace.findIndex(stack =>
                    stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                );
                const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                const className = callingFunctionStack.getClassName();
                const methodName = callingFunctionStack.getMethodName();

                // console.log(`      Thrown by ${className}->${methodName}`);

                const callingClass = Java.use(className);
                const callingMethod = callingClass[methodName];

                if (callingMethod.implementation) return; // Already patched by Frida - skip it

                // console.log('      Attempting to patch automatically...');
                const returnTypeName = callingMethod.returnType.type;

                callingMethod.implementation = function () {
                    // console.log(`  --> Bypassing ${className}->${methodName} (automatic exception patch)`);

                    // This is not a perfect fix! Most unknown cases like this are really just
                    // checkCert(cert) methods though, so doing nothing is perfect, and if we
                    // do need an actual return value then this is probably the best we can do,
                    // and at least we're logging the method name so you can patch it manually:

                    if (returnTypeName === 'void') {
                        return;
                    } else {
                        return null;
                    }
                };

                // console.log(`      [+] ${className}->${methodName} (automatic exception patch)`);
            } catch (e) {
                // console.log('      [ ] Failed to automatically patch failure');
            }

            return this.$init(str);
        };
        // console.log('[+] SSLPeerUnverifiedException auto-patcher');
    } catch (err) {
        // console.log('[ ] SSLPeerUnverifiedException auto-patcher');
    }

    /// -- Specific targeted hooks: -- ///

    // HttpsURLConnection
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
            // console.log('  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)');
            return; // Do nothing, i.e. don't change the hostname verifier
        };
        // console.log('[+] HttpsURLConnection (setDefaultHostnameVerifier)');
    } catch (err) {
        // console.log('[ ] HttpsURLConnection (setDefaultHostnameVerifier)');
    }
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
            // console.log('  --> Bypassing HttpsURLConnection (setSSLSocketFactory)');
            return; // Do nothing, i.e. don't change the SSL socket factory
        };
        // console.log('[+] HttpsURLConnection (setSSLSocketFactory)');
    } catch (err) {
        // console.log('[ ] HttpsURLConnection (setSSLSocketFactory)');
    }
    try {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
            // console.log('  --> Bypassing HttpsURLConnection (setHostnameVerifier)');
            return; // Do nothing, i.e. don't change the hostname verifier
        };
        // console.log('[+] HttpsURLConnection (setHostnameVerifier)');
    } catch (err) {
        // console.log('[ ] HttpsURLConnection (setHostnameVerifier)');
    }

    // SSLContext
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');

        const TrustManager = Java.registerClass({
            // Implement a custom TrustManager
            name: 'dev.asd.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });

        // Prepare the TrustManager array to pass to SSLContext.init()
        const TrustManagers = [TrustManager.$new()];

        // Get a handle on the init() on the SSLContext class
        const SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );

        // Override the init method, specifying the custom TrustManager
        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
            // console.log('  --> Bypassing Trustmanager (Android < 7) request');
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
        // console.log('[+] SSLContext');
    } catch (err) {
        // console.log('[ ] SSLContext');
    }

    // TrustManagerImpl (Android > 7)
    try {
        const array_list = Java.use("java.util.ArrayList");
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        // This step is notably what defeats the most common case: network security config
        TrustManagerImpl.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            // console.log('  --> Bypassing TrustManagerImpl checkTrusted ');
            return array_list.$new();
        }

        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            // console.log('  --> Bypassing TrustManagerImpl verifyChain: ' + host);
            return untrustedChain;
        };
        // console.log('[+] TrustManagerImpl');
    } catch (err) {
        // console.log('[ ] TrustManagerImpl');
    }

    // OkHTTPv3 (quadruple bypass)
    try {
        // Bypass OkHTTPv3 {1}
        const okhttp3_Activity_1 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_1.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            // console.log('  --> Bypassing OkHTTPv3 (list): ' + a);
            return;
        };
        // console.log('[+] OkHTTPv3 (list)');
    } catch (err) {
        // console.log('[ ] OkHTTPv3 (list)');
    }
    try {
        // Bypass OkHTTPv3 {2}
        // This method of CertificatePinner.check could be found in some old Android app
        const okhttp3_Activity_2 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_2.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
            // console.log('  --> Bypassing OkHTTPv3 (cert): ' + a);
            return;
        };
        // console.log('[+] OkHTTPv3 (cert)');
    } catch (err) {
        // console.log('[ ] OkHTTPv3 (cert)');
    }
    try {
        // Bypass OkHTTPv3 {3}
        const okhttp3_Activity_3 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (a, b) {
            // console.log('  --> Bypassing OkHTTPv3 (cert array): ' + a);
            return;
        };
        // console.log('[+] OkHTTPv3 (cert array)');
    } catch (err) {
        // console.log('[ ] OkHTTPv3 (cert array)');
    }
    try {
        // Bypass OkHTTPv3 {4}
        const okhttp3_Activity_4 = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity_4['check$okhttp'].implementation = function (a, b) {
            // console.log('  --> Bypassing OkHTTPv3 ($okhttp): ' + a);
            return;
        };
        // console.log('[+] OkHTTPv3 ($okhttp)');
    } catch (err) {
        // console.log('[ ] OkHTTPv3 ($okhttp)');
    }

    // Trustkit (triple bypass)
    try {
        // Bypass Trustkit {1}
        const trustkit_Activity_1 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
            // console.log('  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): ' + a);
            return true;
        };
        // console.log('[+] Trustkit OkHostnameVerifier(SSLSession)');
    } catch (err) {
        // console.log('[ ] Trustkit OkHostnameVerifier(SSLSession)');
    }
    try {
        // Bypass Trustkit {2}
        const trustkit_Activity_2 = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
            // console.log('  --> Bypassing Trustkit OkHostnameVerifier(cert): ' + a);
            return true;
        };
        // console.log('[+] Trustkit OkHostnameVerifier(cert)');
    } catch (err) {
        // console.log('[ ] Trustkit OkHostnameVerifier(cert)');
    }
    try {
        // Bypass Trustkit {3}
        const trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
            // console.log('  --> Bypassing Trustkit PinningTrustManager');
        };
        // console.log('[+] Trustkit PinningTrustManager');
    } catch (err) {
        // console.log('[ ] Trustkit PinningTrustManager');
    }

    // Appcelerator Titanium
    try {
        const appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
            // console.log('  --> Bypassing Appcelerator PinningTrustManager');
        };
        // console.log('[+] Appcelerator PinningTrustManager');
    } catch (err) {
        // console.log('[ ] Appcelerator PinningTrustManager');
    }

    // OpenSSLSocketImpl Conscrypt
    try {
        const OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
            // console.log('  --> Bypassing OpenSSLSocketImpl Conscrypt');
        };
        // console.log('[+] OpenSSLSocketImpl Conscrypt');
    } catch (err) {
        // console.log('[ ] OpenSSLSocketImpl Conscrypt');
    }

    // OpenSSLEngineSocketImpl Conscrypt
    try {
        const OpenSSLEngineSocketImpl_Activity = Java.use('com.android.org.conscrypt.OpenSSLEngineSocketImpl');
        OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload('[Ljava.lang.Long;', 'java.lang.String').implementation = function (a, b) {
            // console.log('  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + b);
        };
        // console.log('[+] OpenSSLEngineSocketImpl Conscrypt');
    } catch (err) {
        // console.log('[ ] OpenSSLEngineSocketImpl Conscrypt');
    }

    // OpenSSLSocketImpl Apache Harmony
    try {
        const OpenSSLSocketImpl_Harmony = Java.use('org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl');
        OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
            // console.log('  --> Bypassing OpenSSLSocketImpl Apache Harmony');
        };
        // console.log('[+] OpenSSLSocketImpl Apache Harmony');
    } catch (err) {
        // console.log('[ ] OpenSSLSocketImpl Apache Harmony');
    }

    // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
    try {
        const phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
        phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
            // console.log('  --> Bypassing PhoneGap sslCertificateChecker: ' + a);
            return true;
        };
        // console.log('[+] PhoneGap sslCertificateChecker');
    } catch (err) {
        // console.log('[ ] PhoneGap sslCertificateChecker');
    }

    // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
    try {
        // Bypass IBM MobileFirst {1}
        const WLClient_Activity_1 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload('java.lang.String').implementation = function (cert) {
            // console.log('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): ' + cert);
            return;
        };
        // console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
    } catch (err) {
        // console.log('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)');
    }
    try {
        // Bypass IBM MobileFirst {2}
        const WLClient_Activity_2 = Java.use('com.worklight.wlclient.api.WLClient');
        WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload('[Ljava.lang.String;').implementation = function (cert) {
            // console.log('  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): ' + cert);
            return;
        };
        // console.log('[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
    } catch (err) {
        // console.log('[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)');
    }

    // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
    try {
        // Bypass IBM WorkLight {1}
        const worklight_Activity_1 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_1.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (a, b) {
            // console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): ' + a);
            return;
        };
        // console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
    } catch (err) {
        // console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)');
    }
    try {
        // Bypass IBM WorkLight {2}
        const worklight_Activity_2 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_2.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
            // console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): ' + a);
            return;
        };
        // console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
    } catch (err) {
        // console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)');
    }
    try {
        // Bypass IBM WorkLight {3}
        const worklight_Activity_3 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_3.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (a, b) {
            // console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): ' + a);
            return;
        };
        // console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
    } catch (err) {
        // console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)');
    }
    try {
        // Bypass IBM WorkLight {4}
        const worklight_Activity_4 = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity_4.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
            // console.log('  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): ' + a);
            return true;
        };
        // console.log('[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
    } catch (err) {
        // console.log('[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)');
    }

    // Conscrypt CertPinManager
    try {
        const conscrypt_CertPinManager_Activity = Java.use('com.android.org.conscrypt.CertPinManager');
        conscrypt_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            // console.log('  --> Bypassing Conscrypt CertPinManager: ' + a);
            return true;
        };
        // console.log('[+] Conscrypt CertPinManager');
    } catch (err) {
        // console.log('[ ] Conscrypt CertPinManager');
    }

    // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager
    try {
        const cwac_CertPinManager_Activity = Java.use('com.commonsware.cwac.netsecurity.conscrypt.CertPinManager');
        cwac_CertPinManager_Activity.isChainValid.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            // console.log('  --> Bypassing CWAC-Netsecurity CertPinManager: ' + a);
            return true;
        };
        // console.log('[+] CWAC-Netsecurity CertPinManager');
    } catch (err) {
        // console.log('[ ] CWAC-Netsecurity CertPinManager');
    }

    // Worklight Androidgap WLCertificatePinningPlugin
    try {
        const androidgap_WLCertificatePinningPlugin_Activity = Java.use('com.worklight.androidgap.plugin.WLCertificatePinningPlugin');
        androidgap_WLCertificatePinningPlugin_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (a, b, c) {
            // console.log('  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + a);
            return true;
        };
        // console.log('[+] Worklight Androidgap WLCertificatePinningPlugin');
    } catch (err) {
        // console.log('[ ] Worklight Androidgap WLCertificatePinningPlugin');
    }

    // Netty FingerprintTrustManagerFactory
    try {
        const netty_FingerprintTrustManagerFactory = Java.use('io.netty.handler.ssl.util.FingerprintTrustManagerFactory');
        netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
            // console.log('  --> Bypassing Netty FingerprintTrustManagerFactory');
        };
        // console.log('[+] Netty FingerprintTrustManagerFactory');
    } catch (err) {
        // console.log('[ ] Netty FingerprintTrustManagerFactory');
    }

    // Squareup CertificatePinner [OkHTTP<v3] (double bypass)
    try {
        // Bypass Squareup CertificatePinner {1}
        const Squareup_CertificatePinner_Activity_1 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_1.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (a, b) {
            // console.log('  --> Bypassing Squareup CertificatePinner (cert): ' + a);
            return;
        };
        // console.log('[+] Squareup CertificatePinner (cert)');
    } catch (err) {
        // console.log('[ ] Squareup CertificatePinner (cert)');
    }
    try {
        // Bypass Squareup CertificatePinner {2}
        const Squareup_CertificatePinner_Activity_2 = Java.use('com.squareup.okhttp.CertificatePinner');
        Squareup_CertificatePinner_Activity_2.check.overload('java.lang.String', 'java.util.List').implementation = function (a, b) {
            // console.log('  --> Bypassing Squareup CertificatePinner (list): ' + a);
            return;
        };
        // console.log('[+] Squareup CertificatePinner (list)');
    } catch (err) {
        // console.log('[ ] Squareup CertificatePinner (list)');
    }

    // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
    try {
        // Bypass Squareup OkHostnameVerifier {1}
        const Squareup_OkHostnameVerifier_Activity_1 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_1.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (a, b) {
            // console.log('  --> Bypassing Squareup OkHostnameVerifier (cert): ' + a);
            return true;
        };
        // console.log('[+] Squareup OkHostnameVerifier (cert)');
    } catch (err) {
        // console.log('[ ] Squareup OkHostnameVerifier (cert)');
    }
    try {
        // Bypass Squareup OkHostnameVerifier {2}
        const Squareup_OkHostnameVerifier_Activity_2 = Java.use('com.squareup.okhttp.internal.tls.OkHostnameVerifier');
        Squareup_OkHostnameVerifier_Activity_2.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (a, b) {
            // console.log('  --> Bypassing Squareup OkHostnameVerifier (SSLSession): ' + a);
            return true;
        };
        // console.log('[+] Squareup OkHostnameVerifier (SSLSession)');
    } catch (err) {
        // console.log('[ ] Squareup OkHostnameVerifier (SSLSession)');
    }

    // Android WebViewClient (double bypass)
    try {
        // Bypass WebViewClient {1} (deprecated from Android 6)
        const AndroidWebViewClient_Activity_1 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_1.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
            // console.log('  --> Bypassing Android WebViewClient (SslErrorHandler)');
        };
        // console.log('[+] Android WebViewClient (SslErrorHandler)');
    } catch (err) {
        // console.log('[ ] Android WebViewClient (SslErrorHandler)');
    }
    try {
        // Bypass WebViewClient {2}
        const AndroidWebViewClient_Activity_2 = Java.use('android.webkit.WebViewClient');
        AndroidWebViewClient_Activity_2.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function (obj1, obj2, obj3) {
            // console.log('  --> Bypassing Android WebViewClient (WebResourceError)');
        };
        // console.log('[+] Android WebViewClient (WebResourceError)');
    } catch (err) {
        // console.log('[ ] Android WebViewClient (WebResourceError)');
    }

    // Apache Cordova WebViewClient
    try {
        const CordovaWebViewClient_Activity = Java.use('org.apache.cordova.CordovaWebViewClient');
        CordovaWebViewClient_Activity.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (obj1, obj2, obj3) {
            // console.log('  --> Bypassing Apache Cordova WebViewClient');
            obj3.proceed();
        };
    } catch (err) {
        // console.log('[ ] Apache Cordova WebViewClient');
    }

    // Boye AbstractVerifier
    try {
        const boye_AbstractVerifier = Java.use('ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier');
        boye_AbstractVerifier.verify.implementation = function (host, ssl) {
            // console.log('  --> Bypassing Boye AbstractVerifier: ' + host);
        };
    } catch (err) {
        // console.log('[ ] Boye AbstractVerifier');
    }

    // Appmattus
    try {
        const appmatus_Activity = Java.use('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor');
        appmatus_Activity['intercept'].implementation = function (a) {
            // console.log('  --> Bypassing Appmattus (Transparency)');
            return a.proceed(a.request());
        };
        // console.log('[+] Appmattus (CertificateTransparencyInterceptor)');
    } catch (err) {
        // console.log('[ ] Appmattus (CertificateTransparencyInterceptor)');
    }

    try {
        const CertificateTransparencyTrustManager = Java.use(
            'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager'
        );
        CertificateTransparencyTrustManager['checkServerTrusted'].overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String'
        ).implementation = function (x509CertificateArr, str) {
            // console.log('  --> Bypassing Appmattus (CertificateTransparencyTrustManager)');
        };
        CertificateTransparencyTrustManager['checkServerTrusted'].overload(
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ).implementation = function (x509CertificateArr, str, str2) {
            // console.log('  --> Bypassing Appmattus (CertificateTransparencyTrustManager)');
            return Java.use('java.util.ArrayList').$new();
        };
        // console.log('[+] Appmattus (CertificateTransparencyTrustManager)');
    } catch (err) {
        // console.log('[ ] Appmattus (CertificateTransparencyTrustManager)');
    }

    // console.log("Unpinning setup completed");
    // console.log("---");
});


// 获取调用链
function getStackTrace() {
    var Exception = Java.use('java.lang.Exception');
    var ins = Exception.$new('Exception');
    var straces = ins.getStackTrace();
    if (undefined == straces || null == straces) {
        return;
    }
    var result = '';
    for (var i = 0; i < straces.length; i++) {
        var str = '   ' + straces[i].toString();
        result += str + '\r\n';
    }
    Exception.$dispose();
    return result;
}

function get_format_time() {
    var myDate = new Date();

    return myDate.getFullYear() + '-' + myDate.getMonth() + '-' + myDate.getDate() + ' ' + myDate.getHours() + ':' + myDate.getMinutes() + ':' + myDate.getSeconds();
}

//告警发送
function alertSend(action, messages, arg, returnValue) {
    var _time = get_format_time();
    if (returnValue == undefined) returnValue = '无返回值';
    send({
        'type': 'notice',
        'time': _time,
        'action': action,
        'messages': messages,
        'arg': arg,
        'returnValue': returnValue,
        'stacks': getStackTrace()
    });
}

// 增强健壮性，避免有的设备无法使用 Array.isArray 方法
if (!Array.isArray) {
    Array.isArray = function (arg) {
        return Object.prototype.toString.call(arg) === '[object Array]';
    };
}

function b2s(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
        result += String.fromCharCode((array[i] % 256 + 256 ) % 256);
    }
    return result;
}

function b2Ascii(b) {
    var result = "";
    result += String.fromCharCode((b % 256 + 256 ) % 256);
    return result;
}

function isByteArray(obj) {
    if (Array.isArray(JSON.parse(JSON.stringify(obj)))) {
        return true;
    }
    return false;
}

// 递归获取对象的所有字段
function getAllFields(obj, depth) {
    if (isByteArray(obj)) {
        return b2s(obj);
    }
    var result = {};
    if (simpleOnly) return JSON.stringify(obj, null, 4);
    if (depth === maxDepth) {
        try {
            return JSON.stringify(obj.toString(), null, 4);
        } catch (e) {
            return JSON.stringify(obj, null, 4);
        }
    }
    try {
        var objClass = obj.getClass();
        // 处理基本类型
        {
            switch (obj.getClass().getName()) {
                case "java.lang.String":
                    return obj.toString();
                case "java.lang.Integer":
                    return obj.intValue();
                case "java.lang.Boolean":
                    return obj.booleanValue();
                case "java.lang.Long":
                    return obj.longValue();
                case "java.lang.Double":
                    return obj.doubleValue();
                case "java.lang.Float":
                    return obj.floatValue();
                case "java.lang.Short":
                    return obj.shortValue();
                case "java.lang.Byte":
                    return obj.byteValue();
                case "java.lang.Character":
                    return obj.charValue();
                case "java.lang.Void":
                    return "void";
                case "java.lang.Object":
                    return JSON.stringify(obj, null, 4);
                case "java.lang.Class":
                    return obj.getName();
                case "java.lang.Throwable":
                case "java.lang.Enum":
                    return obj.toString();
                default:
                    break;
            }
            const className = obj.getClass().getName();

            // 处理 startsWith 的情况
            {
                if (className.startsWith("android.") ||
                    className.startsWith("java.") ||
                    className.startsWith("javax.") ||
                    className.startsWith("androidx.") ||
                    className.startsWith("kotlin.") ||
                    className.startsWith("kotlinx.") ||
                    className.startsWith("sun.") ||
                    className.startsWith("org.apache.") ||
                    className.startsWith("org.eclipse.") ||
                    className.startsWith("jdk.")) {
                    return JSON.stringify(obj.toString(), null, 4);
                }
            }
            
        }
        
        var fields = objClass.getDeclaredFields();
        fields.forEach(function(field) {
            try {
                field.setAccessible(true);
                var value = field.get(obj);
                result[field.getName()] = getAllFields(value, depth+1);
                console.log(value);
                // result[field.getName()] = JSON.stringify(value, null, 4);
            } catch (e) {
                result[field.getName()] = "Cannot access";
            }
        });
    } catch (e) {
        result = JSON.stringify(obj, null, 4);
    }
    
    return JSON.stringify(result, null, 4);
}

// hook方法
function hookMethod(targetClass, targetMethod, targetArgs, action, messages) {
    try {
        var _Class = Java.use(targetClass);
    } catch (e) {
        return false;
    }

    if (targetMethod == '$init') {
        var overloadCount = _Class.$init.overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            _Class.$init.overloads[i].implementation = function () {
                var temp = this.$init.apply(this, arguments);
                // 是否含有需要过滤的参数
                var argumentValues = Object.values(arguments);
                if (Array.isArray(targetArgs) && targetArgs.length > 0 && !targetArgs.every(item => argumentValues.includes(item))) {
                    return null;
                }
                var arg = '';
                for (var j = 0; j < arguments.length; j++) {
                    arg += '参数' + j + '：' + JSON.stringify(arguments[j], null, 4) + '\r\n';
                }
                if (arg.length == 0) arg = '无参数';
                else arg = arg.slice(0, arg.length - 1);
                var rv = JSON.stringify(temp, null, 4);
                alertSend(action, messages, arg, rv);
                return temp;
            }
        }
    } else {
        try {
            var overloadCount = _Class[targetMethod].overloads.length;
        } catch (e) {
            console.log(e)
            console.log('[*] hook(' + targetMethod + ')方法失败,请检查该方法是否存在！！！');
            return false;
        }
        for (var i = 0; i < overloadCount; i++) {
            _Class[targetMethod].overloads[i].implementation = function () {
                var temp = this[targetMethod].apply(this, arguments);
                // 是否含有需要过滤的参数
                var argumentValues = Object.values(arguments);
                if (Array.isArray(targetArgs) && targetArgs.length > 0 && !targetArgs.every(item => argumentValues.includes(item))) {
                    return null;
                }
                var arg = '';
                for (var j = 0; j < arguments.length; j++) {
                    // arg += '参数' + j + '：' + JSON.stringify(arguments[j], null, 4) + '\r\n';
                    let argStr = arguments[j];
                    if (arg !== null && arg !== undefined) {
                        // 如果参数是对象，递归打印对象的所有字段
                        arg += '参数' + j + '：' + getAllFields(arguments[j], 0) + '\r\n';
                    } else {
                        arg += '参数' + j + '：' + JSON.stringify(arguments[j], null, 4) + '\r\n';
                    }
                }
                if (arg.length == 0) arg = '无参数';
                else arg = arg.slice(0, arg.length - 1);
                // var rv = JSON.stringify(temp, null, 4);
                if (temp !== null && temp !== undefined) {
                    // 如果返回值是对象，递归打印对象的所有字段
                    var rv = getAllFields(temp, 0);
                } else {
                    var rv = JSON.stringify(temp, null, 4);
                }
                alertSend(action, messages, arg, rv);
                return temp;
            }
        }
    }
    return true;
}

// hook方法(去掉不存在方法）
function hook(targetClass, methodData) {
    try {
        var _Class = Java.use(targetClass);
    } catch (e) {
        return false;
    }
    var methods = _Class.class.getDeclaredMethods();
    _Class.$dispose;
    // 排查掉不存在的方法，用于各个android版本不存在方法报错问题。
    methodData.forEach(function (methodData) {
        for (var i in methods) {
            if (methods[i].toString().indexOf('.' + methodData['methodName'] + '(') != -1 || methodData['methodName'] == '$init') {
                hookMethod(targetClass, methodData['methodName'], methodData['args'], methodData['action'], methodData['messages']);
                break;
            }
        }
    });
}

function cryptoHook() {
    var action = '加密算法';

    hook('javax.crypto.Cipher', [
        {'methodName': 'doFinal', 'action': action, 'messages': '执行加密/解密操作'},
        {'methodName': 'update', 'action': action, 'messages': '执行加密/解密的更新操作(例如CBC模式)'},
    ]);
    // hook('javax.crypto.Mac', [
    //     {'methodName': 'doFinal', 'action': action, 'messages': '计算MAC(消息验证代码)'},
    //     {'methodName': 'update', 'action': action, 'messages': '增加MAC(消息验证代码)计算的输入'},
    // ]);
    hook('android.util.Base64', [
        {'methodName': 'encode', 'action': action, 'messages': 'Base64编码'},
        {'methodName': 'decode', 'action': action, 'messages': 'Base64解码'},
    ]);
    // hook('java.security.MessageDigest', [
    //     {'methodName': 'update', 'action': action, 'messages': '计算摘要'},
    //     {'methodName': 'digest', 'action': action, 'messages': '使用给定输入更新摘要'},
    // ]);
    // hook('javax.crypto.spec.SecretKeySpec', [
    //     {'methodName': 'doFinal', 'action': action, 'messages': '加密算法'},
    //     {'methodName': '$init', 'action': action, 'messages': '加密算法'},
    // ]);
    // hook('javax.crypto.spec.IvParameterSpec', [
    //     {'methodName': '$init', 'action': action, 'messages': '加密算法'},
    // ]);
    // hook('java.security.KeyFactory', [
    //     {'methodName': 'getInstance', 'action': action, 'messages': '加密算法'},
    // ]);
    // hook('java.security.spec.EncodedKeySpec', [
        // {'methodName': 'getEncoded', 'action': action, 'messages': '创建编码后的密钥'},
    // ]);
    // hook('java.security.cert.CertificateFactory', [
    //     {'methodName': 'generateCertificate', 'action': action, 'messages': '生成证书'},
    // ]);
}

function customHook() {
    cryptoHook();
}

function useModule(moduleList) {
    var _module = {
        'custom': [customHook]
    };
    var _m = Object.keys(_module);
    var tmp_m = []
    if (moduleList['type'] !== 'all') {
        var input_module_data = moduleList['data'].split(',');
        for (i = 0; i < input_module_data.length; i++) {
            if (_m.indexOf(input_module_data[i]) === -1) {
                send({'type': 'noFoundModule', 'data': input_module_data[i]})
            } else {
                tmp_m.push(input_module_data[i])
            }
        }
    }
    switch (moduleList['type']) {
        case 'use':
            _m = tmp_m;
            break;
        case 'nouse':
            for (var i = 0; i < input_module_data.length; i++) {
                for (var j = 0; j < _m.length; j++) {
                    if (_m[j] == input_module_data[i]) {
                        _m.splice(j, 1);
                        j--;
                    }
                }
            }
            break;
    }
    send({'type': 'loadModule', 'data': _m})
    if (_m.length !== 0) {
        for (i = 0; i < _m.length; i++) {
            for (j = 0; j < _module[_m[i]].length; j++) {
                _module[_m[i]][j]();
            }
        }
    }
}

function main() {
    try {
        Java.perform(function () {
            console.log('[*] ' + get_format_time() + ' 隐私合规检测敏感接口开始监控...');
            send({"type": "isHook"})
            console.log('[*] ' + get_format_time() + ' 检测到安卓版本：' + Java.androidVersion);
            var moduleList;
            recv(function (received_json_object) {
                moduleList = received_json_object.use_module;
            }).wait();
            useModule(moduleList);
        });
    } catch (e) {
        console.log(e)
    }
}

// 绕过TracerPid检测 默认关闭，有必要时再自行打开
// setImmediate(ByPassTracerPid);

//在spawn模式下，hook系统API时如javax.crypto.Cipher建议使用setImmediate立即执行，不需要延时
//在spawn模式下，hook应用自己的函数或含壳时，建议使用setTimeout并给出适当的延时(500~5000)

// main();
//setImmediate(main)
// setTimeout(main, 3000);

