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
        const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
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

// 递归获取对象的所有字段
function getAllFields(obj, depth) {
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
            // 处理 startsWith 的情况
            const className = obj.getClass().getName();
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

// hook获取其他app信息api，排除app自身
function hookApplicationPackageManagerExceptSelf(targetMethod, action) {
    var _ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
    try {
        try {
            var overloadCount = _ApplicationPackageManager[targetMethod].overloads.length;
        } catch (e) {
            return false;
        }
        for (var i = 0; i < overloadCount; i++) {
            _ApplicationPackageManager[targetMethod].overloads[i].implementation = function () {
                var temp = this[targetMethod].apply(this, arguments);
                var arg = '';
                for (var j = 0; j < arguments.length; j++) {
                    if (j === 0) {
                        var string_to_recv;
                        send({'type': 'app_name', 'data': arguments[j]});
                        recv(function (received_json_object) {
                            string_to_recv = received_json_object.my_data;
                        }).wait();
                    }
                    arg += '参数' + j + '：' + JSON.stringify(arguments[j], null, 4) + '\r\n';
                }
                if (arg.length == 0) arg = '无参数';
                else arg = arg.slice(0, arg.length - 1);
                if (string_to_recv) {
                    var rv = JSON.stringify(temp, null, 4);
                    alertSend(action, targetMethod + '获取的数据为：' + temp, arg, rv);
                }
                return temp;
            }
        }
    } catch (e) {
        console.log(e);
        return
    }


}

// 申请权限
function checkRequestPermission() {
    var action = '申请权限';

    //老项目
    hook('android.support.v4.app.ActivityCompat', [
        {'methodName': 'requestPermissions', 'action': action, 'messages': '申请具体权限看"参数1"'}
    ]);

    hook('androidx.core.app.ActivityCompat', [
        {'methodName': 'requestPermissions', 'action': action, 'messages': '申请具体权限看"参数1"'}
    ]);
}

// 获取电话相关信息
function getPhoneState() {
    var action = '获取电话相关信息';

    hook('android.telephony.TelephonyManager', [
        // Android 8.0
        {'methodName': 'getDeviceId', 'action': action, 'messages': '获取IMEI'},
        // Android 8.1、9   android 10获取不到
        {'methodName': 'getImei', 'action': action, 'messages': '获取IMEI'},

        {'methodName': 'getMeid', 'action': action, 'messages': '获取MEID'},
        {'methodName': 'getLine1Number', 'action': action, 'messages': '获取电话号码标识符'},
        {'methodName': 'getSimSerialNumber', 'action': action, 'messages': '获取IMSI/iccid'},
        {'methodName': 'getSubscriberId', 'action': action, 'messages': '获取IMSI'},
        {'methodName': 'getSimOperator', 'action': action, 'messages': '获取MCC/MNC'},
        {'methodName': 'getNetworkOperator', 'action': action, 'messages': '获取MCC/MNC'},
        {'methodName': 'getSimCountryIso', 'action': action, 'messages': '获取SIM卡国家代码'},

        {'methodName': 'getCellLocation', 'action': action, 'messages': '获取电话当前位置信息'},
        {'methodName': 'getAllCellInfo', 'action': action, 'messages': '获取电话当前位置信息'},
        {'methodName': 'requestCellInfoUpdate', 'action': action, 'messages': '获取基站信息'},
        // {'methodName': 'getServiceState', 'action': action, 'messages': '获取sim卡是否可用'},
    ]);

    // 电信卡cid lac
    hook('android.telephony.cdma.CdmaCellLocation', [
        {'methodName': 'getBaseStationId', 'action': action, 'messages': '获取基站cid信息'},
        {'methodName': 'getNetworkId', 'action': action, 'messages': '获取基站lac信息'}
    ]);

    // 移动联通卡 cid/lac
    hook('android.telephony.gsm.GsmCellLocation', [
        {'methodName': 'getCid', 'action': action, 'messages': '获取基站cid信息'},
        {'methodName': 'getLac', 'action': action, 'messages': '获取基站lac信息'}
    ]);

    // 短信
    // hook('android.telephony.SmsManager', [
    //     {'methodName': 'sendTextMessageInternal', 'action': action, 'messages': '获取短信信息-发送短信'},
    //     {'methodName': 'getDefault', 'action': action, 'messages': '获取短信信息-发送短信'},
    //     {'methodName': 'sendTextMessageWithSelfPermissions', 'action': action, 'messages': '获取短信信息-发送短信'},
    //     {'methodName': 'sendMultipartTextMessageInternal', 'action': action, 'messages': '获取短信信息-发送短信'},
    //     {'methodName': 'sendDataMessage', 'action': action, 'messages': '获取短信信息-发送短信'},
    //     {'methodName': 'sendDataMessageWithSelfPermissions', 'action': action, 'messages': '获取短信信息-发送短信'},
    // ]);

}

// 系统信息(AndroidId/标识/content敏感信息)
function getSystemData() {
    var action = '获取系统信息';

    hook('android.provider.Settings$Secure', [
        {'methodName': 'getString', 'args': ['android_id'], 'action': action, 'messages': '获取安卓ID'}
    ]);
    hook('android.provider.Settings$System', [
        {'methodName': 'getString', 'args': ['android_id'], 'action': action, 'messages': '获取安卓ID'}
    ]);


    hook('android.os.Build', [
        {'methodName': 'getSerial', 'action': action, 'messages': '获取设备序列号'},
    ]);

    hook('android.app.admin.DevicePolicyManager', [
        {'methodName': 'getWifiMacAddress', 'action': action, 'messages': '获取mac地址'},
    ]);

    // hook('android.content.ClipboardManager', [
    //     {'methodName': 'getPrimaryClip', 'action': action, 'messages': '读取剪切板信息'},
    //     {'methodName': 'setPrimaryClip', 'action': action, 'messages': '写入剪切板信息'},
    // ]);

    hook('android.telephony.UiccCardInfo', [
        {'methodName': 'getIccId', 'action': action, 'messages': '读取手机IccId信息'},
    ]);

    //小米
    hook('com.android.id.impl.IdProviderImpl', [
        {'methodName': 'getUDID', 'action': action, 'messages': '读取小米手机UDID'},
        {'methodName': 'getOAID', 'action': action, 'messages': '读取小米手机OAID'},
        {'methodName': 'getVAID', 'action': action, 'messages': '读取小米手机VAID'},
        {'methodName': 'getAAID', 'action': action, 'messages': '读取小米手机AAID'},
    ]);

    //三星
    hook('com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy', [
        {'methodName': 'getOAID', 'action': action, 'messages': '读取三星手机OAID'},
        {'methodName': 'getVAID', 'action': action, 'messages': '读取三星手机VAID'},
        {'methodName': 'getAAID', 'action': action, 'messages': '读取三星手机AAID'},
    ]);

    hook('repeackage.com.samsung.android.deviceidservice.IDeviceIdService$Stub$Proxy', [
        {'methodName': 'getOAID', 'action': action, 'messages': '读取三星手机OAID'},
        {'methodName': 'getVAID', 'action': action, 'messages': '读取三星手机VAID'},
        {'methodName': 'getAAID', 'action': action, 'messages': '读取三星手机AAID'},
    ]);

    //获取content敏感信息
    // try {
    //     // 通讯录内容
    //     var ContactsContract = Java.use('android.provider.ContactsContract');
    //     var contact_authority = ContactsContract.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    // } catch (e) {
    //     console.log(e)
    // }
    // try {
    //     // 日历内容
    //     var CalendarContract = Java.use('android.provider.CalendarContract');
    //     var calendar_authority = CalendarContract.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    // } catch (e) {
    //     console.log(e)
    // }
    // try {
    //     // 浏览器内容
    //     var BrowserContract = Java.use('android.provider.BrowserContract');
    //     var browser_authority = BrowserContract.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    // } catch (e) {
    //     console.log(e)
    // }
    // try {
    //     // 相册内容
    //     var MediaStore = Java.use('android.provider.MediaStore');
    //     var media_authority = MediaStore.class.getDeclaredField('AUTHORITY').get('java.lang.Object');
    // } catch (e) {
    //     console.log(e)
    // }
    // try {
    //     var ContentResolver = Java.use('android.content.ContentResolver');
    //     var queryLength = ContentResolver.query.overloads.length;
    //     for (var i = 0; i < queryLength; i++) {
    //         ContentResolver.query.overloads[i].implementation = function () {
    //             var temp = this.query.apply(this, arguments);
    //             if (arguments[0].toString().indexOf(contact_authority) != -1) {
    //                 var rv = JSON.stringify(temp, null, 4);
    //                 alertSend(action, '获取手机通信录内容', '', rv);
    //             } else if (arguments[0].toString().indexOf(calendar_authority) != -1) {
    //                 var rv = JSON.stringify(temp, null, 4);
    //                 alertSend(action, '获取日历内容', '', rv);
    //             } else if (arguments[0].toString().indexOf(browser_authority) != -1) {
    //                 var rv = JSON.stringify(temp, null, 4);
    //                 alertSend(action, '获取浏览器内容', '', rv);
    //             } else if (arguments[0].toString().indexOf(media_authority) != -1) {
    //                 var rv = JSON.stringify(temp, null, 4);
    //                 alertSend(action, '获取相册内容', '', rv);
    //             }
    //             return temp;
    //         }
    //     }
    // } catch (e) {
    //     console.log(e);
    //     return
    // }
}

//获取其他app信息
function getPackageManager() {
    var action = '获取其他app信息';

    hook('android.content.pm.PackageManager', [
        {'methodName': 'getInstalledPackages', 'action': action, 'messages': 'APP获取了其他app信息'},
        {'methodName': 'getInstalledApplications', 'action': action, 'messages': 'APP获取了其他app信息'}
    ]);

    hook('android.app.ApplicationPackageManager', [
        {'methodName': 'getInstalledPackages', 'action': action, 'messages': 'APP获取了其他app信息'},
        {'methodName': 'getInstalledApplications', 'action': action, 'messages': 'APP获取了其他app信息'},
        {'methodName': 'queryIntentActivities', 'action': action, 'messages': 'APP获取了其他app信息'},
    ]);

    hook('android.app.ActivityManager', [
        {'methodName': 'getRunningAppProcesses', 'action': action, 'messages': '获取了正在运行的App'},
        {'methodName': 'getRunningServiceControlPanel', 'action': action, 'messages': '获取了正在运行的服务面板'},
    ]);
    //需排除应用本身
    hookApplicationPackageManagerExceptSelf('getApplicationInfo', action);
    hookApplicationPackageManagerExceptSelf('getPackageInfoAsUser', action);
    hookApplicationPackageManagerExceptSelf('getInstallerPackageName', action);
}

// 获取位置信息
function getGSP() {
    var action = '获取位置信息';

    hook('android.location.LocationManager', [
        {'methodName': 'requestLocationUpdates', 'action': action, 'messages': action},
        {'methodName': 'getLastKnownLocation', 'action': action, 'messages': action},
        {'methodName': 'getBestProvider', 'action': action, 'messages': action},
        {'methodName': 'getGnssHardwareModelName', 'action': action, 'messages': action},
        {'methodName': 'getGnssYearOfHardware', 'action': action, 'messages': action},
        {'methodName': 'getProvider', 'action': action, 'messages': action},
        {'methodName': 'requestSingleUpdate', 'action': action, 'messages': action},
        {'methodName': 'getCurrentLocation', 'action': action, 'messages': action},
    ]);

    hook('android.location.Location', [
        {'methodName': 'getAccuracy', 'action': action, 'messages': action},
        {'methodName': 'getAltitude', 'action': action, 'messages': action},
        {'methodName': 'getBearing', 'action': action, 'messages': action},
        {'methodName': 'getBearingAccuracyDegrees', 'action': action, 'messages': action},
        {'methodName': 'getElapsedRealtimeNanos', 'action': action, 'messages': action},
        {'methodName': 'getExtras', 'action': action, 'messages': action},
        {'methodName': 'getLatitude', 'action': action, 'messages': action},
        {'methodName': 'getLongitude', 'action': action, 'messages': action},
        {'methodName': 'getProvider', 'action': action, 'messages': action},
        {'methodName': 'getSpeed', 'action': action, 'messages': action},
        {'methodName': 'getSpeedAccuracyMetersPerSecond', 'action': action, 'messages': action},
        {'methodName': 'getTime', 'action': action, 'messages': action},
        {'methodName': 'getVerticalAccuracyMeters', 'action': action, 'messages': action},
    ]);

    hook('android.location.Geocoder', [
        {'methodName': 'getFromLocation', 'action': action, 'messages': action},
        {'methodName': 'getFromLocationName', 'action': action, 'messages': action},
    ]);

}

// 调用摄像头(hook，防止静默拍照)
function getCamera() {
    var action = '调用摄像头';

    hook('android.hardware.Camera', [
        {'methodName': 'open', 'action': action, 'messages': action},
    ]);

    hook('android.hardware.camera2.CameraManager', [
        {'methodName': 'openCamera', 'action': action, 'messages': action},
    ]);

    hook('androidx.camera.core.ImageCapture', [
        {'methodName': 'takePicture', 'action': action, 'messages': '调用摄像头拍照'},
    ]);

}

//获取网络信息
function getNetwork() {
    var action = '获取网络信息';

    hook('android.net.wifi.WifiInfo', [
        {'methodName': 'getMacAddress', 'action': action, 'messages': '获取Mac地址'},
        {'methodName': 'getSSID', 'action': action, 'messages': '获取wifi SSID'},
        {'methodName': 'getBSSID', 'action': action, 'messages': '获取wifi BSSID'},
    ]);

    // hook('android.net.wifi.WifiManager', [
    //     {'methodName': 'getConnectionInfo', 'action': action, 'messages': '获取wifi信息'},
    //     {'methodName': 'getConfiguredNetworks', 'action': action, 'messages': '获取wifi信息'},
    //     {'methodName': 'getScanResults', 'action': action, 'messages': '获取wifi信息'},
    //     {'methodName': 'getWifiState', 'action': action, 'messages': '获取wifi状态信息'},
    // ]);

    hook('java.net.InetAddress', [
        {'methodName': 'getHostAddress', 'action': action, 'messages': '获取IP地址'},
        {'methodName': 'getAddress', 'action': action, 'messages': '获取网络address信息'},
        {'methodName': 'getHostName', 'action': action, 'messages': '获取网络hostname信息'},
    ]);

    hook('java.net.Inet4Address', [
        {'methodName': 'getHostAddress', 'action': action, 'messages': '获取IP地址'},
    ]);

    hook('java.net.Inet6Address', [
        {'methodName': 'getHostAddress', 'action': action, 'messages': '获取IP地址'},
    ]);

    hook('java.net.NetworkInterface', [
        {'methodName': 'getHardwareAddress', 'action': action, 'messages': '获取Mac地址'}
    ]);

    // hook('android.net.NetworkInfo', [
    //     {'methodName': 'getType', 'action': action, 'messages': '获取网络类型'},
    //     {'methodName': 'getTypeName', 'action': action, 'messages': '获取网络类型名称'},
    //     {'methodName': 'getExtraInfo', 'action': action, 'messages': '获取网络名称'},
    //     {'methodName': 'isAvailable', 'action': action, 'messages': '获取网络是否可用'},
    //     {'methodName': 'isConnected', 'action': action, 'messages': '获取网络是否连接'},
    // ]);

    // hook('android.net.ConnectivityManager', [
    //     {'methodName': 'getActiveNetworkInfo', 'action': action, 'messages': '获取网络状态信息'},
    // ]);

    // hook('java.net.InetSocketAddress', [
    //     {'methodName': 'getHostAddress', 'action': action, 'messages': '获取网络hostaddress信息'},
    //     {'methodName': 'getAddress', 'action': action, 'messages': '获取网络address信息'},
    //     {'methodName': 'getHostName', 'action': action, 'messages': '获取网络hostname信息'},
    // ]);

    // ip地址
    try {
        var _WifiInfo = Java.use('android.net.wifi.WifiInfo');
        //获取ip
        _WifiInfo.getIpAddress.implementation = function () {
            var temp = this.getIpAddress();
            var _ip = new Array();
            _ip[0] = (temp >>> 24) >>> 0;
            _ip[1] = ((temp << 8) >>> 24) >>> 0;
            _ip[2] = (temp << 16) >>> 24;
            _ip[3] = (temp << 24) >>> 24;
            var _str = String(_ip[3]) + "." + String(_ip[2]) + "." + String(_ip[1]) + "." + String(_ip[0]);
            var rv = JSON.stringify(temp, null, 4);
            alertSend(action, '获取IP地址：' + _str, '', rv);
            return temp;
        }
    } catch (e) {
        console.log(e)
    }
}

//获取蓝牙设备信息
function getBluetooth() {
    var action = '获取蓝牙设备信息';

    hook('android.bluetooth.BluetoothDevice', [
        // {'methodName': 'getName', 'action': action, 'messages': '获取蓝牙设备名称'},
        {'methodName': 'getAddress', 'action': action, 'messages': '获取蓝牙设备mac'},
    ]);

    // hook('android.bluetooth.BluetoothAdapter', [
    //     {'methodName': 'getName', 'action': action, 'messages': '获取蓝牙设备名称'}
    // ]);
}

//读写文件
function getFileMessage() {
    var action = '文件操作';

    hook('java.io.RandomAccessFile', [
        {'methodName': '$init', 'action': action, 'messages': 'RandomAccessFile写文件'}
    ]);
    hook('java.io.File', [
        {'methodName': 'mkdirs', 'action': action, 'messages': '尝试写入sdcard创建小米市场审核可能不通过'},
        {'methodName': 'mkdir', 'action': action, 'messages': '尝试写入sdcard创建小米市场审核可能不通过'}
    ]);
}

//获取麦克风信息
function getMedia() {
    var action = '获取麦克风'

    hook('android.media.MediaRecorder', [
        {'methodName': 'start', 'action': action, 'messages': '获取麦克风'},
    ]);
    hook('android.media.AudioRecord', [
        {'methodName': 'startRecording', 'action': action, 'messages': '获取麦克风'},
    ]);
}

//获取传感器信息
function getSensor() {
    var action = '获取传感器信息'

    hook('android.hardware.SensorManager', [
        {'methodName': 'getSensorList', 'action': action, 'messages': '获取传感器信息'},
    ]);

}

function customHook() {
    var action = '用户自定义hook';
    // hook('android.webkit.WebView', [
    //     {'methodName': 'loadUrl', 'action': action, 'messages': '加载url'}
    // ]);
    // hook('ndroid.content.Context', [
    //     {'methodName': 'startActivity', 'action': action, 'messages': '启动activity'},
    //     {'methodName': 'startActivityForResult', 'action': action, 'messages': '启动activityForResult'},
    //     {'methodName': 'sendBroadcast', 'action': action, 'messages': '发送广播'},
    //     {'methodName': 'sendOrderedBroadcast', 'action': action, 'messages': '发送有序广播'},
    //     {'methodName': 'startService', 'action': action, 'messages': '启动服务'},
    // ]);
    // hook('com.amap.bundle.utils.encrypt.MD5Util', [
    //     // {'methodName': 'getStringMD5', 'action': action, 'messages': '出现hash算法，可能用于加密'},
    // ]);
    // hook('com.amap.bundle.searchservice.history.SearchHistoryHelper',[
    //     {'methodName': '$init', 'action': action, 'messages': 'setSyncSearchHistoryDataTemp'}
    // ]);
    //自定义hook函数，可自行添加。格式如下：
    // hook('com.zhengjim.myapplication.HookTest', [
    //     {'methodName': 'getPassword', 'action': action, 'messages': '获取zhengjim密码'},
    //     {'methodName': 'getUser', 'action': action, 'messages': '获取zhengjim用户名'},
    // ]);
}

function useModule(moduleList) {
    var _module = {
        // 'permission': [checkRequestPermission],
        // 'phone': [getPhoneState],
        // 'system': [getSystemData],
        // 'app': [getPackageManager],
        // 'location': [getGSP],
        // 'network': [getNetwork],
        // 'camera': [getCamera],
        // 'bluetooth': [getBluetooth],
        // 'file': [getFileMessage],
        // 'media': [getMedia],
        // 'sensor': [getSensor],
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
