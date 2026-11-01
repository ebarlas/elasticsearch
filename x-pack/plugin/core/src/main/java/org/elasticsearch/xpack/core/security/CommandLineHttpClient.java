/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security;

import org.elasticsearch.common.CheckedSupplier;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.common.network.InetAddresses;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.ssl.KeyStoreUtil;
import org.elasticsearch.common.ssl.SslConfiguration;
import org.elasticsearch.core.CharArrays;
import org.elasticsearch.core.CheckedFunction;
import org.elasticsearch.env.Environment;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.XPackSettings;
import org.elasticsearch.xpack.core.security.HttpResponse.HttpResponseBuilder;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.core.ssl.SSLService;
import org.elasticsearch.xpack.core.ssl.SslProfile;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import static org.elasticsearch.http.HttpTransportSettings.SETTING_HTTP_PORT;
import static org.elasticsearch.http.HttpTransportSettings.SETTING_HTTP_PUBLISH_HOST;
import static org.elasticsearch.http.HttpTransportSettings.SETTING_HTTP_PUBLISH_PORT;

/**
 * A simple http client for usage in command line tools. This client only uses internal jdk classes and does
 * not rely on an external http libraries.
 */
public class CommandLineHttpClient {

    /**
     * Timeout HTTP(s) requests after 35 seconds.
     * The default timeout for discovering a master is 30s, and we want to be longer than this, otherwise a querying a disconnected node
     * will trigger as client side timeout rather than giving clear error details.
     */
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(35);

    private final Environment env;
    private final String pinnedCaCertFingerprint;

    public CommandLineHttpClient(Environment env) {
        this.env = env;
        this.pinnedCaCertFingerprint = null;
    }

    public CommandLineHttpClient(Environment env, String pinnedCaCertFingerprint) {
        this.env = env;
        this.pinnedCaCertFingerprint = pinnedCaCertFingerprint;
    }

    /**
     * General purpose HTTP(S) call with JSON Content-Type and Authorization Header.
     * SSL settings are read from the settings file, if any.
     *
     * @param user
     *            user in the authorization header.
     * @param password
     *            password in the authorization header.
     * @param requestBodySupplier
     *            supplier for the JSON string body of the request.
     * @param responseHandler
     *            handler of the response Input Stream.
     * @return HTTP protocol response code.
     */
    public HttpResponse execute(
        String method,
        URL url,
        String user,
        SecureString password,
        CheckedSupplier<String, Exception> requestBodySupplier,
        CheckedFunction<InputStream, HttpResponseBuilder, Exception> responseHandler
    ) throws Exception {

        final String authorizationHeader = UsernamePasswordToken.basicAuthHeaderValue(user, password);
        return execute(method, url, authorizationHeader, requestBodySupplier, responseHandler);
    }

    /**
     * General purpose HTTP(S) call with JSON Content-Type and Authorization Header.
     * SSL settings are read from the settings file, if any.
     *
     * @param apiKey
     *            API key value to be used in the Authorization header
     * @param requestBodySupplier
     *            supplier for the JSON string body of the request.
     * @param responseHandler
     *            handler of the response Input Stream.
     * @return HTTP protocol response code.
     */
    public HttpResponse execute(
        String method,
        URL url,
        SecureString apiKey,
        CheckedSupplier<String, Exception> requestBodySupplier,
        CheckedFunction<InputStream, HttpResponseBuilder, Exception> responseHandler
    ) throws Exception {
        final String authorizationHeaderValue = apiKeyHeaderValue(apiKey);
        return execute(method, url, authorizationHeaderValue, requestBodySupplier, responseHandler);
    }

    private HttpResponse execute(
        String method,
        URL url,
        String authorizationHeader,
        CheckedSupplier<String, Exception> requestBodySupplier,
        CheckedFunction<InputStream, HttpResponseBuilder, Exception> responseHandler
    ) throws Exception {
        final HttpClient.Builder clientBuilder = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1);
        // If using SSL, need a custom service because it's likely a self-signed certificate
        if ("https".equalsIgnoreCase(url.getProtocol())) {
            final SSLService sslService = new SSLService(env);
            if (pinnedCaCertFingerprint != null) {
                final SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[] { fingerprintTrustingTrustManager(pinnedCaCertFingerprint) }, null);
                clientBuilder.sslContext(sslContext);
            } else {
                final SslProfile sslProfile = sslService.profile(XPackSettings.HTTP_SSL_PREFIX);
                final SslConfiguration sslConfiguration = sslProfile.configuration();
                final boolean isHostnameVerificationEnabled = sslConfiguration.verificationMode().isHostnameVerificationEnabled();
                final SSLContext sslContext;
                if (isHostnameVerificationEnabled) {
                    sslContext = sslProfile.sslContext();
                } else {
                    sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(
                        new KeyManager[] { sslConfiguration.keyConfig().createKeyManager() },
                        new TrustManager[] { hostnameIgnoringTrustManager(sslConfiguration.trustConfig().createTrustManager()) },
                        null
                    );
                }
                final SSLParameters sslParameters = new SSLParameters(
                    SSLService.supportedCiphers(
                        sslContext.getSupportedSSLParameters().getCipherSuites(),
                        sslConfiguration.getCipherSuites(),
                        false
                    ),
                    sslConfiguration.supportedProtocols().toArray(Strings.EMPTY_ARRAY)
                );
                // we use the cipher suite order so that we can prefer the ciphers we set first in the list
                sslParameters.setUseCipherSuitesOrder(true);
                clientBuilder.sslContext(sslContext).sslParameters(sslParameters);
            }
        }
        final String bodyString = requestBodySupplier.get();
        final HttpRequest request = HttpRequest.newBuilder(url.toURI())
            .method(
                method,
                bodyString == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(bodyString, StandardCharsets.UTF_8)
            )
            .timeout(REQUEST_TIMEOUT)
            // Add basic-auth header
            .header("Authorization", authorizationHeader)
            .header("Content-Type", XContentType.JSON.mediaType())
            .build();
        try (HttpClient client = clientBuilder.build()) {
            // this throws IOException if there is a network problem
            final java.net.http.HttpResponse<InputStream> response = client.send(
                request,
                java.net.http.HttpResponse.BodyHandlers.ofInputStream()
            );
            final HttpResponseBuilder responseBuilder;
            try (InputStream inputStream = response.body()) {
                responseBuilder = responseHandler.apply(inputStream);
            }
            responseBuilder.withHttpStatus(response.statusCode());
            return responseBuilder.build();
        }
    }

    public String getDefaultURL() {
        final Settings settings = env.settings();
        final String scheme = XPackSettings.HTTP_SSL_ENABLED.get(settings) ? "https" : "http";
        List<String> httpPublishHost = SETTING_HTTP_PUBLISH_HOST.get(settings);
        if (httpPublishHost.isEmpty()) {
            httpPublishHost = NetworkService.GLOBAL_NETWORK_PUBLISH_HOST_SETTING.get(settings);
        }

        // we cannot do custom name resolution here...
        NetworkService networkService = new NetworkService(Collections.emptyList());
        try {
            InetAddress publishAddress = networkService.resolvePublishHostAddresses(httpPublishHost.toArray(Strings.EMPTY_ARRAY));
            int port = SETTING_HTTP_PUBLISH_PORT.get(settings);
            if (port <= 0) {
                int[] ports = SETTING_HTTP_PORT.get(settings).ports();
                if (ports.length > 0) {
                    port = ports[0];
                }

                // this sucks but a port can be specified with a value of 0, we'll never be able to connect to it so just default to
                // what we know
                if (port <= 0) {
                    throw new IllegalStateException("unable to determine http port from settings");
                }
            }
            return scheme + "://" + InetAddresses.toUriString(publishAddress) + ":" + port;
        } catch (Exception e) {
            throw new IllegalStateException(
                "unable to determine default URL from settings, please use the -u option to explicitly " + "provide the url",
                e
            );
        }
    }

    public static String getErrorCause(HttpResponse httpResponse) {
        final Object error = httpResponse.getResponseBody().get("error");
        if (error == null) {
            return null;
        }
        if (error instanceof Map) {
            Object reason = ((Map) error).get("reason");
            if (reason != null) {
                return reason.toString();
            }
            final Object root = ((Map) error).get("root_cause");
            if (root != null && root instanceof Map) {
                reason = ((Map) root).get("reason");
                if (reason != null) {
                    return reason.toString();
                }
                final Object type = ((Map) root).get("type");
                if (type != null) {
                    return (String) type;
                }
            }
            return String.valueOf(((Map) error).get("type"));
        }
        return error.toString();
    }

    /**
     * If cluster is not up yet (connection refused or master is unavailable), we will retry @retries number of times
     * If status is 'Red', we will wait for 'Yellow' for 30s (default timeout)
     */
    public void checkClusterHealthWithRetriesWaitingForCluster(String username, SecureString password, int retries) throws Exception {
        final URL clusterHealthUrl = createURL(new URL(getDefaultURL()), "_cluster/health", "?wait_for_status=yellow&pretty");
        HttpResponse response;
        try {
            response = execute("GET", clusterHealthUrl, username, password, () -> null, CommandLineHttpClient::responseBuilder);
        } catch (Exception e) {
            if (retries > 0) {
                Thread.sleep(1000);
                retries -= 1;
                checkClusterHealthWithRetriesWaitingForCluster(username, password, retries);
                return;
            } else {
                throw new IllegalStateException("Failed to determine the health of the cluster.", e);
            }
        }
        final int responseStatus = response.getHttpStatus();
        if (responseStatus != HttpURLConnection.HTTP_OK) {
            if (responseStatus != HttpURLConnection.HTTP_UNAVAILABLE) {
                if (retries > 0) {
                    Thread.sleep(1000);
                    retries -= 1;
                    checkClusterHealthWithRetriesWaitingForCluster(username, password, retries);
                    return;
                } else {
                    throw new IllegalStateException(
                        "Failed to determine the health of the cluster. Unexpected http status [" + responseStatus + "]"
                    );
                }
            }
            throw new IllegalStateException(
                "Failed to determine the health of the cluster. Unexpected http status [" + responseStatus + "]"
            );
        } else {
            final String clusterStatus = Objects.toString(response.getResponseBody().get("status"), "");
            if (clusterStatus.isEmpty()) {
                throw new IllegalStateException(
                    "Failed to determine the health of the cluster. Cluster health API did not return a status value."
                );
            } else if ("red".equalsIgnoreCase(clusterStatus)) {
                throw new IllegalStateException("Failed to determine the health of the cluster. Cluster health is currently RED.");
            }
            // else it is yellow or green so we can continue
        }
    }

    public static HttpResponse.HttpResponseBuilder responseBuilder(InputStream is) throws IOException {
        final HttpResponse.HttpResponseBuilder httpResponseBuilder = new HttpResponse.HttpResponseBuilder();
        final String responseBody = Streams.readFully(is).utf8ToString();
        httpResponseBuilder.withResponseBody(responseBody);
        return httpResponseBuilder;
    }

    public static URL createURL(URL url, String path, String query) throws MalformedURLException, URISyntaxException {
        return new URL(url, (url.toURI().getPath() + path).replaceAll("//+", "/") + query);
    }

    public static String apiKeyHeaderValue(SecureString apiKey) {
        CharBuffer chars = CharBuffer.allocate(apiKey.length());
        byte[] charBytes = null;
        try {
            chars.put(apiKey.getChars());
            charBytes = CharArrays.toUtf8Bytes(chars.array());

            // TODO we still have passwords in Strings in headers. Maybe we can look into using a CharSequence?
            String apiKeyToken = Base64.getEncoder().encodeToString(charBytes);
            return "ApiKey " + apiKeyToken;
        } finally {
            Arrays.fill(chars.array(), (char) 0);
            if (charBytes != null) {
                Arrays.fill(charBytes, (byte) 0);
            }
        }
    }

    /**
     * Returns a TrustManager for a client SSLContext that validates the server certificate chain using the CA identified
     * by the SHA-256 fingerprint {@code caCertFingerprint} as its trust anchor.
     */
    private static TrustManager fingerprintTrustingTrustManager(String caCertFingerprint) {
        final TrustManager trustManager = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (chain.length < 2) {
                    throw new CertificateException("CA certificate not in chain, or self-signed certificate");
                }
                final Certificate caCertFromChain = chain[1];
                MessageDigest sha256 = MessageDigests.sha256();
                sha256.update(caCertFromChain.getEncoded());
                if (MessageDigests.toHexString(sha256.digest()).equals(caCertFingerprint) == false) {
                    throw new CertificateException();
                }
                // Use the fingerprint-matched CA as the trust anchor for certificate-chain validation.
                final X509ExtendedTrustManager pkixTrustManager;
                try {
                    pkixTrustManager = KeyStoreUtil.createTrustManager(List.of(caCertFromChain));
                } catch (GeneralSecurityException e) {
                    throw new CertificateException("Failed to build trust manager for the pinned CA certificate", e);
                }
                pkixTrustManager.checkServerTrusted(chain, authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        return trustManager;
    }

    /**
     * Returns a TrustManager that validates the server certificate chain with {@code delegate}, but not that the certificate names the
     * server. {@link HttpClient} always has the TLS layer verify the server's host name and offers no per-client way to turn that off,
     * so this is how a verification mode without hostname verification is honoured. The two-argument checks of a JSSE trust manager do
     * not perform endpoint identification.
     */
    private static X509ExtendedTrustManager hostnameIgnoringTrustManager(X509ExtendedTrustManager delegate) {
        return new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                delegate.checkClientTrusted(chain, authType, socket);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                delegate.checkServerTrusted(chain, authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                delegate.checkClientTrusted(chain, authType, engine);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                delegate.checkServerTrusted(chain, authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                delegate.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                delegate.checkServerTrusted(chain, authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return delegate.getAcceptedIssuers();
            }
        };
    }
}
