package net.lightbody.bmp.proxy.http;

import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.protocol.HttpContext;
import org.java_bandwidthlimiter.StreamManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustingSSLSocketFactory extends SSLConnectionSocketFactory {

    public enum SSLAlgorithm {
        SSLv3,
        TLSv1
    }

    private static SSLContext sslContext;
    private StreamManager streamManager;

    static {
        try {
            sslContext = SSLContext.getInstance( SSLAlgorithm.SSLv3.name() );
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("TLS algorithm not found! Critical SSL error!", e);
        }
        TrustManager easyTrustManager = new X509TrustManager() {
            @Override
            public void checkClientTrusted(
                    X509Certificate[] chain,
                    String authType) throws CertificateException {
                // Oh, I am easy!
            }

            @Override
            public void checkServerTrusted(
                    X509Certificate[] chain,
                    String authType) throws CertificateException {
                // Oh, I am easy!
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

        };
        try {
            sslContext.init(null, new TrustManager[]{easyTrustManager}, null);
        } catch (KeyManagementException e) {
            throw new RuntimeException("Unexpected key management error", e);
        }
    }

    public TrustingSSLSocketFactory(StreamManager streamManager) {
        super(sslContext, new AllowAllHostnameVerifier());
        assert streamManager != null;
        this.streamManager = streamManager;
    }

    //just an helper function to wrap a normal sslSocket into a simulated one so we can do throttling
    private Socket createSimulatedSocket(SSLSocket socket) {
        SimulatedSocketFactory.configure(socket);
        socket.setEnabledProtocols(new String[] { SSLAlgorithm.SSLv3.name(), SSLAlgorithm.TLSv1.name() } );
        //socket.setEnabledCipherSuites(new String[] { "SSL_RSA_WITH_RC4_128_MD5" });
        return new SimulatedSSLSocket(socket, streamManager);
    }


    @Override
    public Socket connectSocket(int connectTimeout, Socket socket, HttpHost host, InetSocketAddress remoteAddress,
                                InetSocketAddress localAddress, HttpContext context)
            throws java.io.IOException {
        SSLSocket sslSocket = (SSLSocket) super.connectSocket( connectTimeout, socket, host, remoteAddress, localAddress, context);
        if( sslSocket instanceof SimulatedSSLSocket ) {
            return sslSocket;
        } else {
            return createSimulatedSocket(sslSocket);
        }
    }

    @Override
    public Socket createSocket(HttpContext context) throws IOException {
        Socket socket = super.createSocket(context);
        if (socket instanceof SSLSocket) {
            return createSimulatedSocket((SSLSocket) socket);
        }
        return socket;

    }

}
