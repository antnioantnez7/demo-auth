package mx.gob.banobras.securityauth.infraestructure.adapter.out.client;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;

import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Component
public class HttpClientFactory {

	/** Trazas de la aplicación */
	Logger log = LogManager.getLogger(HttpClientFactory.class);

	@Value("${app.file.filejks}")
	private String fileKeyStore;

	@Value("${app.cert.jks.password}")
	private String trusStorePassword;

	@Value("${app.bypass.cert}")
	private boolean byPassCert;
	
	CloseableHttpClient httpClient;
	
	public CloseableHttpClient getHttpClient(String URL) throws Exception {
		if (URL.toUpperCase().contains(ConstantsSecurityAuth.HTTPS.getName())) {
				this.httpClient = createHttpsClient();
		} else {
				this.httpClient = HttpClients.createDefault();
		}
		return httpClient;
	}

	/**
	 * Metodo para crear la conexion del cliente por Http o Https
	 * 
	 * @return
	 * @throws IOException
	 */
	public CloseableHttpClient createHttpsClient() throws Exception {
		
		SSLContext sslContext = null;
		SSLConnectionSocketFactory sslConnSocketFactory = null;
		if(!byPassCert) {
			log.info("Validar Certificados");
			sslContext = new SSLContextBuilder()
					.loadTrustMaterial(new URL("file:" + fileKeyStore), trusStorePassword.toCharArray()).build();
			sslConnSocketFactory = new SSLConnectionSocketFactory(sslContext);
			
			
	    	Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
	                .register("https", sslConnSocketFactory)
	                .register("http", new PlainConnectionSocketFactory())
	                .build();
			
	    	BasicHttpClientConnectionManager connectionManager =
	                new BasicHttpClientConnectionManager(socketFactoryRegistry);

	    	httpClient = HttpClients.custom()
	                .setConnectionManager(connectionManager)
	                .build();
			
		} else {
			log.info("SIN Validar Certificados");
			sslContext = SSLContext.getInstance(ConstantsSecurityAuth.SSL.getName());
			sslContext.init(null, new TrustManager[] { MOCK_TRUST_MANAGER }, new SecureRandom());
			sslConnSocketFactory = new SSLConnectionSocketFactory(sslContext);
	    	Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
	                .register("https", sslConnSocketFactory)
	                .register("http", new PlainConnectionSocketFactory())
	                .build();
			
	    	BasicHttpClientConnectionManager connectionManager =
	                new BasicHttpClientConnectionManager(socketFactoryRegistry);

	    	httpClient = HttpClients.custom()
	                .setConnectionManager(connectionManager)
	                .build();
		}

		return httpClient;
	}

	
	
	
	private static final TrustManager MOCK_TRUST_MANAGER = new X509ExtendedTrustManager() {
		@Override
		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
			return new java.security.cert.X509Certificate[0];
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		}

		@Override
		public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
				throws CertificateException {
		}

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {

		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
				throws CertificateException {
		}

	};

}
