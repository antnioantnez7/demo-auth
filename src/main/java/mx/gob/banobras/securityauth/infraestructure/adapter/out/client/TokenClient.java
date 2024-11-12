package mx.gob.banobras.securityauth.infraestructure.adapter.out.client;

import java.io.IOException;

/**
 * TokenClient.java:
 * 
 * Clase para conectarse al tokenizer y validar el token. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */


import java.util.Date;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import com.google.gson.Gson;


import mx.gob.banobras.securityauth.application.port.out.ITokenClient;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;
import mx.gob.banobras.securityauth.common.util.ErrorDetail;
import mx.gob.banobras.securityauth.infraestructure.config.dto.ErrorMessageDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.HttpErrorExceptionDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.TokenizerResponseDTO;

@Component
public class TokenClient implements ITokenClient {

	/** Trazas de la aplicación */
	Logger log = LogManager.getLogger(TokenClient.class);

	/** Variable que contiene el nombre de usuario de conexion en ldap */
	@Value("${app.url.token.valid}")
	String urlTokenValid;

	private final HttpClientFactory httpClientFactory;

	public TokenClient(HttpClientFactory httpClientFactory) {
		this.httpClientFactory = httpClientFactory;
	}

	/**
	 * Metodo para validar el token.
	 * 
	 * @param securityAuthInDTO componente que contiene los datos del token.
	 * 
	 * @return HttpResponse<String> regresa un objeto con los datos del token
	 *         validado
	 * @throws Exception
	 * 
	 */
	@Override
	public TokenizerResponseDTO validToken(SecurityAuthDTO securityAuthInDTO)  {
		Gson gson = new Gson();
		String respondeBody = null;
		CloseableHttpClient client = null;
		CloseableHttpResponse response = null;
		TokenizerResponseDTO tokenizerResponseDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		log.info("Inicia restCient Valida Token");
		try {
			if(System.getenv("app.url.token.valid") != null) {
				urlTokenValid = System.getenv("app.url.token.valid");
			}
			client = httpClientFactory.getHttpClient(urlTokenValid);
			
			HttpPost httpPost = new HttpPost(urlTokenValid);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("credentials", securityAuthInDTO.getCredentials());
			httpPost.setHeader("token-auth", securityAuthInDTO.getTokenAuth());
			httpPost.setHeader("app-name", securityAuthInDTO.getAppName());
			httpPost.setHeader("consumer-id", securityAuthInDTO.getConsumerId());
			httpPost.setHeader("functional-id", securityAuthInDTO.getFunctionalId());
			httpPost.setHeader("transaction-id", securityAuthInDTO.getTransactionId());
			response = client.execute(httpPost);
			try {
				HttpEntity entity = response.getEntity();
				if (entity != null) {
					log.info("Valida OK");
					respondeBody = EntityUtils.toString(entity);
					tokenizerResponseDTO = gson.fromJson(respondeBody, TokenizerResponseDTO.class);
					/** Si la respuesta no tiene datos **/
					if(tokenizerResponseDTO.getStatusCode() == null) {
						HttpErrorExceptionDTO httpErrorExceptionDTO = gson.fromJson(respondeBody,
								HttpErrorExceptionDTO.class);
						log.info(httpErrorExceptionDTO.getStatus());
						errorMessageDTO = new ErrorMessageDTO();
						errorMessageDTO.setStatusCode(Integer.parseInt(httpErrorExceptionDTO.getStatus()));
						errorMessageDTO.setTimestamp(new Date());
						errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_NO_SERVICE_TOKENIZER.getName());
						errorMessageDTO.setDetail(httpErrorExceptionDTO.getPath() + 
								" - " + httpErrorExceptionDTO.getError());
						/** Respuesta del servicio */
						tokenizerResponseDTO = new TokenizerResponseDTO();
						tokenizerResponseDTO.setStatusCode(Integer.parseInt(httpErrorExceptionDTO.getStatus()));
						tokenizerResponseDTO.setErrorMessageDTO(errorMessageDTO);
					}
				} else {
					/***** CAMBIAR POR UNA EXCEPCION **/
					log.info("Valida NOK");
					errorMessageDTO = new ErrorMessageDTO();
					errorMessageDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
					errorMessageDTO.setTimestamp(new Date());
					errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_NO_SERVICE_TOKENIZER.getName());
					/** Respuesta del servicio */
					tokenizerResponseDTO = new TokenizerResponseDTO();
					tokenizerResponseDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
					tokenizerResponseDTO.setErrorMessageDTO(errorMessageDTO);
					
				}
				EntityUtils.consume(entity);
			} finally {
				response.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
			log.info("aqui");
			log.info(e);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_NO_SERVICE_TOKENIZER.getName());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(e));
			/** Respuesta del servicio */
			tokenizerResponseDTO = new TokenizerResponseDTO();
			tokenizerResponseDTO.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
			tokenizerResponseDTO.setErrorMessageDTO(errorMessageDTO);
		} finally {
			try {
				client.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		log.info("Finaliza restCient Valida Token");
		return tokenizerResponseDTO;
	}
}
