package mx.gob.banobras.securityauth.application.service;

/**
 * TokenizerUseCaseService.java:
 * 
 * Clase de tipo @Service que contiene las funciones del caso de uso del Api TOkenizer
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.util.Date;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import mx.gob.banobras.securityauth.application.port.in.ISecurityAuthCasoUsoService;
import mx.gob.banobras.securityauth.application.port.out.ILdapClient;
import mx.gob.banobras.securityauth.application.port.out.ITokenClient;
import mx.gob.banobras.securityauth.common.util.CipherAESCommon;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;
import mx.gob.banobras.securityauth.common.util.ErrorDetail;
import mx.gob.banobras.securityauth.infraestructure.adapter.out.client.LdapVO;
import mx.gob.banobras.securityauth.infraestructure.adapter.out.client.LdapVOMapperDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.CipherResponseDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.DataDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.ErrorMessageDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapResponseDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.TokenizerResponseDTO;

@Service
public class SecurityAuthCasoUsoServiceImpl implements ISecurityAuthCasoUsoService {

	/** Trazas de la aplicación */
	Logger log = LogManager.getLogger(SecurityAuthCasoUsoServiceImpl.class);

	/** Variable para inejctar la clase Tokenizer */
	private final ITokenClient iTokenClient;
	/** Variable para inejctar la clase ILdapOutPort, para conexión a LDAP */
	private final ILdapClient iLdapClient;
	/** Injection variable para la clase CipherAESCommon */
	private final CipherAESCommon cipherAESCommon;

	/** Variable que contiene la url del ldap */
	@Value("${app.ldap.server}")
	String ldapServer;

	/**
	 * Constructor para inyectar los objetos Tokenizer, ILdapOutPort y
	 * CipherAESCommon
	 * 
	 * @param tokenizer       Objeto de dominio el Api Tokenizer.
	 * @param iLdapOutPort    Interface de puerto de salida para conectarse al LDAP.
	 * @param CipherAESCommon componente para desencriptar datos.
	 * 
	 */
	public SecurityAuthCasoUsoServiceImpl(ILdapClient iLdapClient, ITokenClient iTokenClient,
			CipherAESCommon cipherAESCommon) {
		this.iLdapClient = iLdapClient;
		this.iTokenClient = iTokenClient;
		this.cipherAESCommon = cipherAESCommon;
	}

	/**
	 * Metodo para validar el Token y autenticar el usuario.
	 * 
	 * @param securityAuthDTO Objeto que contien los datos para la validación y
	 *                        autenticacion.
	 * @return LdapResponseDTO objeto que contiene los datos del usuario en LDAP.
	 * 
	 */
	@Override
	public LdapResponseDTO authenticationTokenLdap(SecurityAuthDTO securityAuthDTO) {
		/** Variable que contiene el objeto de respuesta */
		LdapResponseDTO ldapResponseDTO = null;
		TokenizerResponseDTO tokenizerResponseDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		try {
			/** Descripta las credenciales */
			securityAuthDTO = cipherAESCommon.getDataCredentials(securityAuthDTO);
			log.info("Valida el token");
			tokenizerResponseDTO = iTokenClient.validToken(securityAuthDTO);
			if (tokenizerResponseDTO.getStatusCode() == 200) {
				log.info("Token valido");
				log.info(new StringBuilder().append("Valida si existe el usuario en LDAP: ")
						.append(securityAuthDTO.getUserName()));
				ldapResponseDTO = iLdapClient.autentication(securityAuthDTO);

			} else {
					log.info("Error al validar el token");
					errorMessageDTO = new ErrorMessageDTO();
					errorMessageDTO.setStatusCode(tokenizerResponseDTO.getErrorMessageDTO().getStatusCode());
					errorMessageDTO.setTimestamp(tokenizerResponseDTO.getErrorMessageDTO().getTimestamp());
					errorMessageDTO.setMessage(tokenizerResponseDTO.getErrorMessageDTO().getMessage());
					errorMessageDTO.setDetail(tokenizerResponseDTO.getErrorMessageDTO().getDetail());
					/** Respuesta del Servicio */
					ldapResponseDTO = new LdapResponseDTO();
					ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
					ldapResponseDTO.setStatusCode(tokenizerResponseDTO.getStatusCode());
			}

		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ex1.getMessage());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(ex1));
			/** Respuiesta del servicio **/
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}
		return ldapResponseDTO;
	}

	/**
	 * Metodo para autentifica el usuario en LDAP
	 * 
	 * @param tokenizerDTO Objeto que contien los datos para generar el toekn.
	 * @return TokenizerResponseDTO regresa el objeto TokenizerResponseDTO que
	 *         contiene los datos del toekn.
	 * 
	 */
	@Override
	public LdapResponseDTO authenticationLdap(SecurityAuthDTO securityAuthDTO) {

		/** Variable que contiene el objeto de respuesta de LDAP */
		LdapResponseDTO ldapResponseDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		try {
			/** Descripta las credenciales */
			securityAuthDTO = cipherAESCommon.getDataCredentials(securityAuthDTO);

			log.info(new StringBuilder().append("Valida si existe el usuario en LDAP: ")
					.append(securityAuthDTO.getUserName()));
			ldapResponseDTO = iLdapClient.autentication(securityAuthDTO);
		
		} catch (Exception ex1) {
			ex1.printStackTrace();
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ex1.getMessage());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(ex1));
			/** Respuesta del servicio **/
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}
		return ldapResponseDTO;
	}

	/**
	 * Metodo para obtener encirptar una cedena.
	 * 
	 * @param securityAuthDTO - DTO que contien los datos para encirptar.
	 * @return regresa el objeto encirptado.
	 * @throws Exception Excepción durante el proceso.
	 */
	@Override
	public CipherResponseDTO encode(SecurityAuthDTO securityAuthDTO) {

		/** Variable que contiene el objeto de respuesta del token */
		CipherResponseDTO cipherResponseDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		String data = null;
		log.info("Inicia encode service");
		try {
			data = cipherAESCommon.encryptStringToAesHex(securityAuthDTO.getCredentials());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setDataDTO(new DataDTO(data.toUpperCase()));
			cipherResponseDTO.setStatusCode(HttpStatus.OK.value());

		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_ERROR_500.getName());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(ex1));
			/** Respuesta del Servicio */
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}
		log.info("Termina encode service");
		return cipherResponseDTO;
	}

	/**
	 * Metodo para desencirptar una cedena en formato Hexadecimal.
	 * 
	 * @param securityAuthDTO - DTO que contien los datos para desencirptar.
	 * @return CipherResponseDTO regresa el objeto desencirptado.
	 */
	@Override
	public CipherResponseDTO decode(SecurityAuthDTO securityAuthDTO) {
		/** Variable que contiene el objeto de respuesta */
		CipherResponseDTO cipherResponseDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		String data = null;
		log.info("Inicia decode service");
		try {
			data = cipherAESCommon.decryptAesHexToString(securityAuthDTO.getCredentials());
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setDataDTO(new DataDTO(data));
			cipherResponseDTO.setStatusCode(HttpStatus.OK.value());
		} catch (Exception ex1) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_NO_FORMAT_DATA_CORRECT.getName());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(ex1));
			/** Respuesta del Servicio */
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}
		log.info("Termina decode service");
		return cipherResponseDTO;
	}
	
	
	

	@Override
	public LdapResponseDTO allDataUserLdap(SecurityAuthDTO securityAuthDTO) {
		/** Variable que contiene el objeto de respuesta de LDAP */
		LdapResponseDTO ldapResponseDTO = null;
		LdapVO ldapVO = null;
		TokenizerResponseDTO tokenizerResponseDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		try {
			log.info("Busca los datos del usuario en LDAP");

			/** Descripta las credenciales */
			securityAuthDTO = cipherAESCommon.getDataCredentials(securityAuthDTO);

			log.info("Valida el token");
			tokenizerResponseDTO = iTokenClient.validToken(securityAuthDTO);

			if (tokenizerResponseDTO.getStatusCode() == 200) {
				log.info(new StringBuilder().append("Obtiene los datos en LDAP: ")
						.append(securityAuthDTO.getUserName()));
				ldapVO = iLdapClient.allDataUserLdap(securityAuthDTO);

				if (ldapVO != null) {
					LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
					LdapDTO ldapDTO = mapperLdapDTO.mapperVOtoDTO(ldapVO);
					ldapResponseDTO = new LdapResponseDTO();
					ldapResponseDTO.setStatusCode(HttpStatus.OK.value());
					ldapResponseDTO.setLdapDTO(ldapDTO);
				}
			} else {
				log.info("Error al validar el Token");
				errorMessageDTO = new ErrorMessageDTO();
				errorMessageDTO.setStatusCode(tokenizerResponseDTO.getErrorMessageDTO().getStatusCode());
				errorMessageDTO.setTimestamp(tokenizerResponseDTO.getErrorMessageDTO().getTimestamp());
				errorMessageDTO.setMessage(tokenizerResponseDTO.getErrorMessageDTO().getMessage());
				errorMessageDTO.setDetail(tokenizerResponseDTO.getErrorMessageDTO().getDetail());
				/** Respuesta del Servicio */
				ldapResponseDTO = new LdapResponseDTO();
				ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
				ldapResponseDTO.setStatusCode(tokenizerResponseDTO.getStatusCode());
			}
		} 
		catch (Exception ex1) {
			ex1.printStackTrace();
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), ex1);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ex1.getMessage());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(ex1));
			/** Respuesta del servicio **/
			ldapResponseDTO = new LdapResponseDTO();
			ldapResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}
		return ldapResponseDTO;

	}

}
