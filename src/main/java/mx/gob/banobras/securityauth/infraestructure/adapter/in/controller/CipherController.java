package mx.gob.banobras.securityauth.infraestructure.adapter.in.controller;

/**
 * CipherCotroller.java:
 * 
 * Clase controller que expone los servicios para cifrar datos
 * 
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.util.Date;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import mx.gob.banobras.securityauth.application.port.in.ISecurityAuthCasoUsoService;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;
import mx.gob.banobras.securityauth.common.util.ErrorDetail;
import mx.gob.banobras.securityauth.infraestructure.config.dto.CipherResponseDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.ErrorMessageDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;

@CrossOrigin(originPatterns = { "*" })
@RestController
public class CipherController implements ICipherController {

	/** Trazas de la aplicación */
	Logger log = LogManager.getLogger(CipherController.class);

	/** Injection variable para la interfaz iTokenizerInputPort */
	private final ISecurityAuthCasoUsoService iSecurityAuthInputPort;

	/** Consturctor de las interfaces que usa el controller */
	public CipherController(ISecurityAuthCasoUsoService iSecurityAuthInputPort) {
		this.iSecurityAuthInputPort = iSecurityAuthInputPort;

	}

	/**
	 * Metodo para obtener encriptar una cadena.
	 * 
	 * @param data datos a desecriptar.
	 * 
 	 * @return CipherResponseDTO objeto que contien los dato encriptados.
	 * @throws Exception Excepción durante el proceso.
	 * 
	 */
	public ResponseEntity<CipherResponseDTO> encode(
			@RequestHeader(value = "data") String data) {
		CipherResponseDTO cipherResponseDTO = null;
		SecurityAuthDTO securityAuthDTO = null;
		ErrorMessageDTO errorMessageDTO = null;
		try {
			log.info("Inicia controller encode");
			securityAuthDTO = new SecurityAuthDTO(data, null,null, null, null, null, null,null, false);
			
			/** Verifica que las credenciales no esten vacias **/
			if (!data.isEmpty()) {
				cipherResponseDTO = iSecurityAuthInputPort.encode(securityAuthDTO);
				log.info("No tiene los permisos para generar el token");
			}else {
				errorMessageDTO = new ErrorMessageDTO();
				errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
				errorMessageDTO.setTimestamp(new Date());
				errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_CREDENTIALS_EMPTY.getName());
				/** Respuesta del servicio **/
				cipherResponseDTO = new CipherResponseDTO();
				cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
				cipherResponseDTO.setErrorMessageDTO(errorMessageDTO);
			}
		}  catch (Exception e) {
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), e);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_ERROR_500.getName());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(e));
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(errorMessageDTO);
		} finally {
			log.info("Finaliza controller encode");
		}
		return new ResponseEntity<>(cipherResponseDTO, HttpStatus.valueOf(cipherResponseDTO.getStatusCode()) );
	}
	
	/**
	 * Metodo para obtener desencriptar una cadena.
	 * 
	 * @param ResponseEntity<CipherResponseDTO>.
	 * 
 	 * @return regresa la cadena desencriptada.
	 * @throws Exception Excepción durante el proceso.
	 * 
	 */
	public ResponseEntity<CipherResponseDTO> decode(@RequestHeader(value = "data") String data) {

		CipherResponseDTO cipherResponseDTO = null;
		SecurityAuthDTO securityAuthDTO = null;
		ErrorMessageDTO errorMessageDTO = null;

		try {
			log.info("Inicia controller encode");
			/** Verifica que las credenciales no esten vacias **/
			if (!data.isEmpty()) {
				securityAuthDTO = new SecurityAuthDTO(data, null,null, null, null, null, null,null, false);
				cipherResponseDTO = iSecurityAuthInputPort.decode(securityAuthDTO);
			}else {
				errorMessageDTO = new ErrorMessageDTO();
				errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
				errorMessageDTO.setTimestamp(new Date());
				errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_CREDENTIALS_EMPTY.getName());
				/** Respuesta del servicio **/
				cipherResponseDTO = new CipherResponseDTO();
				cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
				cipherResponseDTO.setErrorMessageDTO(errorMessageDTO);
			}
		} catch (Exception e) {
			e.printStackTrace();
			log.error(ConstantsSecurityAuth.EXCEPTION.getName(), e);
			errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_ERROR_500.getName());
			errorMessageDTO.setDetail(ErrorDetail.getDetail(e));
			cipherResponseDTO = new CipherResponseDTO();
			cipherResponseDTO.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
			cipherResponseDTO.setErrorMessageDTO(errorMessageDTO);
			
		} finally {
			log.info("Finaliza controller encode");
		}
		return new ResponseEntity<>(cipherResponseDTO,  HttpStatus.valueOf(cipherResponseDTO.getStatusCode()));
	}
	

	
	
}
