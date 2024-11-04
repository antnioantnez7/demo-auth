package mx.gob.banobras.securityauth.infraestructure.adapter.in.controller;
/**
 * SecurityAuthController.java:
 * 
 * Interfaz controller que expone los servicios de autenticacion de usuario.
 * 
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapResponseDTO;

@Tag(name = "Autenticación de usuarios en Directorio Activo.", description = "Servicio para autenticar a los usuario en el Directorio Activo.")
@RequestMapping("/security-auth/v1")
public interface ISecurityAuthController {

	/**
	 * Method to authenticated the user through LDAP
	 * 
	 * @param credentials    - Encrypted user credentials.
	 * @param app-name       - Name of the system that consume of service.
	 * @param consumer-id    - System layer that consumes the service.
	 * @param functional-id  - Functionality that consumes the service.
	 * @param transaction-id - Transaction identifier, generated by UUID.
	 * 
	 * @return back the object TokenizerResponseDTO with the token data
	 * @throws Exception send during process of authentication.
	 * 
	 */
	@Operation(summary = "Servicio para autenticar solamente el usuario en el Directorio Activo.", description = "Servicio para autenticar solamente el usuario en el Directorio Activo.")
	@Parameter(name = "credentials", required = true, description = "Credenciales encriptadas, usuario y password.", example = "0FFA7868B0A8CE36ED6C98230E7AC933")
	@Parameter(name = "app-name", required = true, description = "Nombre del sistema que consume el servicio.", example = "SICOVI")
	@Parameter(name = "consumer-id", required = true, description = "Capa del sistema que consuem el servicio.", example = "UI SICOVI")
	@Parameter(name = "functional-id", required = true, description = "Funcionalidad que consume el servicio.", example = "Login user")
	@Parameter(name = "transaction-id", required = true, description = "Identificador &uacute;nico para identificar la operación, funcionalidad o transacci&oacute;n, generado por c&oacute;digo UUID", example = "9680e51f-4766-4124-a3ff-02e9c3a5f9d6")

	@ApiResponse(responseCode = "200", description = "El usuario existe en LDAP.")
	@ApiResponse(responseCode = "400", description = "Solicitud err&oacute;nea.")
	@ApiResponse(responseCode = "404", description = "Recurso no encontrado.")
	@ApiResponse(responseCode = "500", description = "Error Interno.")
	@ApiResponse(responseCode = "503", description = "Servicio no disponible.")

	@PostMapping("/ldap-user")
	public ResponseEntity<LdapResponseDTO> ldapAuth(
			@RequestHeader(value = "credentials") String credentials,
			@RequestHeader(value = "app-name") String appName, 
			@RequestHeader(value = "consumer-id") String consumerId,
			@RequestHeader(value = "functional-id") String functionalId,
			@RequestHeader(value = "transaction-id") String transactionId);

	/**
	 * Method to authenticated the user and passwordthrough LDAP
	 * 
	 * @param credentials    - Encrypted user credentials.
	 * @param app-name       - Name of the system that consume of service.
	 * @param consumer-id    - System layer that consumes the service.
	 * @param functional-id  - Functionality that consumes the service.
	 * @param transaction-id - Transaction identifier, generated by UUID.
	 * 
	 * @return back the object TokenizerResponseDTO with the token data
	 * @throws Exception send during process of authentication.
	 * 
	 */
	@Operation(summary = "Servicio para autenticar el usuario y el password, en el Directorio Activo.", description = "Servicio para autenticar el usuario y el password, en el Directorio Activo.")
	@Parameter(name = "credentials", required = true, description = "Credenciales encriptadas, usuario y password.", example = "0FFA7868B0A8CE36ED6C98230E7AC933")
	@Parameter(name = "app-name", required = true, description = "Nombre del sistema que consume el servicio.", example = "SICOVI")
	@Parameter(name = "consumer-id", required = true, description = "Capa del sistema que consuem el servicio.", example = "UI SICOVI")
	@Parameter(name = "functional-id", required = true, description = "Funcionalidad que consume el servicio.", example = "Login user")
	@Parameter(name = "transaction-id", required = true, description = "Identificador &uacute;nico para identificar la operación, funcionalidad o transacci&oacute;n, generado por c&oacute;digo UUID", example = "9680e51f-4766-4124-a3ff-02e9c3a5f9d6")

	@ApiResponse(responseCode = "200", description = "El usuario y password existen en LDAP.")
	@ApiResponse(responseCode = "400", description = "Solicitud err&oacute;nea.")
	@ApiResponse(responseCode = "404", description = "Recurso no encontrado.")
	@ApiResponse(responseCode = "500", description = "Error Interno.")
	@ApiResponse(responseCode = "503", description = "Servicio no disponible.")

	@PostMapping("/ldap-user-pwd")
	public ResponseEntity<LdapResponseDTO> ldapUserPwd(@RequestHeader(value = "credentials") String credentials,
			@RequestHeader(value = "app-name") String appName, @RequestHeader(value = "consumer-id") String consumerId,
			@RequestHeader(value = "functional-id") String functionalId,
			@RequestHeader(value = "transaction-id") String transactionId);

	/**
	 * Method to authenticated the user through of Token and LDAP
	 * 
	 * @param credentials    - Encrypted user credentials.
	 * @param token-auth     - Authentication Token.
	 * @param app-name       - Name of the system that consume of service.
	 * @param consumer-id    - System layer that consumes the service.
	 * @param functional-id  - Functionality that consumes the service.
	 * @param transaction-id - Transaction identifier, generated by UUID.
	 * 
	 * @return back the object TokenizerResponseDTO with the token data
	 * @throws Exception send during process of authentication.
	 * 
	 */
	@Operation(summary = "Servicio para autenticar el usuario y validar el token, por medio de LDAP y Api Tokenizer.", description = "Servicio para autenticar el usuario y validar el token, por medio de LDAP y Api Tokenizer.")
	@Parameter(name = "credentials", required = true, description = "Credenciales encriptadas, usuario y password.", example = "0FFA7868B0A8CE36ED6C98230E7AC933")
	@Parameter(name = "token-auth", required = true, description = "Token de autenticaci&oacute;n", example = "Bearer eyJ0eXAiOiJKV1Qi...")
	@Parameter(name = "app-name", required = true, description = "Nombre del sistema que consume el servicio.", example = "SICOVI")
	@Parameter(name = "consumer-id", required = true, description = "Capa del sistema que consuem el servicio.", example = "UI SICOVI")
	@Parameter(name = "functional-id", required = true, description = "Funcionalidad que consume el servicio.", example = "Login user")
	@Parameter(name = "transaction-id", required = true, description = "Identificador &uacute;nico para identificar la operación, funcionalidad o transacci&oacute;n, generado por c&oacute;digo UUID", example = "9680e51f-4766-4124-a3ff-02e9c3a5f9d6")

	@ApiResponse(responseCode = "200", description = "El usuario existe en LDAP y token v&aacute;lido.")
	@ApiResponse(responseCode = "400", description = "Solicitud err&oacute;nea.")
	@ApiResponse(responseCode = "404", description = "Recurso no encontrado.")
	@ApiResponse(responseCode = "500", description = "Error Interno.")
	@ApiResponse(responseCode = "503", description = "Servicio no disponible.")
	@PostMapping("/token-ldap")
	public LdapResponseDTO ldapTokenAuth(@RequestHeader(value = "credentials") String credentials,
			@RequestHeader(value = "token-auth") String tokenAuth, @RequestHeader(value = "app-name") String appName,
			@RequestHeader(value = "consumer-id") String consumerId,
			@RequestHeader(value = "functional-id") String functionalId,
			@RequestHeader(value = "transaction-id") String transactionId);

	
	/*
	 * Metodo para obtener todos los datos de un usuario de LDAP.
	 * 
	 * @param credentials    - Datos encriptados del usuario.
	 * 
	 * @return regresa el objeto con los datos del usuario
	 * @throws Exception
	 * 
	 */
	@Operation(summary = "Servicio para obtener todos los datos de un usuario de LDAP.", description = "Servicio para obtener todos los datos de un usuario de LDAP.")
	@Parameter(name = "credentials", required = true, description = "Credenciales encriptadas, usuario y password.", example = "0FFA7868B0A8CE36ED6C98230E7AC933")
	@Parameter(name = "token-auth", required = true, description = "Token de autenticaci&oacute;n", example = "Bearer eyJ0eXAiOiJKV1Qi...")
	@Parameter(name = "app-name", required = true, description = "Nombre del sistema que consume el servicio.", example = "SICOVI")
	@Parameter(name = "consumer-id", required = true, description = "Capa del sistema que consuem el servicio.", example = "UI SICOVI")
	@Parameter(name = "functional-id", required = true, description = "Funcionalidad que consume el servicio.", example = "Login user")
	@Parameter(name = "transaction-id", required = true, description = "Identificador &uacute;nico para identificar la operación, funcionalidad o transacci&oacute;n, generado por c&oacute;digo UUID", example = "9680e51f-4766-4124-a3ff-02e9c3a5f9d6")

	@ApiResponse(responseCode = "200", description = "El usuario existe en LDAP.")
	@ApiResponse(responseCode = "400", description = "Solicitud err&oacute;nea.")
	@ApiResponse(responseCode = "404", description = "Recurso no encontrado.")
	@ApiResponse(responseCode = "500", description = "Error Interno.")
	@ApiResponse(responseCode = "503", description = "Servicio no disponible.")
	@GetMapping("/all-data-user-ldap")
	public ResponseEntity<LdapResponseDTO> allDataUserLdap(
			@RequestHeader(value = "credentials") String credentials,
			@RequestHeader(value = "token-auth") String tokenAuth,
			@RequestHeader(value = "app-name") String appName, 
			@RequestHeader(value = "consumer-id") String consumerId,
			@RequestHeader(value = "functional-id") String functionalId,
			@RequestHeader(value = "transaction-id") String transactionId);

}