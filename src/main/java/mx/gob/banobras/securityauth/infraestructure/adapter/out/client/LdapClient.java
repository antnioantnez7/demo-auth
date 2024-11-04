package mx.gob.banobras.securityauth.infraestructure.adapter.out.client;

/**
 * LdapClient.java:
 * 
 * Clase para conectarse en al directorio activo y validar el usuario y password. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import mx.gob.banobras.securityauth.application.port.out.ILdapClient;
import mx.gob.banobras.securityauth.common.util.CipherAESCommon;
import mx.gob.banobras.securityauth.common.util.ConstantsSecurityAuth;
import mx.gob.banobras.securityauth.infraestructure.config.dto.ErrorMessageDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.LdapResponseDTO;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;

@Component
public class LdapClient implements ILdapClient {

	/** Variable para las trazas de la clase */
	Logger log = LogManager.getLogger(LdapClient.class);

	/** Variable que contiene la url del ldap */
	@Value("${app.ldap.server}")
	String ldapServer;

	/** Variable que contiene el filtro para la busqueda en ldap */
	@Value("${app.ldap.search.base}")
	String ldapSearchBase;

	/** Variable que contiene el usuario de servicio de conexion en ldap */
	@Value("${app.ldap.username}")
	String ldapUsername;

	/** Variable que contiene el password de servicio deconexión de ldap */
	@Value("${app.ldap.password}")
	String ldapPassword;

	/** Variable que contiene el dominio de mail */
	@Value("${app.ldap.dominio.mail}")
	String ldapDominioMail;

	/** Variable que contiene el valor para buscar en ldap */
	@Value("${app.ldap.validate}")
	boolean ldapValidate;

	private final CipherAESCommon cipherAESCommon;

	public LdapClient(CipherAESCommon cipherAESCommon) {
		this.cipherAESCommon = cipherAESCommon;
	}

	private InitialDirContext conexionLdap(boolean findUserPwd, SecurityAuthDTO securityAuthDTO)
			throws NamingException {
		InitialDirContext ctx = null;
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapServer);
		
		/** Se realiza la conexion con el usuario y pasword del usuario */
		if (findUserPwd) {
			env.put(Context.SECURITY_PRINCIPAL, securityAuthDTO.getUserName() + ldapDominioMail);
			env.put(Context.SECURITY_CREDENTIALS, securityAuthDTO.getPassword());
			ctx = new InitialDirContext(env);
		} else {
			/** Se realiza la conexion con usuario y pasword del servicio */
			env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
			env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
			ctx = new InitialDirContext(env);
		}
		return ctx;
	}

	/**
	 * Metodo para buscar el usuario en LDAP.
	 * 
	 * @param userName - Alias del usuario.
	 * 
	 * @return regresa un valor booleano, si el valor es verdadero si encotro al
	 *         usario.
	 * @throws NamingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * 
	 */
	@Override
	public LdapResponseDTO autentication(SecurityAuthDTO securityAuthDTO)
			throws NamingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		/** Objeto para guardar los datos que provienen de LDAP */
		LdapVO dataLdapVO = null;
		LdapResponseDTO ldapResponseDTO = new LdapResponseDTO();
		String userName = null;

		/** Solo para pruebas funcionales en desarrollo **/
		if (securityAuthDTO.getUserName().contains("elenao") || 
				securityAuthDTO.getUserName().contains("anamaria") ||
					securityAuthDTO.getUserName().contains("sahelig") ||
						securityAuthDTO.getUserName().contains("mariob") ||
							securityAuthDTO.getUserName().contains("benitob") ||
								securityAuthDTO.getUserName().contains("bartolob")) {
			ldapResponseDTO = datosDummysTest(securityAuthDTO);
			return ldapResponseDTO;
		}

		/** Condicion para validar en LDAP */
		if (ldapValidate) {
			log.info("Se valida usuario en LDAP");
			log.info("La validacion es por usuario en credentials.");
			userName = securityAuthDTO.getUserName();

			// Valida solo el usuario
			InitialDirContext ctx = conexionLdap(false, securityAuthDTO);
			dataLdapVO = buscaUsuario(ctx, securityAuthDTO);
			if (dataLdapVO != null) {

				log.info(new StringBuilder().append("Si existe el usuario en LDAP: ").append(userName));
				
				if(dataLdapVO.getIntentosFallidos() <= 3) {
				
					if (securityAuthDTO.isValidUserPwd()) {
						try {
							log.info("La validacion es por password.");
							/** valida el usuario y el password */
							InitialDirContext ctx2 = conexionLdap(securityAuthDTO.isValidUserPwd(), securityAuthDTO);
							dataLdapVO = buscaUsuario(ctx2, securityAuthDTO);
							ldapResponseDTO.setStatusCode(200);
							LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
							ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
	
						} catch (Exception ee) {
							ldapResponseDTO.setStatusCode(403);		
							ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
							errorMessageDTO.setStatusCode(2);
							errorMessageDTO.setTimestamp(new Date());
							errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_PASSWORD_INCORRECT.getName());
							LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
							ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
							ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
							log.info(new StringBuilder().append("EL password es incorrecto."));
						}
					}else {
						log.info("La validacion es por uauario.");
						ldapResponseDTO.setStatusCode(200);
						LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
						ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
					}
				}else {
					ldapResponseDTO.setStatusCode(403);		
					ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
					errorMessageDTO.setStatusCode(3);
					errorMessageDTO.setTimestamp(new Date());
					errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_USER_BLOCKED_FAILED_ATTEMPTS.getName());
					ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
					LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
					ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
					ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
					log.info(new StringBuilder().append("Usuario bloqueado por 3 intentos fallidos."));
				}

			} else {
				
				ldapResponseDTO.setStatusCode(403);		
				ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
				errorMessageDTO.setStatusCode(1);
				errorMessageDTO.setTimestamp(new Date());
				errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_USER_DISAEBLE.getName());
				ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
				log.info(new StringBuilder().append("Usuario no encontrado."));
			}
		} else {
			dataLdapVO = new LdapVO("usuario01", "*****", "10001", "20002", "usuario01 prueba", "usuario01",
					"Experto Técnico", "Area Prueba", "1530", 1, "usuario01@banobras.gob.mx",
					"Usuario01Prueba@banobras.gob.mx", 0, null, null, null, null);
			
			ldapResponseDTO.setStatusCode(200);
			LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
			ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
			
		}
		return ldapResponseDTO;
	}

	private LdapVO buscaUsuario(InitialDirContext ctx, SecurityAuthDTO securityAuthDTO)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NamingException {

		List<String> listaGrupoApp = null;
		List<String> listaGrupoAll = null;
		LdapVO dataLdapVO = null;

		/** Busca un usuario en especifico */
		String searchFilter = "(samaccountName=" + securityAuthDTO.getUserName() + ")";
		/** crea los filtros a buscar en LDAP */
		String[] reqAtt = { "uid", "cn", "sn", "initials", "displayname", "givenName", "mail", "department", "company",
				"sAMAccountName", "userPrincipalName", "title", "mailNickname", "telephoneNumber", "userAccountControl",
				"badPwdCount", "lockoutTime", "accountExpires", ConstantsSecurityAuth.MEMBER_OF.getName() };
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningAttributes(reqAtt);
		NamingEnumeration<SearchResult> objs = ctx.search(ldapSearchBase, searchFilter, controls);

		if (objs.hasMoreElements()) {

			while (objs.hasMoreElements()) {
				SearchResult match = objs.nextElement();
				Attributes attrs = match.getAttributes();

				try {
					/** Variable para guardar todos los perfiles a los que pertence el usuario */
					listaGrupoApp = findGroupsApp(attrs.get("memberOf").toString(), securityAuthDTO.getAppName());
					/** Variable para guardar todos los grupos a los que pertence el usuario */
					listaGrupoAll = findGroupsAll(attrs.get("memberOf").toString());
				} catch (Exception exnull) {
					listaGrupoAll = null;
				}

				dataLdapVO = new LdapVO(cleanText(attrs, "sAMAccountName"),
						securityAuthDTO.isValidUserPwd()
								? cipherAESCommon.encryptStringToAesHex(securityAuthDTO.getPassword())
								: null,
						cleanText(attrs, "initials"), cleanText(attrs, "userAccountControl"), cleanText(attrs, "cn"),
						cleanText(attrs, "givenName"), cleanText(attrs, "title"), cleanText(attrs, "department"),
						cleanText(attrs, "telephoneNumber"), findDisabled(match, "Disabled Accounts"),
						cleanText(attrs, "userPrincipalName"), cleanText(attrs, "mail"),
						cleanTextToInteger(attrs, "badPwdCount"), ldapDateToDateTime(cleanText(attrs, "lockoutTime")),
						listaGrupoApp, listaGrupoAll, null);
			}
		}
		return dataLdapVO;
	}

	@Override
	public LdapVO allDataUserLdap(SecurityAuthDTO securityAuthDTO)
			throws NamingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		List<String> listaGrupoApp = null;
		List<String> listaGrupoAll = null;
		
		LdapVO dataLdapVO = null;

		/** Conexion con el usuario de servicio */
		InitialDirContext ctx = conexionLdap(false, null);

		/** Busca todos en LDAP */
		/** String searchFilter = "(objectClass=*)"; **/

		/** Busca el usuario **/
		String searchFilter = "(samaccountName=" + securityAuthDTO.getUserName() + ")";

		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration<?> objs = ctx.search(ldapSearchBase, searchFilter, controls);

		while (objs.hasMoreElements()) {

			SearchResult match = (SearchResult) objs.nextElement();
			Attributes attrs = match.getAttributes();

			/** obtiene los grupos a los que pertenece **/
			try {

				/** Variable para guardar todos los perfiles a los que pertence el usuario */
				listaGrupoApp = findGroupsApp(attrs.get("memberOf").toString(), securityAuthDTO.getAppName());
				/** Variable para guardar todos los grupos a los que pertence el usuario */
				listaGrupoAll = findGroupsAll(attrs.get("memberOf").toString());

			} catch (Exception exnull) {
				listaGrupoAll = new ArrayList<String>();
				listaGrupoAll.add("-E-");
			}

			dataLdapVO = new LdapVO(cleanText(attrs, "sAMAccountName"),
					securityAuthDTO.isValidUserPwd()
							? cipherAESCommon.encryptStringToAesHex(securityAuthDTO.getPassword())
							: null,
					cleanText(attrs, "initials"), 
					cleanText(attrs, "userAccountControl"), 
					cleanText(attrs, "cn"),
					cleanText(attrs, "givenName"), cleanText(attrs, "title"), 
					cleanText(attrs, "department"),
					cleanText(attrs, "telephoneNumber"), 
					findDisabled(match, "Disabled Accounts"),
					cleanText(attrs, "userPrincipalName"), 
					cleanText(attrs, "mail"),
					cleanTextToInteger(attrs, "badPwdCount"), 
					ldapDateToDateTime(cleanText(attrs, "lockoutTime")),
					listaGrupoApp, listaGrupoAll, attrs.toString());
		}
		

		return dataLdapVO;
	}

	private String cleanText(Attributes attrs, String etiqueta) {
		String cadenaResult = "etiqueta";
		try {
			cadenaResult = attrs.get(etiqueta).toString();
			cadenaResult = cadenaResult.replace(etiqueta, "");
			cadenaResult = cadenaResult.replace(":", "");
		} catch (Exception exx) {
			cadenaResult = "";
		}
		return cadenaResult.trim();
	}

	private Integer cleanTextToInteger(Attributes attrs, String etiqueta) {
		String cadenaResult = "0";
		try {
			cadenaResult = attrs.get(etiqueta).toString();
			cadenaResult = cadenaResult.replace(etiqueta, "");
			cadenaResult = cadenaResult.replace(":", "");
		} catch (Exception exx) {
			return 0;
		}
		return Integer.parseInt(cadenaResult.trim());
	}

	private Integer findDisabled(SearchResult match, String etiqueta) {
		String cadena = match.toString();
		if (cadena.contains(etiqueta)) {
			return 0;
		} else {
			return 1;
		}
	}

	private List<String> findGroupsApp(String attr, String app) {
		String[] memberOfList = attr.split("DC=mx,");
		List<String> listGroup = new ArrayList<>();
		Map<String, Object> gruposMap = new HashMap<>();

		if (app != null && app.length() > 0) {
			for (String grupo : memberOfList) {
				if (grupo.contains(app)) {
					int ii = grupo.indexOf("CN=");
					String grupoAux = grupo.substring(ii + 3);
					int fi = grupoAux.indexOf(",");
					String valGrupo = grupoAux.substring(0, fi);

					if (!gruposMap.containsValue(valGrupo)) {
						listGroup.add(valGrupo);
						gruposMap.put(valGrupo, valGrupo);
					}
				}
			}
		}
		return listGroup;
	}

	private List<String> findGroupsAll(String attr) {
		String[] memberOfList = attr.split("DC=mx,");
		List<String> listGroup = new ArrayList<>();
		Map<String, Object> gruposMap = new HashMap<>();

		for (String grupo : memberOfList) {
			int ii = grupo.indexOf("CN=");
			String grupoAux = grupo.substring(ii + 3);
			int fi = grupoAux.indexOf(",");
			String valGrupo = grupoAux.substring(0, fi);

			if (!gruposMap.containsValue(valGrupo)) {
				listGroup.add(valGrupo);
				gruposMap.put(valGrupo, valGrupo);
			}
		}
		return listGroup;
	}

	/**
	 * Meotodo para formatear le fecha de LDAP a Date-
	 * @param inputDateString
	 * @return Date
	 */
	private Date ldapDateToDateTime(String inputDateString) {
		try {
			if (inputDateString != null && inputDateString.length() > 5) {
				if (!inputDateString.isEmpty()) {
					long fileTime = (Long.parseLong(inputDateString) / 10000L) - +11644473600000L;
					return new Date(fileTime);
				} else {
					return null;
				}

			} else {
				return null;
			}
		} catch (Exception ex) {
			return null;
		}

	}

	/*
	 * Metodo para crear datos dummys y realizar las pruebas funcionales
	 */
	private LdapResponseDTO datosDummysTest(SecurityAuthDTO securityAuthDTO) throws NamingException {
		LdapVO dataLdapVO = null;
		List<String> listaGrupoApp = new ArrayList<>();
		List<String> listaGrupoAll = new ArrayList<>();
		LdapResponseDTO ldapResponseDTO = new LdapResponseDTO();
		log.info(securityAuthDTO.getPassword() + " - " + securityAuthDTO.getPassword().equals("12345"));
		if (securityAuthDTO.getUserName().equals("elenao")) {
				listaGrupoAll.add("BITACORAS_APLICATIVO ");
				listaGrupoApp.add("BITACORAS_APLICATIVO");
				dataLdapVO = new LdapVO("elenao", "*****", "34505", "10001", "Orozco Siliceo, Elena", 
						"Elena", "Experto Técnico",
						"193210-GERENCIA DE SOLUCIONES TECNOLOGICAS", "1001", 1, "elenao@banobras.gob.mx",
						"ElenaOrozco@banobras.gob.mx", 0, null, listaGrupoApp, listaGrupoAll, null);
				ldapResponseDTO.setStatusCode(200);		
				LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
				ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
		} else if (securityAuthDTO.getUserName().equals("anamaria")) {
				listaGrupoApp.add("BITACORAS_AUDITOR");
				listaGrupoAll.add("BITACORAS_AUDITOR");
				dataLdapVO = new LdapVO("anamaria", "*****", "44504", "20002", "Calderon Sánchez, Ana María", "Ana María",
						"Experto Técnico", "193210-GERENCIA DE SOLUCIONES TECNOLOGICAS", "1002", 1,
						"anamaria@banobras.gob.mx", "AnaMariaCalderon@banobras.gob.mx", 0, null, listaGrupoApp,
						listaGrupoAll, null);
				ldapResponseDTO.setStatusCode(200);		
				LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
				ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
		} else if (securityAuthDTO.getUserName().equals("sahelig")) {
				listaGrupoApp.add("BITACORAS_AUDITOR");
				listaGrupoApp.add("BITACORAS_ADMINISTRADOR");
				listaGrupoApp.add("BITACORAS_APLICATIVO");
				listaGrupoApp.add("MAC_AUDITOR");
				listaGrupoApp.add("SIGEVI_AUDITOR");
				
				listaGrupoAll.add("BITACORAS_AUDITOR");
				listaGrupoAll.add("BITACORAS_ADMINISTRADOR");
				listaGrupoAll.add("BITACORAS_APLICATIVO");
				listaGrupoAll.add("MAC_AUDITOR");
				listaGrupoAll.add("SIGEVI_AUDITOR");
				
				dataLdapVO = new LdapVO("sahelig", "*****", "34503", "30003", "Grrero Barrita, Saheli", "Saheli", "Experto Técnico",
						"193210-GERENCIA DE SOLUCIONES TECNOLOGICAS", "1003", 1, "sahelig@banobras.gob.mx",
						"SaheliGerrero@banobras.gob.mx", 0, null, listaGrupoApp, listaGrupoAll, null);
				ldapResponseDTO.setStatusCode(200);		
				LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
				ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
		}else if (securityAuthDTO.getUserName().equals("mariob")) {
				listaGrupoApp.add("BITACORAS_APLICATIVO");
				listaGrupoAll.add("BITACORAS_APLICATIVO");
				dataLdapVO = new LdapVO("mariob", "*****", "664506", "60006", "Barrera Ochoa, Mario", "Mario", "Experto Técnico",
						"193210-GERENCIA DE SOLUCIONES TECNOLOGICAS", "1066", 1, "mariob@banobras.gob.mx",
						"MarioBarrera@banobras.gob.mx", 3, null, listaGrupoApp, listaGrupoAll, null);
				ldapResponseDTO.setStatusCode(403);		
				ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
				errorMessageDTO.setStatusCode(3);
				errorMessageDTO.setTimestamp(new Date());
				errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_USER_BLOCKED_FAILED_ATTEMPTS.getName());
				LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
				ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
				ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}else if (securityAuthDTO.getUserName().equals("bartolob")) {
			listaGrupoApp.add("BITACORAS_APLICATIVO");
			listaGrupoAll.add("BITACORAS_APLICATIVO");
			dataLdapVO = new LdapVO("bartolob", "*****", "664506", "60006", "Ochoa Ochoa, Bartolo", "Bartolo", "Experto Técnico",
					"193210-GERENCIA DE SOLUCIONES TECNOLOGICAS", "1066", 0, "bartolob@banobras.gob.mx",
					"BartoloOchoa@banobras.gob.mx", 0, null, listaGrupoApp, listaGrupoAll, null);
			ldapResponseDTO.setStatusCode(403);		
			ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(4);
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_USER_DISAEBLE.getName());
			ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
	}else {
			ldapResponseDTO.setStatusCode(403);		
			ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(1);
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_USER_NOT_FOUND.getName());
			ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
		}

		if (!securityAuthDTO.getPassword().equals("12345")) {
			ldapResponseDTO.setStatusCode(403);		
			ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
			errorMessageDTO.setStatusCode(2);
			errorMessageDTO.setTimestamp(new Date());
			errorMessageDTO.setMessage(ConstantsSecurityAuth.MSG_PASSWORD_INCORRECT.getName());
			LdapVOMapperDTO mapperLdapDTO = new LdapVOMapperDTO();
			ldapResponseDTO.setLdapDTO(mapperLdapDTO.mapperVOtoDTO(dataLdapVO));
			ldapResponseDTO.setErrorMessageDTO(errorMessageDTO);
			log.info(new StringBuilder().append("EL password es incorrecto."));
		}
		return ldapResponseDTO;
	}
}
