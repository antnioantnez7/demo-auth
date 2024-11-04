package mx.gob.banobras.securityauth.common.util;

/**
 * CipherAESCommon.java:
 * 
 * Clase para encriptar y descriptar cadenas alfanumericas, usanod el cifrado AES y 
 * el modo AES/CBC/PKCS5PADDING
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Component;

import lombok.Data;
import mx.gob.banobras.securityauth.infraestructure.config.dto.SecurityAuthDTO;

@Data
@Component
public class CipherAESCommon {

	/** Trazas de la aplicación */
	Logger log = LogManager.getLogger(CipherAESCommon.class);

	public CipherAESCommon() {
		log.info("");
	}

	/** Constante de la llave secreta */
	/**
	 * private static final String CIPHER_KEY = System.getenv().get("CIPHER_KEY");
	 */
	/** Constante del vector de cifrado */
	/** private static final String CIPHER_IV = System.getenv().get("CIPHER_IV"); */
	/** Constante de la tipo de cifrado */
	/**
	 * private static final String CIPHER_AES = System.getenv().get("CIPHER_AES");
	 */
	/** Constante del modo de cifrado */
	/**
	 * private static final String CIPHER_MODE = System.getenv().get("CIPHER_MODE");
	 */

	/** Constante de la llave secreta */
	@Value("${app.cipher.key}")
	String cipherKey;
	/** Constante del vector de cifrado */
	@Value("${app.cipher.iv}")
	String cipherIV;
	/** Constante de la tipo de cifrado */
	@Value("${app.cipher.aes}")
	String cipherAES;
	/** Constante del modo de cifrado */
	@Value("${app.cipher.mode}")
	String cipherMode;

	/**
	 * Metodo para encriptar un String y regresa en string en formato Hexadecimal.
	 * 
	 * @param plainTextData cadena a encriptar.
	 * @return String.
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * 
	 */
	public String encryptStringToAesHex(String plainTextData) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(cipherMode);
		byte[] dataBytes = plainTextData.getBytes();
		int plaintextLength = dataBytes.length;
		byte[] plaintext = new byte[plaintextLength];
		System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);

		SecretKeySpec keyspec = new SecretKeySpec(cipherKey.getBytes(), cipherAES);
		IvParameterSpec ivspec = new IvParameterSpec(cipherIV.getBytes());

		cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
		byte[] encrypted = cipher.doFinal(plaintext);

		return new String(Hex.encode(encrypted));

	}

	/**
	 * Metodo para desencriptar un String en formato Hexadecimal
	 * 
	 * @param String cadena a desencriptar.
	 * @return cipherTextData
	 * @throws IllegalBlockSizeException
	 */
	public String decryptAesHexToString(String cipherTextData) throws IllegalArgumentException {
		byte[] original = null;
		try {
			byte[] hexBytes = HexFormat.of().parseHex(cipherTextData);
			Cipher cipher = Cipher.getInstance(cipherMode);
			SecretKeySpec keyspec = new SecretKeySpec(cipherKey.getBytes(), cipherAES);
			IvParameterSpec ivspec = new IvParameterSpec(cipherIV.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
			original = cipher.doFinal(hexBytes);
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
		return new String(original);
	}

	/**
	 * Metodo para descriptar las credenciales del usuario, la cadena de entrada
	 * contien UserName y Password, separados por un espacio.
	 * 
	 * @param securityAuthDTO objeto que contien los datos de las credenciales.
	 * @return SecurityAuthDTO
	 * @throws IllegalArgumentException
	 */
	public SecurityAuthDTO getDataCredentials(SecurityAuthDTO securityAuthDTO)
			throws IllegalArgumentException {
		String[] valDecrypt;
		try {
			log.info("Incia obtener datos de credentials");
			valDecrypt = decryptAesHexToString(securityAuthDTO.getCredentials()).split(" ");
			/** Si los parametros en credentials son igual a mas de 2 */
			if (valDecrypt.length >= 2) {
				securityAuthDTO.setUserName(valDecrypt[0]);
				securityAuthDTO.setPassword(valDecrypt[1]);
			} else if (valDecrypt.length == 1) {
				securityAuthDTO.setUserName(valDecrypt[0]);
				securityAuthDTO.setPassword("");
			} else {
				throw new IllegalArgumentException(ConstantsSecurityAuth.MSG_CREDENTIALS_INVALID.getName());
			}

		} catch(Exception e) {
			e.printStackTrace();
			throw new IllegalArgumentException(ConstantsSecurityAuth.MSG_CREDENTIALS_INVALID.getName(),e);
		}
		log.info("Termina obtener datos de credentials.");
		return securityAuthDTO;

	}

}
