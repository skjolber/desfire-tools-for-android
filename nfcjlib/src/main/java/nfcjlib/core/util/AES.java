package nfcjlib.core.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encryption and decryption using AES.
 * 
 * @author Daniel Andrade
 */
public class AES {

	/**
	 * Encrypt using AES.
	 * 
	 * @param myIV	Initialization vector (16 bytes)
	 * @param myKey	Encryption key (16 bytes)
	 * @param myMsg	Message to encrypt
	 * @return		The cipher text, or null on error.
	 */
	public static byte[] encrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		byte[] cipherText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			SecretKey sks = new SecretKeySpec(myKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, sks, iv);
			cipherText = cipher.doFinal(myMsg);
		} catch (Exception e) {
			return null;
		}

		return cipherText;
	}

	/**
	 * Decrypt using AES.
	 * 
	 * @param myIV	Initialization vector
	 * @param myKey	Decryption key
	 * @param myMsg	Cipher text to decrypt
	 * @return		The plain text, or null on error.
	 */
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		byte[] plainText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			SecretKey sks = new SecretKeySpec(myKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, sks, iv);
			plainText = cipher.doFinal(myMsg);
		} catch (Exception e) {
			return null;
		}

		return plainText;
	}

	/**
	 * Decryption using AES.
	 * 
	 * @param myIV		the initialization vector
	 * @param myKey		the key
	 * @param myMsg		the message
	 * @param offset	the offset within the message, pointing at ciphertext
	 * @param length	the length of the ciphertext
	 * @return			the plaintext, or {@code null} on error
	 */
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg, int offset, int length) {
		byte[] plainText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			SecretKey sks = new SecretKeySpec(myKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, sks, iv);
			plainText = cipher.doFinal(myMsg, offset, length);
		} catch (Exception e) {
			return null;
		}

		return plainText;
	}

}