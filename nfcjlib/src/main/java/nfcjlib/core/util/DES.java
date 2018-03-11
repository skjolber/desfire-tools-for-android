package nfcjlib.core.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Provides DES encryption services.
 * 
 * @author Daniel Andrade
 */
public class DES {

	public static byte[] encrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		byte[] cipherText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			DESKeySpec desKey = new DESKeySpec(myKey);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey key = keyFactory.generateSecret(desKey);

			Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			cipherText = cipher.doFinal(myMsg);
		} catch (Exception e) {
			return null;
		}

		return cipherText;
	}
	
	/*public static byte[] decrypt(byte[] myKey, byte[] myMsg) {
		return decrypt(new byte[8], myKey, myMsg, 0, myMsg.length);
	}*/
	
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		return decrypt(myIV, myKey, myMsg, 0, myMsg.length);
	}
	
	public static byte[] decrypt(byte[] myKey, byte[] myMsg, int offset, int length) {
		return decrypt(new byte[8], myKey, myMsg, offset, length);
	}

	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg, int offset, int length) {
		byte[] plainText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			DESKeySpec desKey = new DESKeySpec(myKey);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey key = keyFactory.generateSecret(desKey);

			Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			//plainText = cipher.doFinal(myMsg);
			plainText = cipher.doFinal(myMsg, offset, length);
		} catch (Exception e) {
			//TODO: multicatch only Java 1.7+
			e.printStackTrace();
			return null;
		}

		return plainText;
	}

}