package com.github.skjolber.desfire.ev1.model.key.session;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.github.skjolber.desfire.ev1.model.key.DesfireAESKey;

public class DesfireAESSessionKey extends DesfireSessionKey<DesfireAESKey> {
	
    private Cipher decodeCipher;
    private Cipher encodeCipher;
    
    public DesfireAESSessionKey(byte[] key) throws Exception {
    	if(key.length != 16) {
    		throw new IllegalArgumentException();
    	}
    	this.data = key;
    	
	    SecretKeySpec secretKeySpec = new SecretKeySpec(data, 0, 16, "AES");
	    
    	decodeCipher = Cipher.getInstance("AES/ECB/NoPadding");
        decodeCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        
    	encodeCipher = Cipher.getInstance("AES/ECB/NoPadding");
	    encodeCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec); // XXX
	    
    }
    
	@Override
	public byte[] encrypt(byte[] encrypt) throws Exception {
		return encodeCipher.doFinal(encrypt);
	}

	@Override
	public byte[] decrypt(byte[] decrypt) throws Exception {
		return decodeCipher.doFinal(decrypt);
	}

	@Override
	public DesfireAESSessionKey newKey(byte[] rnda, byte[] rndb) throws Exception {
		byte[] buffer = new byte[16];
		System.arraycopy (rnda, 0, buffer, 0, 4);
        System.arraycopy (rndb, 0, buffer, 4, 4);
        System.arraycopy (rnda, 12, buffer, 8, 4);
        System.arraycopy (rndb, 12, buffer, 12, 4);
		
		return new DesfireAESSessionKey(buffer); 
	}
}
