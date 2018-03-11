package com.github.skjolber.desfire.ev1.model.key.session;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.github.skjolber.desfire.ev1.model.key.DesfireDESKey;

public class DesfireDESSessionKey extends DesfireSessionKey<DesfireDESKey> {
	
    private Cipher decodeCipher;
    private Cipher encodeCipher;
    
    public DesfireDESSessionKey newInstance(byte[] value, byte version) throws Exception {
        byte[] data = new byte[8];
        System.arraycopy(value, 0, data, 0, 8);
        
        for (int n = 0; n < 8; n++) {
    		byte version_bit = (byte) ((version & (1 << (7-n))) >> (7-n));
    		
    		data[n] &= 0xFE;
    		data[n] |= version_bit;
        }
        
        return new DesfireDESSessionKey(data);
    }
    
    protected DesfireDESSessionKey(byte[] data) throws Exception {
    	this.data = data;
    	
	    SecretKeySpec secretKeySpec = new SecretKeySpec(data, 0, 8, "DES");
	    
    	decodeCipher = Cipher.getInstance("DES/ECB/NoPadding");
        decodeCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        
    	encodeCipher = Cipher.getInstance("DES/ECB/NoPadding");
	    encodeCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
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
	public DesfireDESSessionKey newKey(byte[] rnda, byte[] rndb) throws Exception {
		byte[] buffer = new byte[8];
		 
		System.arraycopy(buffer, 0, rnda, 0, 4);
        System.arraycopy(rndb, 0, buffer, 4, 4);
		
		return new DesfireDESSessionKey (buffer);
	}

}
