package com.github.skjolber.desfire.ev1.model.key.session;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import com.github.skjolber.desfire.ev1.model.key.Desfire3K3DESKey;

public class Desfire3K3DESSessionKey extends DesfireSessionKey<Desfire3K3DESKey> {
	
    private Cipher[] decodeCiphers;
    private Cipher[] encodeCiphers;
    
    public Desfire3K3DESSessionKey newInstance(byte[] value) throws Exception {
        byte[] data = new byte[24];
        System.arraycopy (value, 0, data, 0, 24);
        for (int n=0; n < 8; n++)
    	data[n] &= 0xfe;
        
    	return new Desfire3K3DESSessionKey(data);
    }
    
    protected Desfire3K3DESSessionKey(byte[] data) throws Exception {
    	this.data = data;
    	
	    SecretKeySpec[] secretKeySpec = new SecretKeySpec[]{
	    		new SecretKeySpec(data, 0, 8, "DES"),
	    		new SecretKeySpec(data, 8, 8, "DES"),
	    		new SecretKeySpec(data, 16, 8, "DES")
	    };
	    
    	decodeCiphers = new Cipher[]{
    				Cipher.getInstance("DES/ECB/NoPadding"),
    				Cipher.getInstance("DES/ECB/NoPadding"),
    				Cipher.getInstance("DES/ECB/NoPadding")
    	};

    	encodeCiphers = new Cipher[]{
				Cipher.getInstance("DES/ECB/NoPadding"),
				Cipher.getInstance("DES/ECB/NoPadding"),
				Cipher.getInstance("DES/ECB/NoPadding")
    	};

    	encodeCiphers[0].init(Cipher.ENCRYPT_MODE, secretKeySpec[0]);
    	encodeCiphers[1].init(Cipher.DECRYPT_MODE, secretKeySpec[1]);
    	encodeCiphers[2].init(Cipher.ENCRYPT_MODE, secretKeySpec[2]);
    	
    	encodeCiphers[2].init(Cipher.DECRYPT_MODE, secretKeySpec[2]);
    	encodeCiphers[1].init(Cipher.ENCRYPT_MODE, secretKeySpec[1]);
    	encodeCiphers[0].init(Cipher.DECRYPT_MODE, secretKeySpec[0]);

    }
    
	@Override
	public byte[] encrypt(byte[] payload) throws Exception {
		for(Cipher cipher : encodeCiphers) {
			payload = cipher.doFinal(payload);
		}
		return payload;
	}

	@Override
	public byte[] decrypt(byte[] payload) throws Exception {
		for(Cipher cipher : decodeCiphers) {
			payload = cipher.doFinal(payload);
		}
		return payload;
	}

	@Override
	public Desfire3K3DESSessionKey newKey(byte[] rnda, byte[] rndb) throws Exception {
		byte[] buffer = new byte[24];
		
		System.arraycopy (rnda, 0, buffer, 0, 4);
        System.arraycopy (rndb, 0, buffer, 4, 4);
        System.arraycopy (rnda, 6, buffer, 8, 4);
        System.arraycopy (rndb, 6, buffer, 12, 4);
        System.arraycopy (rnda, 12, buffer, 16, 4);
        System.arraycopy (rndb, 12, buffer, 20, 4);
		
		return newInstance(buffer); // XXX bug?
	}
}
