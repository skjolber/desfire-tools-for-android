package com.github.skjolber.desfire.ev1.model.key.session;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.github.skjolber.desfire.ev1.model.key.Desfire3DESKey;

public class Desfire3DESSessionKey extends DesfireSessionKey<Desfire3DESKey> {
	
    private Cipher[] decodeCiphers;
    private Cipher[] encodeCiphers;
    
    public Desfire3DESSessionKey newInstance(byte[] value, byte version) throws Exception {
    	
        byte[] data = new byte[16];
        System.arraycopy(value, 0, data, 0, 16);
        
		for (int n = 0; n < 8; n++) {
			byte version_bit = (byte) ((version & (1 << (7-n))) >> (7-n));
			
			data[n] &= 0xFE;
			data[n] |= version_bit;
			
		    // Write ~version to avoid turning a 3DES key into a DES key
		    data[n+8] &= 0xfe;
		    data[n+8] |= ~version_bit;
		}    	
		
        return new Desfire3DESSessionKey(data);
    }

    protected Desfire3DESSessionKey(byte[] value) throws Exception {
    	this.data = value;
    	
	    SecretKeySpec[] secretKeySpec = new SecretKeySpec[]{
	    		new SecretKeySpec(data, 0, 8, "DES"),
	    		new SecretKeySpec(data, 8, 8, "DES"),
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
    	encodeCiphers[2].init(Cipher.ENCRYPT_MODE, secretKeySpec[0]);
    	
    	encodeCiphers[2].init(Cipher.DECRYPT_MODE, secretKeySpec[0]);
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
	public Desfire3DESSessionKey newKey(byte[] rnda, byte[] rndb) throws Exception {
		byte[] buffer = new byte[16];
		
		System.arraycopy(rnda, 0, buffer, 0, 4);
        System.arraycopy(rndb, 0, buffer, 4, 4);
        System.arraycopy(rnda, 4, buffer, 8, 4);
        System.arraycopy(rndb, 4, buffer, 12, 4);
		
		return new Desfire3DESSessionKey(buffer);
	}
	
	
}
