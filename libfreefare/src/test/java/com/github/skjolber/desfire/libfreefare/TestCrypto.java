package com.github.skjolber.desfire.libfreefare;

import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

import junit.framework.TestCase;

// https://github.com/leg0/libfreefare/blob/86c194ef6c308342f5ee23331894e9301a0e385c/test/test_mifare_desfire_aes.c

public class TestCrypto extends TestCase {
	
	private static final String TAG = TestCrypto.class.getName();

	private byte[] key_data = new byte[]{
			(byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
			(byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
			(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
			(byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
	};

	/**
	 * Test AES encryption. Note block size 16.
	 */
	
    public void test_mifare_desfire_aes_generate_subkeys() throws Throwable {
	    byte[] sk1 = {
    	        (byte)0xfb, (byte)0xee, (byte)0xd6, (byte)0x18,
    	        (byte)0x35, (byte)0x71, (byte)0x33, (byte)0x66,
    	        (byte)0x7c, (byte)0x85, (byte)0xe0, (byte)0x8f,
    	        (byte)0x72, (byte)0x36, (byte)0xa8, (byte)0xde
    	    };

	    byte[] sk2 = {
    	        (byte)0xf7, (byte)0xdd, (byte)0xac, (byte)0x30,
    	        (byte)0x6a, (byte)0xe2, (byte)0x66, (byte)0xcc,
    	        (byte)0xf9, (byte)0x0b, (byte)0xc1, (byte)0x1e,
    	        (byte)0xe4, (byte)0x6d, (byte)0x51, (byte)0x3b
    	    };
    	
	    Crypt.subKeys(key_data);

	    for(int i = 0; i < sk1.length; i++) {
	    	assertEquals(sk1[i], Crypt.K1[i]);
	    }

	    for(int i = 0; i < sk2.length; i++) {
	    	assertEquals(sk2[i], Crypt.K2[i]);
	    }

	    MifareDESFireKey mifareDESFireKey = new MifareDESFireKey();
	    mifareDESFireKey.setData(key_data);
	    mifareDESFireKey.setType(DesfireKeyType.AES);
	    
	    AESCrypto.cmac_generate_subkeys(mifareDESFireKey);

	    byte[] generatedSk1 = mifareDESFireKey.getCmac_sk1();
	    
	    for(int i = 0; i < sk1.length; i++) {
	    	assertEquals("Fail at " + i, sk1[i], generatedSk1[i]);
	    }

	    byte[] generatedSk2 = mifareDESFireKey.getCmac_sk2();
	    for(int i = 0; i < sk2.length; i++) {
	    	assertEquals("Fail at " + i, sk2[i], generatedSk2[i]);
	    }
	    
	    
    }

    public void test_mifare_desfire_aes_cmac_128() throws Exception {

        byte[] message = new byte[]{
            (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
            (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
            (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
            (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a
        };

        byte[] expected_cmac = new byte[]{
            (byte)0x07, (byte)0x0a, (byte)0x16, (byte)0xb4,
            (byte)0x6b, (byte)0x4d, (byte)0x41, (byte)0x44,
            (byte)0xf7, (byte)0x9b, (byte)0xdd, (byte)0x9d,
            (byte)0xd0, (byte)0x4a, (byte)0x28, (byte)0x7c
        };

    	byte[] cmac = Crypt.CMAC(key_data, message);
    	
	    for(int i = 0; i < cmac.length; i++) {
	    	assertEquals(expected_cmac[i], cmac[i]);
	    }
	    
	    MifareDESFireKey mifareDESFireKey = new MifareDESFireKey();
	    mifareDESFireKey.setData(key_data);
	    mifareDESFireKey.setType(DesfireKeyType.AES);
	    AESCrypto.cmac_generate_subkeys(mifareDESFireKey);
	    
	    byte[] ivect = new byte[16];
	    byte[] my_cmac = new byte[16];

	    AESCrypto.cmac (mifareDESFireKey, ivect, message, 0, message.length, my_cmac);
	    
	    for(int i = 0; i < cmac.length; i++) {
	    	assertEquals("Fail at " + i + ": " + Utils.getHexString(message), expected_cmac[i], my_cmac[i]);
	    }
	    
    }
    
    public void test_mifare_desfire_aes_cmac_512() throws Exception {

    	byte[] message = new byte[]{
    	        (byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
    	        (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
    	        (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
    	        (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a,
    	        (byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57,
    	        (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c,
    	        (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac,
    	        (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51,
    	        (byte)0x30, (byte)0xc8, (byte)0x1c, (byte)0x46,
    	        (byte)0xa3, (byte)0x5c, (byte)0xe4, (byte)0x11,
    	        (byte)0xe5, (byte)0xfb, (byte)0xc1, (byte)0x19,
    	        (byte)0x1a, (byte)0x0a, (byte)0x52, (byte)0xef,
    	        (byte)0xf6, (byte)0x9f, (byte)0x24, (byte)0x45,
    	        (byte)0xdf, (byte)0x4f, (byte)0x9b, (byte)0x17,
    	        (byte)0xad, (byte)0x2b, (byte)0x41, (byte)0x7b,
    	        (byte)0xe6, (byte)0x6c, (byte)0x37, (byte)0x10
    	    };

    	byte[] expected_cmac = new byte[]{
    	        (byte)0x51, (byte)0xf0, (byte)0xbe, (byte)0xbf,
    	        (byte)0x7e, (byte)0x3b, (byte)0x9d, (byte)0x92,
    	        (byte)0xfc, (byte)0x49, (byte)0x74, (byte)0x17,
    	        (byte)0x79, (byte)0x36, (byte)0x3c, (byte)0xfe
    	    };
    	    
    	byte[] cmac = Crypt.CMAC(key_data, message);
    	
	    for(int i = 0; i < cmac.length; i++) {
	    	assertEquals(expected_cmac[i], cmac[i]);
	    }
	    
	    MifareDESFireKey mifareDESFireKey = new MifareDESFireKey();
	    mifareDESFireKey.setData(key_data);
	    mifareDESFireKey.setType(DesfireKeyType.AES);
	    AESCrypto.cmac_generate_subkeys(mifareDESFireKey);
	    
	    byte[] ivect = new byte[16];
	    byte[] my_cmac = new byte[16];

	    AESCrypto.cmac (mifareDESFireKey, ivect, message, 0, message.length, my_cmac);
	    
	    for(int i = 0; i < cmac.length; i++) {
	    	assertEquals("Fail at " + i + ": " + Utils.getHexString(message), expected_cmac[i], my_cmac[i]);
	    }

    }
    
    public void test_mifare_desfire_aes_cmac_320() throws Exception {

    	byte[] message = new byte[] {
    			(byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2,
    	        (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96,
    	        (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11,
    	        (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a,
    	        (byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57,
    	        (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c,
    	        (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac,
    	        (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51,
    	        (byte)0x30, (byte)0xc8, (byte)0x1c, (byte)0x46,
    	        (byte)0xa3, (byte)0x5c, (byte)0xe4, (byte)0x11
    	    };

    	byte[] expected_cmac = new byte[]{
    			(byte)0xdf, (byte)0xa6, (byte)0x67, (byte)0x47,
    	        (byte)0xde, (byte)0x9a, (byte)0xe6, (byte)0x30,
    	        (byte)0x30, (byte)0xca, (byte)0x32, (byte)0x61,
    	        (byte)0x14, (byte)0x97, (byte)0xc8, (byte)0x27
    	    };
    	    
    	byte[] cmac = Crypt.CMAC(key_data, message);
    	
	    for(int i = 0; i < cmac.length; i++) {
	    	assertEquals(expected_cmac[i], cmac[i]);
	    }
	    
	    MifareDESFireKey mifareDESFireKey = new MifareDESFireKey();
	    mifareDESFireKey.setData(key_data);
	    mifareDESFireKey.setType(DesfireKeyType.AES);
	    AESCrypto.cmac_generate_subkeys(mifareDESFireKey);
	    
	    byte[] ivect = new byte[16];
	    byte[] my_cmac = new byte[16];

	    AESCrypto.cmac (mifareDESFireKey, ivect, message, 0, message.length, my_cmac);
	    
	    for(int i = 0; i < expected_cmac.length; i++) {
	    	assertEquals("Fail at " + i + ": " + Utils.getHexString(my_cmac), expected_cmac[i], my_cmac[i]);
	    }

    }
}