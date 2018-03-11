package com.github.skjolber.desfire.libfreefare;

import org.junit.Assert;

import static com.github.skjolber.desfire.libfreefare.MifareDesfireKey.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireCrypto.*;


public class TestMifareDesfireAES {
	
	private static final String TAG = TestMifareDesfireAES.class.getName();

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
	    

	    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
	    assertEquals(key_data, key.getData());
	    
	    cmac_generate_subkeys (key);

	    assertEquals(sk1, key.getCmac_sk1());
	    assertEquals (sk2, key.getCmac_sk2());
	}
    
    public static final void assertEquals(byte[] expected, byte[] actual) {
    	for(int i = 0; i < expected.length; i++) {
	    	Assert.assertEquals("At " + i + "\n" + toHexString(expected) + "\n" + toHexString(actual), expected[i], actual[i]);
	    }
    }
    

    /**
     * Converts the byte array to HEX string.
     * 
     * @param buffer
     *            the buffer.
     * @return the HEX string.
     */
    public static String toHexString(byte[] buffer) {
		StringBuilder sb = new StringBuilder();
		for(byte b: buffer)
			sb.append(String.format("%02x", b&0xff));
		return sb.toString();
    }
    

	public void test_mifare_desfire_aes_cmac_empty() throws Exception {
	    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
	    cmac_generate_subkeys (key);

	    byte[] ivect = new byte[16];

	    byte[] expected_cmac = {
    	        (byte)0xbb, (byte)0x1d, (byte)0x69, (byte)0x29,
    	        (byte)0xe9, (byte)0x59, (byte)0x37, (byte)0x28,
    	        (byte)0x7f, (byte)0xa3, (byte)0x7d, (byte)0x12,
    	        (byte)0x9b, (byte)0x75, (byte)0x67, (byte)0x46
    	    };
    	

	    byte[] my_cmac = new byte[16];
	    cmac (key, ivect, null, 0, my_cmac);

	    assertEquals (expected_cmac, my_cmac);
	}

	public void test_mifare_desfire_aes_cmac_128() throws Exception {
	    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
	    cmac_generate_subkeys (key);

	    byte[] ivect = new byte[16];

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

	    byte[] my_cmac = new byte[16];
	    cmac (key, ivect, message, 16, my_cmac);

	    assertEquals (expected_cmac, my_cmac );
	}
	
	public void test_mifare_desfire_aes_cmac_320() throws Exception {
	    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
	    cmac_generate_subkeys (key);

	    byte[] ivect = new byte[16];

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
    	
    	
	    byte[] my_cmac = new byte[16];
	    cmac (key, ivect, message, message.length, my_cmac);

	    assertEquals (expected_cmac, my_cmac);
	}

	public void test_mifare_desfire_aes_cmac_512() throws Exception 
	{
	    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
	    cmac_generate_subkeys (key);

	    byte[] ivect = new byte[16];

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

	    byte[] my_cmac = new byte[16];
	    cmac (key, ivect, message, message.length, my_cmac);

	    assertEquals(expected_cmac, my_cmac);
	}
	
	
}
