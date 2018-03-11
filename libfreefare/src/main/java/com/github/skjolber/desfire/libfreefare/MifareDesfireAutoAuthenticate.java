package com.github.skjolber.desfire.libfreefare;

import android.util.Log;

public class MifareDesfireAutoAuthenticate {
	
	private static final String TAG = MifareDesfireAutoAuthenticate.class.getName();

	public static byte[] key_data_null  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	public static byte[] key_data_des   = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
	public static byte[] key_data_3des = { 'C', 'a', 'r', 'd', ' ', 'M', 'a', 's', 't', 'e', 'r', ' ', 'K', 'e', 'y', '!' };
	public static byte[] key_data_aes  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	public static byte[] key_data_3k3des  = { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	public static final byte key_data_aes_version = 0x42;
	
	public static void mifare_desfire_auto_authenticate (MifareTag tag, byte key_no) throws Exception
	{
	    /* Determine which key is currently the master one */
	    byte[] key_version = new byte[1];
	    int res = MifareDesfire.mifare_desfire_get_key_version (tag, key_no, key_version);
	    if(res < 0) {
	    	throw new IllegalArgumentException("Key version returned " + res);
	    }

	    MifareDESFireKey key;

    	Log.d(TAG, "Key version is " + Integer.toHexString((0xFF & key_version[0])));

	    switch (key_version[0]) {
	    case 0x00:
		key = MifareDesfireKey.mifare_desfire_des_key_new_with_version (key_data_null);
		break;
	    case 0x42:
		key = MifareDesfireKey.mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
		break;
	    case (byte) 0xAA:
	    	Log.d(TAG, "Authenticate using DES key");
		key = MifareDesfireKey.mifare_desfire_des_key_new_with_version (key_data_des);
		break;
	    case (byte) 0xC7:
		key = MifareDesfireKey.mifare_desfire_3des_key_new_with_version (key_data_3des);
		break;
	    case 0x55:
		key = MifareDesfireKey.mifare_desfire_3k3des_key_new_with_version (key_data_3k3des);
		break;
	    default:
		throw new IllegalArgumentException("Unknown master key " + Integer.toHexString(key_version[0] & 0xFF));
	    }

	    /* Authenticate with this key */
	    switch (key_version[0]) {
	    case 0x00:
	    case (byte) 0xAA:
	    case (byte) 0xC7:
	    	Log.d(TAG, "Regular authenticate");
		res = MifareDesfire.mifare_desfire_authenticate (tag, key_no, key);
		break;
	    case 0x55:
	    	Log.d(TAG, "ISO authenticate");
		res = MifareDesfire.mifare_desfire_authenticate_iso (tag, key_no, key);
		break;
	    case 0x42:
	    	Log.d(TAG, "AES authenticate");
		res = MifareDesfire.mifare_desfire_authenticate_aes (tag, key_no, key);
		break;
	    }
	    
	    if(res != 0) {
	    	throw new IllegalArgumentException("Not authenticated");
	    }
	}
}
