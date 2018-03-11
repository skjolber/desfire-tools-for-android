package com.github.skjolber.desfire.libfreefare;

import android.util.Log;

import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

public class MifareDesfireKey {

	private static final String TAG = MifareDesfireKey.class.getName();

	public static void update_key_schedules (MifareDESFireKey key) {
	    Crypt.DES_set_key (key.getData(), 0, key.getKs1());
	    Crypt.DES_set_key (key.getData(), 8, key.getKs2());
	    if (DesfireKeyType.TKTDES == key.getType()) {
	    	Crypt.DES_set_key (key.getData(), 16, key.getKs3());
	    }
}

public static MifareDESFireKey mifare_desfire_des_key_new (byte[] value) {
    byte[] data = new byte[8];
    C.memcpy (data, value, 8);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_des_key_new_with_version (data);
}

public static MifareDESFireKey mifare_desfire_des_key_new_with_version (byte[] value) {
    MifareDESFireKey key = new MifareDESFireKey();

	key.setType(DesfireKeyType.DES);
	C.memcpy (key.getData(), value, 8);
	C.memcpy (key.getData(), 8, value, 0, 8);
	update_key_schedules (key);
	
	Log.d(TAG, "Key " + C.toHexString(value) + " K1: " + C.toHexString(key.getKs1()) + " K2: " + C.toHexString(key.getKs2()));
	
    return key;
}

	public static MifareDESFireKey mifare_desfire_3des_key_new (byte[] value)
{
    byte[] data = new byte[16];
    C.memcpy (data, value, 16);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    for (int n=8; n < 16; n++)
	data[n] |= 0x01;
    return mifare_desfire_3des_key_new_with_version (data);
}

	public static MifareDESFireKey mifare_desfire_3des_key_new_with_version (byte[] value)
{
    MifareDESFireKey key = new MifareDESFireKey();

	key.setType(DesfireKeyType.TDES);
	C.memcpy (key.getData(), value, 16);
	update_key_schedules (key);
	
    return key;
}

	public static MifareDESFireKey mifare_desfire_3k3des_key_new (byte[] value)
{
    byte[] data = new byte[24];
    C.memcpy (data, value, 24);
    for (int n=0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_3k3des_key_new_with_version (data);
}

	public static MifareDESFireKey mifare_desfire_3k3des_key_new_with_version (byte[] value)
{
    MifareDESFireKey key;

    if ((key = new MifareDESFireKey()) != null) {
	key.setType(DesfireKeyType.TKTDES);
	C.memcpy (key.getData(), value, 24);
	update_key_schedules (key);
    }
    return key;
}

	public static MifareDESFireKey mifare_desfire_aes_key_new (byte[] value)
{
    return mifare_desfire_aes_key_new_with_version (value, C.zero);
}

public static MifareDESFireKey mifare_desfire_aes_key_new_with_version (byte[] value, byte version)
{
    MifareDESFireKey key = new MifareDESFireKey();

    byte[] copy = new byte[value.length];
    System.arraycopy(value, 0, copy, 0, value.length);
    
	key.setData(copy);
	key.setType(DesfireKeyType.AES);
	key.setAESVersion(version);
	
    return key;
}

public static byte mifare_desfire_key_get_version (MifareDESFireKey key)
{
    byte version = 0;

    for (int n = 0; n < 8; n++) {
    	version |= ((key.getData()[n] & 1) << (7 - n));
    }

    return version;
}

public static void mifare_desfire_key_set_version (MifareDESFireKey key, byte version)
{
    for (int n = 0; n < 8; n++) {
	byte version_bit = (byte) ((version & (1 << (7-n))) >> (7-n));
	key.getData()[n] &= 0xfe;
	key.getData()[n] |= version_bit;
	if (key.getType() == DesfireKeyType.DES) {
	    key.getData()[n+8] = key.getData()[n];
	} else {
	    // Write ~version to avoid turning a 3DES key into a DES key
	    key.getData()[n+8] &= 0xfe;
	    key.getData()[n+8] |= ~version_bit;
	}
    }
}

public static MifareDESFireKey mifare_desfire_session_key_new (byte[] rnda, byte[] rndb, MifareDESFireKey authentication_key)
{
    MifareDESFireKey key = null;

    byte[] buffer = new byte[24];

    switch (authentication_key.getType()) {
    case DES:
	C.memcpy (buffer, rnda, 4);
	C.memcpy (buffer, 4, rndb, 0, 4);
	key = mifare_desfire_des_key_new_with_version (buffer);
	break;
    case TDES:
	C.memcpy (buffer, rnda, 4);
	C.memcpy (buffer, 4, rndb, 0, 4);
	C.memcpy (buffer, 8, rnda, 4, 4);
	C.memcpy (buffer, 12, rndb, 4, 4);
	key = mifare_desfire_3des_key_new_with_version (buffer);
	break;
    case TKTDES:
	C.memcpy (buffer, rnda, 4);
	C.memcpy (buffer, 4, rndb, 4);
	C.memcpy (buffer, 8, rnda, 6, 4);
	C.memcpy (buffer, 12, rndb, 6, 4);
	C.memcpy (buffer, 16, rnda, 12, 4);
	C.memcpy (buffer, 20, rndb, 12, 4);
	key = mifare_desfire_3k3des_key_new (buffer);
	break;
    case AES:
	C.memcpy (buffer, rnda, 4);
	C.memcpy (buffer, 4, rndb, 4);
	C.memcpy (buffer, 8, rnda, 12, 4);
	C.memcpy (buffer, 12, rndb, 12, 4);
	key = mifare_desfire_aes_key_new (buffer);
	break;
    }

    return key;
}

}
