
package com.github.skjolber.desfire.libfreefare;

import java.util.zip.CRC32;

import javax.crypto.Cipher;

import android.util.Log;

import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.IsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

public class AESCrypto {
	
	public static final byte CRYPTO_ERROR = 0x01;
	public static final int CRC32_PRESET = 0xFFFFFFFF;

	public static final int MAC_LENGTH = 4;
	public static final int CMAC_LENGTH = 8;
	
	public static final byte MDCM_PLAIN = 0x00;
	public static final byte MDCM_MACED = 0x01;
	public static final byte MDCM_ENCIPHERED = 0x03;
	
	public static final byte NOT_YET_AUTHENTICATED = -1;
	
	public static final byte  AUTHENTICATE_LEGACY = 0x0A;
	public static final byte  AUTHENTICATE_ISO = 0x1A;
	public static final byte  AUTHENTICATE_AES = (byte) 0xAA;
	
	
	public static final int MDCM_MASK = 0x000F;

	public static final int CMAC_NONE = 0;

	// Data send to the PICC is used to update the CMAC
	public static final int CMAC_COMMAND = 0x010;
	// Data received from the PICC is used to update the CMAC
	public static final int CMAC_VERIFY = 0x020;

	// MAC the command (when MDCM_MACED)
	public static final int MAC_COMMAND = 0x100;
	// The command returns a MAC to verify (when MDCM_MACED)
	public static final int MAC_VERIFY = 0x200;

	public static final int ENC_COMMAND = 0x1000;
	public static final int NO_CRC = 0x2000;

	public static final int MAC_MASK = 0x0F0;
	public static final int CMAC_MACK = 0xF00;
	
	public static final String TAG = AESCrypto.class.getName();

	public static final int MAX_CRYPTO_BLOCK_SIZE = 16;

	public static void xor (byte[] ivect, byte[] data, int offset, int len) {
	    for (int i = 0; i < len; i++) {
	        data[offset + i] ^= ivect[i];
	    }
	}
	
	public static void mifare_cypher_single_block (MifareDESFireKey key, byte[] data, int offset, byte[] ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, int block_size) throws Exception {
		
	    byte[] ovect = new byte[16];

	    if (direction == MifareCryptoDirection.MCD_SEND) {
	        xor (ivect, data, offset, block_size);
	    } else {
	        //memcpy (ovect, data, block_size);
	    	System.arraycopy(data, offset, ovect, 0, block_size);
	    }

	    byte[] edata = new byte[16];

	    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		
        switch (operation) {
	        case MCO_ENCYPHER:
	            cipher.init(Cipher.ENCRYPT_MODE, key.toKey());
	            break;
	        case MCO_DECYPHER:
	            cipher.init(Cipher.DECRYPT_MODE, key.toKey());
	            break;
	        }
        
        cipher.doFinal(data, offset, edata.length, edata, 0);

	    //memcpy (data, edata, block_size);
    	System.arraycopy(edata, 0, data, offset, block_size);

	    if (direction == MifareCryptoDirection.MCD_SEND) {
	        //memcpy (ivect, data, block_size);
	    	System.arraycopy(data, offset, ivect, 0, block_size);
	    } else {
	        xor (ivect, data, offset, block_size);
	        //memcpy (ivect, ovect, block_size);
	    	System.arraycopy(ovect, 0, ivect, 0, block_size);
	    }

	}

	public static void mifare_cypher_blocks_chained (MifareTag tag, MifareDESFireKey key, byte[] ivect, byte[] data, int dataOffset, int data_size, MifareCryptoDirection direction, MifareCryptoOperation operation) throws Exception {

	    if (tag != null) {
	        if (key == null) {
	            key = tag.getSessionKey();
	        }
	        
	        if (ivect == null) {
	            ivect = tag.getInitializationVector();
	        }
	        switch (tag.getAuthenticationScheme()) {
	        case AS_LEGACY:
	        	throw new IllegalArgumentException();
	        case AS_NEW:
	            break;
	        }
	    }
	    
	    int block_size = key_block_size (key);
	    
	    int offset = dataOffset;
	    while (offset < dataOffset + data_size) {
	        mifare_cypher_single_block (key, data, offset, ivect, direction, operation, block_size);
	        offset += block_size;
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
	
	public static void cmac_generate_subkeys(MifareDESFireKey key) throws Exception
	{
	    int kbs = key_block_size (key);
	    byte R = (byte) ((kbs == 8) ? 0x1B : 0x87);

	    byte[] l = new byte[kbs];
	    for(int i = 0; i < l.length; i++) {
	    	l[i] = 0;
	    }

	    byte[] ivect = new byte[kbs];
	    for(int i = 0; i < ivect.length; i++) {
	    	ivect[i] = 0;
	    }

	    mifare_cypher_blocks_chained (null, key, ivect, l, 0, kbs, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_ENCYPHER);

	    boolean xor = false;

	    Log.d(TAG, toHexString(l));

	    // Used to compute CMAC on complete blocks
	    key.setCmac_sk1(new byte[kbs]);
	    System.arraycopy(l, 0, key.getCmac_sk1(), 0, kbs);
	    xor = (l[0] & 0x80) != 0;
	    lsl (key.getCmac_sk1(), kbs);
	    if (xor) {
	        key.getCmac_sk1()[kbs-1] ^= R;
	    }
	    
	    // Used to compute CMAC on the last block if non-complete
	    key.setCmac_sk2(new byte[kbs]);
	    System.arraycopy(key.getCmac_sk1(), 0, key.getCmac_sk2(), 0, kbs);
	    xor = (key.getCmac_sk1()[0] & 0x80) != 0;
	    lsl (key.getCmac_sk2(), kbs);
	    if (xor) {
	        key.getCmac_sk2()[kbs-1] ^= R;
	    }
	}

	public static void cmac (MifareDESFireKey key, byte[] ivect, byte[] data, int dataOffset, int len, byte[] cmac) throws Exception
	{
	    int kbs = key_block_size (key);
	    byte[] buffer = new byte[padded_data_length (len, kbs)];

	    System.arraycopy(data, dataOffset, buffer, 0, len);

	    if ((len == 0) || (len % kbs != 0)) {
	        buffer[len++] = (byte) 0x80;
	        while (len % kbs != 0) {
	            buffer[len++] = 0x00;
	        }
	        xor (key.getCmac_sk2(), buffer, len - kbs, kbs);
	    } else {
	        xor (key.getCmac_sk1(), buffer, len - kbs, kbs);
	    }
	    
	    mifare_cypher_blocks_chained (null, key, ivect, buffer, 0, len, MifareCryptoDirection.MCD_SEND, MifareCryptoOperation.MCO_ENCYPHER);

	    System.arraycopy(ivect, 0, cmac, 0, kbs);
	}

	/*
	 * Size required to store nbytes of data in a buffer of size n*block_size.
	 */
	public static int padded_data_length (int nbytes, int block_size) {
	    if ((nbytes == 0) || (nbytes % block_size != 0))
	        return ((nbytes / block_size) + 1) * block_size;
	    else
	        return nbytes;
	}

	public static int key_block_size(MifareDESFireKey key) {
		
	    switch (key.getType()) {
		    case DES:
		    case TDES:
		    case TKTDES:
		    	return 8;
		    case AES:
				return 16;
		}
	
	    return 0;
	}
	
	public static  void lsl (byte[] data, int len) {
	    for (int n = 0; n < len - 1; n++) {
	        data[n] = (byte) ((data[n] << 1) | ((data[n+1]& 0x80) >> 7));
	    }
	    data[len - 1] <<= 1;
	}
	
	public boolean authenticate(MifareTag tag, int keyNo, MifareDESFireKey key, IsoDepAdapter io) throws Exception {
		byte[] ivect = tag.getInitializationVector();
		for(int i = 0; i < tag.getInitializationVector().length; i++) {
			ivect[i] = 0;
		}

		tag.setAuthenticatedKeyNumber(NOT_YET_AUTHENTICATED);

		tag.setSessionKey(null);

		tag.setAuthenticationScheme(AuthenticationScheme.AS_NEW);

		byte[] command = new byte[]{(byte) 0x90, AUTHENTICATE_AES, 0x00, 0x00, 0x01, (byte) keyNo, 0x00};
		
		Log.d(TAG, "Authenticate");
		byte[] result = io.transceive(command);
		
	    int key_length = result.length - 2;

	    byte[] PICC_E_RndB = new byte[16];
	    System.arraycopy(result, 0, PICC_E_RndB, 0, key_length);

	    byte[] PICC_RndB = new byte[16];
	    
	    System.arraycopy(PICC_E_RndB, 0, PICC_E_RndB, 0, key_length);

	    mifare_cypher_blocks_chained (tag, key, tag.getInitializationVector(), PICC_RndB, 0, key_length, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_DECYPHER);

	    byte[] PCD_RndA = new byte[16];

	    byte[] PCD_r_RndB = new byte[16];
	    
	    System.arraycopy(PICC_RndB, 0, PCD_r_RndB, 0, key_length);

	    rol (PCD_r_RndB, key_length);

	    byte[] token = new byte[32];
	    System.arraycopy(token, 0, PCD_RndA, 0, key_length);
	    
	    System.arraycopy(token, key_length, PCD_r_RndB, 0, key_length);

	    mifare_cypher_blocks_chained (tag, key, tag.getInitializationVector(), token, 0, 2 * key_length, MifareCryptoDirection.MCD_SEND, MifareCryptoOperation.MCO_ENCYPHER);

	    byte[] cmd2 = new byte[32 + 2 + 4];
	    cmd2[0] = (byte) 0x90;
	    cmd2[1] = (byte) 0xAF;
	    cmd2[2] = 0;
	    cmd2[3] = 0;
	    cmd2[4] = 0x20;
	    cmd2[cmd2.length - 1] = 0x00;
	    
	    System.arraycopy(token, 0, cmd2, 5, 2*key_length);

	    byte[] res = io.transceive(cmd2);
	    
	    if(res.length == 2 && res[1] == 0xAE) {
	    	return false;
	    }
	    
	    byte[] PICC_E_RndA_s = new byte[16];
	    System.arraycopy(res, 0, PICC_E_RndA_s, 0, key_length);

	    byte[] PICC_RndA_s = new byte[16];
	    
	    System.arraycopy(PICC_E_RndA_s, 0, PICC_RndA_s, 0, key_length);
	    
	    mifare_cypher_blocks_chained (tag, key, tag.getInitializationVector(), PICC_RndA_s, 0, key_length, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_DECYPHER);

	    byte[] PCD_RndA_s = new byte[key_length];
	    System.arraycopy(PCD_RndA, 0, PCD_RndA_s, 0, key_length);
	    rol (PCD_RndA_s, key_length);

	    for(int i = 0; i < key_length; i++) {
	    	if(PCD_RndA_s[i] != PICC_RndA_s[i]) {
	    		Log.d(TAG, "Failure");

	    		return false;
	    	}
	    }
	    
	    /*
	    tag.authenticated_key_no = keyNo;
	    tag.session_key = mifare_desfire_session_key_new (PCD_RndA, PICC_RndB, key);
	    memset (tag.ivect, 0, MAX_CRYPTO_BLOCK_SIZE);

	    switch (tag.authentication_scheme) {
	    case AS_LEGACY:
		break;
	    case AS_NEW:
		cmac_generate_subkeys (tag.session_key);
		break;
	    }
	     */
	    
	    return true;		
	}
	
	void rol (byte[] data, int len)
	{
	    byte first = data[0];
	    for (int i = 0; i < len-1; i++) {
	    	data[i] = data[i+1];
	    }
	    data[len-1] = first;
	}

	/*
	 * Select the application specified by aid for further operation.  If aid is
	 * NULL, the master application is selected (equivalent to aid = 0x00000).
	 */
	public boolean mifare_desfire_select_application (MifareTag tag, int appId, IsoDepAdapter isoDep) throws Exception	{
	    byte[] cmd = new byte[4 + CMAC_LENGTH];

	    cmd[0] = 0x5A;
	    cmd[1] = (byte) ((appId & 0xFF0000) >> 16);
	    cmd[2] = (byte) ((appId & 0xFF00) >> 8);
	    cmd[3] = (byte) (appId & 0xFF);

	    byte[] p = mifare_cryto_preprocess_data (tag, cmd, 4, 0, MDCM_PLAIN | CMAC_COMMAND);

	    // 1 + CMAC_LENGTH ?
	    byte[] res = isoDep.sendCommand(p[0], p, 1, p.length - 1, DefaultIsoDepAdapter.OPERATION_OK);
	    
	    p = mifare_cryto_postprocess_data (tag, res, res.length, MDCM_PLAIN | CMAC_COMMAND);

	    if (p == null) {
	    	return false;
	    }

	    /*
	    for (int n = 0; n < MAX_FILE_COUNT; n++)
		cached_file_settings_current[n] = false;
	     */
	    
	    tag.setSessionKey(null);
	    
	    tag.setSelectedApplication(appId);

	    return true;
	}
	
	public MifareDESFireKey mifare_desfire_session_key_new (byte[] rnda, byte[] rndb, MifareDESFireKey authentication_key) {
	    MifareDESFireKey key;

	    byte[] buffer = new byte[24];

	    switch (authentication_key.getType()) {
	    case DES:
	    	throw new IllegalArgumentException();
	    case TDES:
	    	throw new IllegalArgumentException();
	    case TKTDES:
	    	throw new IllegalArgumentException();
	    case AES:
	    	System.arraycopy(rnda, 0, buffer, 0, 4);
	    	System.arraycopy(rndb, 0, buffer, 4, 4);
	    	System.arraycopy(rnda, 12, buffer, 8, 4);
	    	System.arraycopy(rndb, 12, buffer, 12, 4);
    	
	    	key = mifare_desfire_aes_key_new (buffer);
	    	
	    	break;
	    default : {
	    	throw new IllegalArgumentException();
	    }
	    }

	    return key;
	}
	
	private MifareDESFireKey mifare_desfire_aes_key_new (byte[] value) {
		if(value.length != 16) {
			throw new IllegalArgumentException();
		}
	    return mifare_desfire_aes_key_new_with_version (value, 0);
	}

	private MifareDESFireKey mifare_desfire_aes_key_new_with_version (byte[] value, int version) {
		if(value.length != 16) {
			throw new IllegalArgumentException();
		}

	    MifareDESFireKey key = new MifareDESFireKey();
	    key.setType(DesfireKeyType.AES);
	    key.setVersion((byte)version);
	    
	    return key;
	}	
	
	public byte[] mifare_cryto_preprocess_data (MifareTag tag, byte[] data, int nbytes, int offset, int communication_settings) throws Exception {
	    byte[] res = data;
	    boolean append_mac = true;
	    MifareDESFireKey key = tag.getSessionKey();

	    if (key == null) {
	    	return data;
	    }
	    
	    switch (communication_settings & MDCM_MASK) {
	    case MDCM_PLAIN:
		if (AuthenticationScheme.AS_LEGACY == tag.getAuthenticationScheme()) {
		    break;
		}

		/*
		 * When using new authentication methods, PLAIN data transmission from
		 * the PICC to the PCD are CMACed, so we have to maintain the
		 * cryptographic initialisation vector up-to-date to check data
		 * integrity later.
		 *
		 * The only difference with CMACed data transmission is that the CMAC
		 * is not appended to the data send by the PCD to the PICC.
		 */

		append_mac = false;

		/* pass through */
	    case MDCM_MACED:
		switch (tag.getAuthenticationScheme()) {
		case AS_LEGACY:
		    throw new RuntimeException();
		case AS_NEW:
		    if ((communication_settings & CMAC_COMMAND) == 0) {
				break;
		    }
		    cmac (key, tag.getInitializationVector(), res, 0, nbytes, tag.getCMAC());

		    if (append_mac) {
				int mdl = maced_data_length (key, nbytes);
				
				tag.initializeCryptoBuffer(mdl);
				
				System.arraycopy(data, 0, res, 0, nbytes);
				
				System.arraycopy(tag.getCMAC(), 0, res, nbytes, CMAC_LENGTH);
				
				nbytes += CMAC_LENGTH;
		    }
		    break;
		}

		break;
	    case MDCM_ENCIPHERED:
		/*  |<-------------- data -------------.|
		 *  |<--- offset -.|                    |
		 *  +---------------+--------------------+-----+---------+
		 *  | CMD + HEADERS | DATA TO BE SECURED | CRC | PADDING |
		 *  +---------------+--------------------+-----+---------+ ----------------
		 *  |               |<~~~~v~~~~~~~~~~~~~>|  ^  |         |   (DES / 3DES)
		 *  |               |     `---- crc16() ----'  |         |
		 *  |               |                    |  ^  |         | ----- *or* -----
		 *  |<~~~~~~~~~~~~~~~~~~~~v~~~~~~~~~~~~~>|  ^  |         |  (3K3DES / AES)
		 *                  |     `---- crc32() ----'  |         |
		 *                  |                                    | ---- *then* ----
		 *                  |<---------------------------------.|
		 *                            encypher()/decypher()
		 */

		    if ((communication_settings & ENC_COMMAND) == 0) {
		    	break;
		    }
		    
		    int edl = enciphered_data_length (tag, nbytes - offset, communication_settings) + offset;


		    System.arraycopy(data, 0, res, 0, nbytes);
		    
		    // Fill in the crypto buffer with data ...
			    if ((communication_settings & NO_CRC) == 0) {	
					// ... CRC ...
			    	switch (tag.getAuthenticationScheme()) {
					case AS_LEGACY:
						throw new IllegalArgumentException();
					case AS_NEW:
					    desfire_crc32_append (res, nbytes);
					    nbytes += 4;
					    break;
					}
			    }
		    // ... and padding
			for(int i = nbytes; i < edl; i++) {
				res[i] = 0;
			}

		    nbytes = edl;

		    mifare_cypher_blocks_chained (tag, null, null, res, offset, nbytes - offset, MifareCryptoDirection.MCD_SEND, (AuthenticationScheme.AS_NEW == tag.getAuthenticationScheme()) ? MifareCryptoOperation.MCO_ENCYPHER : MifareCryptoOperation.MCO_DECYPHER);
		break;
	    default:
	    	throw new IllegalArgumentException("Unknown communication settings");
	    }

	    return res;
	}
	
	/*
	 * Buffer size required to MAC nbytes of data
	 */
	public int maced_data_length(MifareDESFireKey key, int nbytes) {
	    return nbytes + key_macing_length (key);
	}
	
	/*
	 * Size of MACing produced with the key.
	 */
	public static int key_macing_length (MifareDESFireKey key) {
	    int mac_length;

	    switch (key.getType()) {
	    case DES:
	    case TDES:
		mac_length = MAC_LENGTH;
		break;
	    case TKTDES:
	    case AES:
		mac_length = CMAC_LENGTH;
		break;
		default : {
			mac_length = 0;
		}
	    }

	    return mac_length;
	}


	public byte[] mifare_cryto_postprocess_data (MifareTag tag, byte[] data, int nbytes, int communication_settings) throws Exception {
	    byte[] res = data;
	    byte first_cmac_byte = 0;

	    MifareDESFireKey key = tag.getSessionKey();

	    if (key == null) {
	    	return data;
	    }

	    // Return directly if we just have a status code.
	    if (1 == nbytes)
	    	return res;

	    switch (communication_settings & MDCM_MASK) {
		    case MDCM_PLAIN:
	
			if (AuthenticationScheme.AS_LEGACY == tag.getAuthenticationScheme()) {
			    break;
			}

		/* pass through */
	    case MDCM_MACED:
		switch (tag.getAuthenticationScheme()) {
		case AS_LEGACY:
		    throw new IllegalArgumentException();
		case AS_NEW:
		    if ((communication_settings & CMAC_COMMAND) == 0) {
		    	break;
		    }
		    if ((communication_settings & CMAC_VERIFY) != 0) {
				if (nbytes < 9) {
				    throw new IllegalArgumentException("No room for CMAC!");
				}
				first_cmac_byte = data[nbytes - 9];
				
				data[nbytes - 9] = data[nbytes-1];
		    }

		    int n = ((communication_settings & CMAC_VERIFY) != 0) ? 8 : 0;
		    cmac (key, tag.getInitializationVector(), data, 0, nbytes - n, tag.getCMAC());

		    if ((communication_settings & CMAC_VERIFY) != 0) {
		    	data[nbytes - 9] = first_cmac_byte;
		    	
		    	byte[] cmac = tag.getCMAC();
		    	for(int k = 0; k < 8; k++) {
		    		if(cmac[k] != data[k + nbytes - 9]) {
					    tag.setLastPCDError(CRYPTO_ERROR);

			    		throw new IllegalArgumentException("CMAC NOT verified :-(");
		    		}
		    	}
			} else {
			    nbytes -= 8;
			}
		    break;
		}

		break;
	    case MDCM_ENCIPHERED:
	    	nbytes--;
	    	boolean verified = false;
	    	int crc_pos = 0;
	    	int end_crc_pos = 0;
	    	byte x;

		/*
		 * AS_LEGACY:
		 * ,-----------------+-------------------------------+--------+
		 * \     BLOCK n-1   |              BLOCK n          | STATUS |
		 * /  PAYLOAD | CRC0 | CRC1 | 0x80? | 0x000000000000 | 0x9100 |
		 * `-----------------+-------------------------------+--------+
		 *
		 *         <------------ DATA -----------.
		 * FRAME = PAYLOAD + CRC(PAYLOAD) + PADDING
		 *
		 * AS_NEW:
		 * ,-------------------------------+-----------------------------------------------+--------+
		 * \                 BLOCK n-1     |                  BLOCK n                      | STATUS |
		 * /  PAYLOAD | CRC0 | CRC1 | CRC2 | CRC3 | 0x80? | 0x0000000000000000000000000000 | 0x9100 |
		 * `-------------------------------+-----------------------------------------------+--------+
		 * <----------------------------------- DATA ------------------------------------.|
		 *
		 *         <----------------- DATA ---------------.
		 * FRAME = PAYLOAD + CRC(PAYLOAD + STATUS) + PADDING + STATUS
		 *                                    `------------------'
		 */

		mifare_cypher_blocks_chained (tag, null, null, res, 0, nbytes, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_DECYPHER);

		/*
		 * Look for the CRC and ensure it is followed by NULL padding.  We
		 * can't start by the end because the CRC is supposed to be 0 when
		 * verified, and accumulating 0's in it should not change it.
		 */
		switch (tag.getAuthenticationScheme()) {
		case AS_LEGACY:
			throw new IllegalArgumentException();
		case AS_NEW:
		    /* Move status between payload and CRC */
			
			tag.initializeCryptoBuffer(nbytes + 1);
			
			System.arraycopy(data, 0, res, 0, nbytes);
			
		    crc_pos = (nbytes) - 16 - 3;
		    if (crc_pos < 0) {
				/* Single block */
				crc_pos = 0;
		    }
		    
		    System.arraycopy(res, crc_pos, res,  crc_pos + 1, nbytes - crc_pos);
		    
		    res[crc_pos] = 0x00;
		    crc_pos++;
		    nbytes += 1;
		    break;
		}

		do {
		    int crc = 0;
		    switch (tag.getAuthenticationScheme()) {
		    case AS_LEGACY:
		    	throw new IllegalArgumentException();
		    case AS_NEW:
		    	end_crc_pos = crc_pos + 4;
		    	desfire_crc32 (res, end_crc_pos, crc);
			break;
		    }
		    if (crc == 0) {
				verified = true;
				for (int n = end_crc_pos; n < nbytes - 1; n++) {
				    byte aByte = res[n];
				    if (!( (0x00 == aByte) || ((0x80 == aByte) && (n == end_crc_pos)) )) {
				    	verified = false;
				    }
				}
		    }
		    if (verified) {
				nbytes = crc_pos;
				switch (tag.getAuthenticationScheme()) {
				case AS_LEGACY:
				    data[nbytes++] = 0x00;
				    break;
				case AS_NEW:
				    /* The status byte was already before the CRC */
				    break;
				}
		    } else {
				switch (tag.getAuthenticationScheme()) {
				case AS_LEGACY:
				    break;
				case AS_NEW:
				    x = res[crc_pos - 1];
				    res[crc_pos - 1] = res[crc_pos];
				    res[crc_pos] = x;
				    break;
				}
				crc_pos++;
		    }
		} while (!verified && (end_crc_pos < nbytes));

		if (!verified) {
		    tag.setLastPCDError(CRYPTO_ERROR);
			throw new IllegalArgumentException("CRC not verified in decyphered stream");
		}

		break;
	    default:
		throw new IllegalArgumentException("Unknown communication settings");
	    }
	    return res;
	}

		
	/*
	 * Buffer size required to encipher nbytes of data and a two bytes CRC.
	 */
	
	public int enciphered_data_length (MifareTag tag, int nbytes, int communication_settings) {
	    int crc_length = 0;
	    
	    if ((communication_settings & NO_CRC) == 0) {
			switch (tag.getAuthenticationScheme()) {
			case AS_LEGACY:
			    crc_length = 2;
			    break;
			case AS_NEW:
			    crc_length = 4;
			    break;
			}
	    }

	    int block_size = key_block_size (tag.getSessionKey());

	    return padded_data_length (nbytes + crc_length, block_size);
	}	
	
	public void desfire_crc32_append(byte[] data, int offset) {
		long crc32 = crc32(data, 0, offset);
		
		data[offset] = (byte) ((crc32 >>> 24) & 0xFF);
		data[offset + 1] = (byte) ((crc32 >>> 16) & 0xFF);
		data[offset + 2] = (byte) ((crc32 >>> 8) & 0xFF);
		data[offset + 3] = (byte) ((crc32 >>> 0) & 0xFF);
				
		// TODO might be reversed
	}
	
	public long crc32(byte[] data, int offset, int len) {
		CRC32 crc = new CRC32();
		crc.update(data, offset, len);
		return crc.getValue();
	}
	
	public int desfire_crc32 (byte[] data, int len, int crc) {
	    int desfire_crc = CRC32_PRESET;
	    for (int i = 0; i < len; i++) {
	    	crc = desfire_crc32_byte (desfire_crc, data[i]);
	    }
	    return crc;
	}

	static int desfire_crc32_byte (int crc, byte value) {
	    /* x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 */
	    int poly = 0xEDB88320;

	    crc ^= value;
	    for (int current_bit = 7; current_bit >= 0; current_bit--) {
	    	int bit_out = (crc) & 0x00000001;
	    	crc >>= 1;
	    	if (bit_out != 0) {
	    		crc ^= poly;
	    	}
	    }
	    
	    return crc;
	}
}
