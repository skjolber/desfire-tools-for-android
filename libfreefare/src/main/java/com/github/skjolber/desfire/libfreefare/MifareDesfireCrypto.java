package com.github.skjolber.desfire.libfreefare;

import static com.github.skjolber.desfire.libfreefare.C.htole32;
import static com.github.skjolber.desfire.libfreefare.C.memcmp;
import static com.github.skjolber.desfire.libfreefare.C.memcpy;
import static com.github.skjolber.desfire.libfreefare.C.memmove;
import static com.github.skjolber.desfire.libfreefare.C.memset;

import java.nio.ByteBuffer;

import javax.crypto.Cipher;

import android.util.Log;

public class MifareDesfireCrypto {

	private static final String TAG = MifareDesfireCrypto.class.getName();

	public static final int MAX_CRYPTO_BLOCK_SIZE = 16;

	public static final int CRC32_PRESET = 0xFFFFFFFF;

	public static final int  MAC_LENGTH = 4;
	public static final int  CMAC_LENGTH = 8;

	public static final int NO_CRC = 0x2000;

	// Data send to the PICC is used to update the CMAC
	public static final int CMAC_COMMAND = 0x010;
	// Data received from the PICC is used to update the CMAC
	public static final int CMAC_VERIFY = 0x020;

	// MAC the command (when MDCM_MACED)
	public static final int MAC_COMMAND = 0x100;
	// The command returns a MAC to verify (when MDCM_MACED)
	public static final int MAC_VERIFY = 0x200;

	public static final int MDCM_MASK = 0x000F; // 1111
	
	
	
	/** ENUM */
	public static final byte MDCM_PLAIN = 0x00;
	public static final byte MDCM_MACED = 0x01;
	public static final byte MDCM_ENCIPHERED = 0x03;

	public static final byte APPLICATION_CRYPTO_DES = 0x00;
	public static final byte APPLICATION_CRYPTO_3K3DES = 0x40;
	public static final byte APPLICATION_CRYPTO_AES = (byte) 0x80;
	
	public static final int ENC_COMMAND = 0x1000;

	public static final byte CRYPTO_ERROR = 0x01;

	public static void xor (byte[] ivect, byte[] data, int len) {
		xor(ivect, 0, data, 0, len);
	}

	public static void xor (byte[] ivect, int ivectOffset, byte[] data, int dataOffset, int len) {
		for (int i = 0; i < len; i++) {
			data[i + dataOffset] ^= ivect[i + ivectOffset];
		}
	}

	public static void rol(byte[] data, int len) {
		rol(data, 0, len);
	}

	public static void rol(byte[] data, int offset, int len) {
		byte first = data[offset];
		for (int i = offset; i < offset + len - 1; i++) {
			data[i] = data[i + 1];
		}
		data[offset + len - 1] = first;
	}

	public static void lsl(byte[] data, int len) {
		lsl(data, 0, len);
	}

	public static void lsl(byte[] data, int offset, int len) {
		for (int n = offset; n < offset + len - 1; n++) {
	        data[n] = (byte) ((data[n] << 1) | ((data[n+1]& 0x80) >> 7));
		}
		data[offset + len - 1] <<= 1;
	}	
	
	public static void cmac_generate_subkeys (MifareDESFireKey key) throws Exception
	{
	    int kbs = key_block_size (key);
	    final byte R = (byte) ((kbs == 8) ? 0x1B : 0x87);

	    byte[] l = new byte[kbs]; // encrypted zeros

	    byte[] ivect = new byte[kbs];

	    mifare_cypher_blocks_chained (null, key, ivect, 0, l, 0, kbs, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_ENCYPHER);

	    boolean xor = false;
	    
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
    
    public static String toHexString(byte[] buffer, int dataOffset, int length, boolean space) {
		StringBuilder sb = new StringBuilder();
		for(int i = dataOffset; i < length; i++) {
			sb.append(String.format("%02x", buffer[i]&0xff));
			if(space) {
				sb.append(' ');
			}
		}
		return sb.toString();
    }

	
	public static void cmac (final MifareDESFireKey key, byte[] ivect, final byte[] data, int len, byte[] cmac) throws Exception
	{
	    int kbs = key_block_size (key);
	    byte[] buffer = C.malloc (padded_data_length (len, kbs));
	    
	    /*
	    if (!buffer)
		abort();
		*/
	    
	    C.memcpy (buffer, data, len);

	    if ((len == 0) || ((len % kbs) != 0)) {
	    	// do padding ( 0x80 and zeros )
			buffer[len++] = (byte) 0x80;
			while ((len % kbs) != 0) {
			    buffer[len++] = 0x00;
			}
			xor (key.getCmac_sk2(), 0, buffer, len - kbs, kbs);
	    } else {
	    	xor (key.getCmac_sk1(), 0, buffer, len - kbs, kbs);
	    }

	    mifare_cypher_blocks_chained (null, key, ivect, 0, buffer, 0, len, MifareCryptoDirection.MCD_SEND, MifareCryptoOperation.MCO_ENCYPHER);

	    C.memcpy (cmac, ivect, kbs);
	}
	
	public static void desfire_crc32_byte (int[] crc, final byte value)
	{
	    /* x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 */
	    final int poly = 0xEDB88320;

	    crc[0] ^= value;
	    for (int current_bit = 7; current_bit >= 0; current_bit--) {
			int bit_out = (crc[0]) & 0x00000001;
			crc[0] >>= 1;
			if (bit_out != 0)
				crc[0] ^= poly;
	    }
	}

	private static final int CRC32_POLYNOMIAL = 0xEDB88320;
	/*
	--------------------------------------------------------------------------
	Calculate a CRC value to be used by CRC calculation functions.
	--------------------------------------------------------------------------
	*/
	private static int CRC32Value(int i)
	{
	short j;
	int ulCRC;
	ulCRC = i;

	for (j = 8; j > 0; j--) {
	if ((ulCRC & 1) == 1)
	ulCRC = (ulCRC >>> 1) ^ CRC32_POLYNOMIAL;
	else
	ulCRC >>>= 1;
	}
	return ulCRC;
	}

	/*
	--------------------------------------------------------------------------
	Calculates the CRC-32 of a block of data all at once
	--------------------------------------------------------------------------
	*/
	public static int calculateCRC32(int length, byte[] buffer)
	{
		int ulTemp1;
		int ulTemp2;
		int ulCRC = 0;
	
		for(int i = 0; i < length; i++) {
		ulTemp1 = ( ulCRC >>> 8 ) & 0x00FFFFFF;
		ulTemp2 = CRC32Value( ((int) ulCRC ^ buffer[i] ) & 0xff );
		ulCRC = ulTemp1 ^ ulTemp2;
		}
		return ulCRC;
	}
	
	public static void desfire_crc32 (final byte[] data, final int len, byte[] crc, int crcOffset)
	{

		CRC32 checksum = new CRC32();
	    C.htole32 (checksum.calculateCRC32(data, 0, len), crc, crcOffset);
	}

	public static void desfire_crc32_append (byte[] data, final int len)
	{
	    desfire_crc32 (data, len, data, len);
	}

	public static int key_block_size (final MifareDESFireKey key) {
	    int block_size;

	    switch (key.getType()) {
	    case DES:
	    case TDES:
	    case TKTDES:
		block_size = 8;
		break;
	    case AES:
		block_size = 16;
		break;
		default : throw new IllegalArgumentException();
	    }

	    return block_size;
	}

	/*
	 * Size of MACing produced with the key.
	 */
	public static int key_macing_length (final MifareDESFireKey key)
	{
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
			default : throw new IllegalArgumentException();
	    }

	    return mac_length;
	}

	/*
	 * Size required to store nbytes of data in a buffer of size n*block_size.
	 */
	public static int padded_data_length (final int nbytes, final int block_size)
	{
	    if ((nbytes == 0) || ((nbytes % block_size) != 0))
		return ((nbytes / block_size) + 1) * block_size;
	    else
		return nbytes;
	}

	/*
	 * Buffer size required to MAC nbytes of data
	 */
	public static int maced_data_length (final MifareDESFireKey key, final int nbytes)
	{
	    return nbytes + key_macing_length (key);
	}
	/*
	 * Buffer size required to encipher nbytes of data and a two bytes CRC.
	 */
	public static int
	enciphered_data_length (final MifareTag tag, final int nbytes, int communication_settings)
	{
	    int crc_length = 0;
	    if ((communication_settings & NO_CRC) == 0) {
		switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		case AS_LEGACY:
		    crc_length = 2;
		    break;
		case AS_NEW:
		    crc_length = 4;
		    break;
		}
	    }
	    
	    int block_size = C.MIFARE_DESFIRE(tag).hasSessionKey() ? key_block_size (C.MIFARE_DESFIRE (tag).getSessionKey()) : 1;

	    return padded_data_length (nbytes + crc_length, block_size);
	}


	/*
	 * Ensure that tag's crypto buffer is large enough to store nbytes of data.
	 */
	public static byte[] assert_crypto_buffer_size (MifareTag tag, int nbytes)
	{
		
		// crypto buffer must be exact
		
		byte[] res = new byte[nbytes];
		
		byte[] cryptoBuffer = C.MIFARE_DESFIRE (tag).getCryptoBuffer();
		if(cryptoBuffer != null) {
			System.arraycopy(cryptoBuffer, 0, res, 0, Math.min(cryptoBuffer.length, res.length));
		}

	    C.MIFARE_DESFIRE (tag).setCryptoBuffer(res);

		return res;
		
		/*
	    if (MIFARE_DESFIRE (tag).getCryptoBufferSize() < nbytes) {
	    	res = realloc (MIFARE_DESFIRE (tag).getCryptoBuffer(), nbytes);
	    	
		    MIFARE_DESFIRE (tag).setCryptoBuffer(res);
		    MIFARE_DESFIRE (tag).setCryptoBufferSize(nbytes);
	    } else {
		    res = MIFARE_DESFIRE (tag).getCryptoBuffer();
	    }
	    return res;
	    */
	}

	public static byte[] mifare_cryto_preprocess_data (MifareTag tag, ByteBuffer cmd, int length, int offset, int communication_settings) throws Exception {
		return mifare_cryto_preprocess_data(tag, cmd.array(), 0, length, offset, communication_settings);
	}
	
	/***
	 * 
	 * Modification: Always returns the exact number of bytes required for the command.
	 * 
	 */

	public static byte[] mifare_cryto_preprocess_data (MifareTag tag, byte[] data, int dataOffset, int nbytes, int offset, int communication_settings) throws Exception
	{
		
		// Log.d(TAG, "IVECT " + Utils.getHexString(tag.getInitializationVector()));
		// Log.d(TAG, "CMAC " + Utils.getHexString(MIFARE_DESFIRE (tag).getCMAC()));

    	// if offset, get those bytes too
    	// res må ikke bli for lang heller, må kopieres ned til data
		// TODO bruk byte buffer over alt
		if(dataOffset != 0) {
			throw new IllegalArgumentException();
		}
	    byte[] res = new byte[nbytes];
    	System.arraycopy(data, dataOffset, res, 0, nbytes);

	    byte[] mac = new byte[4];
	    int edl, mdl;
	    boolean append_mac = true;
	    MifareDESFireKey key = C.MIFARE_DESFIRE (tag).getSessionKey();

	    if (key == null) {
	    	return res;
	    }
	    
	    switch (communication_settings & MDCM_MASK) {
	    case MDCM_PLAIN:
		if (AuthenticationScheme.AS_LEGACY == C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		    break;
		}

		/*
		 * When using new authentication methods, PLAIN data transmission from
		 * the PICC to the PCD are CMACed, so we have to maintain the
		 * cryptographic initialisation vector up-to-date to check data
		 * integrity later.
		 *
		 * The only difference with CMACed data transmission is that the CMAC
		 * is not apended to the data send by the PCD to the PICC.
		 */

		append_mac = false;

		/* pass through */
	    case MDCM_MACED:
		switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		case AS_LEGACY:
		    if ((communication_settings & MAC_COMMAND) == 0) {
		    	break;
		    }

		    Log.d(TAG, "LEGACY");
		    
		    /* pass through */
		    edl = padded_data_length (nbytes - offset, key_block_size (C.MIFARE_DESFIRE (tag).getSessionKey())) + offset;
		    res = assert_crypto_buffer_size (tag, edl);

		    // Fill in the crypto buffer with data ...
		    C.memcpy (res, data, dataOffset, nbytes);
		    // ... and 0 padding
		    C.memset (res, nbytes, C.zero, edl - nbytes);

		    mifare_cypher_blocks_chained (tag, null, null, 0, res, offset, edl - offset, MifareCryptoDirection.MCD_SEND, MifareCryptoOperation.MCO_ENCYPHER);

		    C.memcpy (mac, 0, res, edl - 8, 4);

		    // Copy again provided data (was overwritten by mifare_cypher_blocks_chained)
		    C.memcpy (res, data, nbytes);

		    if ((communication_settings & MAC_COMMAND) == 0)
			break;
		    // Append MAC
		    mdl = maced_data_length (C.MIFARE_DESFIRE (tag).getSessionKey(), nbytes - offset) + offset;
		    res = assert_crypto_buffer_size (tag, mdl);

		    C.memcpy (res, nbytes, mac, 0, 4);

		    nbytes += 4;
		    break;
		case AS_NEW:
		    if ((communication_settings & CMAC_COMMAND) == 0) {
		    	break;
		    }
		    cmac (key, C.MIFARE_DESFIRE (tag).getInitializationVector(), res, nbytes, C.MIFARE_DESFIRE (tag).getCMAC());

		    if (append_mac) {
				mdl = maced_data_length (key, nbytes);
				res = assert_crypto_buffer_size (tag, mdl);
	
				C.memcpy (res, data, dataOffset, nbytes);
				C.memcpy (res, nbytes, C.MIFARE_DESFIRE (tag).getCMAC(), 0, CMAC_LENGTH);
				nbytes += CMAC_LENGTH;
		    } else {
		    	// already copied into data
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
		    edl = enciphered_data_length (tag, nbytes - offset, communication_settings) + offset;

		    res = assert_crypto_buffer_size (tag, edl);

		    // Fill in the crypto buffer with data ...
		    C.memcpy (res, data, dataOffset, nbytes);
		    if ((communication_settings & NO_CRC) == 0) {
			// ... CRC ...
			switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
			case AS_LEGACY:
			    ISO14443.iso14443a_crc_append (res, offset, nbytes - offset);
			    nbytes += 2;
			    break;
			case AS_NEW:
			    desfire_crc32_append (res, nbytes);
			    nbytes += 4;
			    break;
			}
		    }
		    // ... and padding
		    C.memset (res, nbytes, C.zero, edl - nbytes);

		    nbytes = edl;
		    
		    mifare_cypher_blocks_chained (tag, null, null, 0, res, offset, nbytes - offset, MifareCryptoDirection.MCD_SEND, (AuthenticationScheme.AS_NEW == C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) ? MifareCryptoOperation.MCO_ENCYPHER : MifareCryptoOperation.MCO_DECYPHER);
		    
		break;
	    default:
	    	C.log("Unknown communication settings");
	    	throw new IllegalArgumentException();
	    	/*
		*nbytes = -1;
		res = null;
		*/
	    }

	    return res;
	}

	public static byte[] mifare_cryto_postprocess_data (MifareTag tag, byte[] data, int nbytes, int communication_settings) throws Exception
	{
	    byte[] res = data;
	    int edl;
	    byte[] edata = null;
	    byte first_cmac_byte = 0;

	    MifareDESFireKey key = C.MIFARE_DESFIRE (tag).getSessionKey();

	    if (key == null)
	    	return data;

	    // Return directly if we just have a status code.
	    if (1 == nbytes)
		return res;

	    switch (communication_settings & MDCM_MASK) {
	    case MDCM_PLAIN:

		if (AuthenticationScheme.AS_LEGACY == C.MIFARE_DESFIRE (tag).getAuthenticationScheme())
		    break;

		/* pass through */
	    case MDCM_MACED:
		switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		case AS_LEGACY:
		    if ((communication_settings & MAC_VERIFY) != 0) {
			nbytes -= key_macing_length (key);

			edl = enciphered_data_length (tag, nbytes - 1, communication_settings);
			edata = C.malloc (edl);

			C.memcpy (edata, data, nbytes - 1);
			C.memset (edata, nbytes - 1, C.zero, edl - nbytes + 1);

			mifare_cypher_blocks_chained (tag, null, null, 0, edata, 0, edl, MifareCryptoDirection.MCD_SEND, MifareCryptoOperation.MCO_ENCYPHER);

			if (0 != C.memcmp (data, nbytes - 1, edata, edl - 8, 4)) {
				// not verified
			    C.hexdump (data, nbytes - 1, key_macing_length (key), "Expect ", 0);
			    C.hexdump (edata, edl - 8, key_macing_length (key), "Actual ", 0);
			    C.MIFARE_DESFIRE (tag).setLastPCDError(CRYPTO_ERROR);
			    nbytes = -1;
			    res = null;
			    throw new IllegalArgumentException("MACing not verified");
			}
		    }
		    break;
		case AS_NEW:
		    if ((communication_settings & CMAC_COMMAND) == 0)
			break;
		    if ((communication_settings & CMAC_VERIFY) != 0) {
			if (nbytes < 9) {
			    // XXX: Can't we avoid abort() -ing?
			    throw new IllegalArgumentException("No room for CMAC at " + nbytes);
			}
			first_cmac_byte = data[nbytes - 9];
			data[nbytes - 9] = data[nbytes-1];
		    }

		    int n = ((communication_settings & CMAC_VERIFY) != 0) ? 8 : 0;
		    cmac (key, C.MIFARE_DESFIRE (tag).getInitializationVector(), data, nbytes - n, C.MIFARE_DESFIRE (tag).getCMAC());

			//Log.d(TAG, "CMAC " + Utils.getHexString(MIFARE_DESFIRE (tag).getCMAC()));

		    if ((communication_settings & CMAC_VERIFY) != 0) {
				data[nbytes - 9] = first_cmac_byte;
				
				if (0 != C.memcmp (C.MIFARE_DESFIRE (tag).getCMAC(), 0, data, nbytes - 9, 8)) {
				    Log.d(TAG, "CMAC NOT verified :-(");
				    C.MIFARE_DESFIRE (tag).setLastPCDError(CRYPTO_ERROR);
				    nbytes = -1;
				    res = null;
				} else {
				    nbytes -= 8;
				}
		    }
		    
		    res = new byte[nbytes];
		    System.arraycopy(data, 0, res, 0, nbytes);
		    
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
		 * AuthenticationScheme.AS_LEGACY:
		 * ,-----------------+-------------------------------+--------+
		 * \     BLOCK n-1   |              BLOCK n          | STATUS |
		 * /  PAYLOAD | CRC0 | CRC1 | 0x80? | 0x000000000000 | 0x9100 |
		 * `-----------------+-------------------------------+--------+
		 *
		 *         <------------ DATA -----------.
		 * FRAME = PAYLOAD + CRC(PAYLOAD) + PADDING
		 *
		 * AuthenticationScheme.AS_NEW:
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
		
		mifare_cypher_blocks_chained (tag, null, null, 0, res, 0, nbytes, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_DECYPHER);

		/*
		Log.d(TAG, "After " + Utils.getHexString(res));
		Log.d(TAG, "After " + new String(res));
*/
		/*
		 * Look for the CRC and ensure it is followed by null padding.  We
		 * can't start by the end because the CRC is supposed to be 0 when
		 * verified, and accumulating 0's in it should not change it.
		 */
		switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		case AS_LEGACY:
		    crc_pos = nbytes - 8 - 1; // The CRC can be over two blocks
		    break;
		case AS_NEW:
		    /* Move status between payload and CRC */
		    res = assert_crypto_buffer_size (tag, nbytes + 1);
		    C.memcpy (res, data, nbytes);

		    crc_pos = nbytes - 16 - 3;
		    if (crc_pos < 0) {
			/* Single block */
		    	crc_pos = 0;
		    	//Log.d(TAG, "Single block");
		    } else {
		    	//Log.d(TAG, "Multiple blocks");
		    }
		    C.memmove (res, crc_pos + 1, res, crc_pos, nbytes - crc_pos);
		    res[crc_pos] = 0x00;
		    crc_pos++;
		    nbytes += 1;

		    //Log.d(TAG, "CRC " + Util.toHexString(res, crc_pos + 4, 4, true));
		    
		    break;
		}

		//Log.d(TAG, "CRC POS IS " + crc_pos + " / " + nbytes);
		//Log.d(TAG, "Look for CRC in " + Utils.getHexString(res, crc_pos, nbytes - crc_pos) + " in array " + Utils.getHexString(res, 0, nbytes));
		
		do {
		    byte[] crc16 = new byte[2];
		    byte[] crc = new byte[4];
		    switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
			    case AS_LEGACY: {
					end_crc_pos = crc_pos + 2;
					ISO14443.iso14443a_crc (res, 0, end_crc_pos, crc16, 0);
					crc = crc16;
					break;
			    }
			    case AS_NEW: {
					end_crc_pos = crc_pos + 4;
					desfire_crc32 (res, end_crc_pos, crc, 0);
					break;
			    }
		    }
		    if (crc[0] == 0 && crc[1] == 0 && crc[2] == 0 && crc[3] == 0) {
				verified = true;
				for (int n = end_crc_pos; n < nbytes - 1; n++) {
				    byte abyte = res[n];
				    if (!( (0x00 == abyte) || (((byte)0x80 == abyte) && (n == end_crc_pos)) )) {
				    	verified = false;
				    	
						//sLog.d(TAG, "Not verified still " + Utils.getHexString(res, end_crc_pos, nbytes - 1 - end_crc_pos) + " for " + Integer.toHexString(0xFF & abyte) + " at " + n + " vs " + end_crc_pos);
						
						break;
				    }
				}
		    }
		    if (verified) {
				nbytes = crc_pos;
				switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
				case AS_LEGACY:
				    data[nbytes++] = 0x00;
				    break;
				case AS_NEW:
				    /* The status byte was already before the CRC */
				    break;
				}
		    } else {
				switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
				case AS_LEGACY:
				    break;
				case AS_NEW:
				    x = ((byte[] )res)[crc_pos - 1];
				    ((byte[] )res)[crc_pos - 1] = ((byte[] )res)[crc_pos];
				    ((byte[] )res)[crc_pos] = x;
				    break;
				}
				crc_pos++;
		    }
		} while (!verified && (end_crc_pos < nbytes));

		/*
		Log.d(TAG, "Have " + nbytes + ": " +  Utils.getHexString(res, 0, nbytes));
		Log.d(TAG, "Have " + nbytes + ": " +  new String(res, 0, nbytes));
		*/
		
		nbytes--;
		
		byte[] result = new byte[nbytes];
		System.arraycopy(res, 0, result, 0, result.length);
		res = result;
		
		if (!verified) {
		    /* FIXME In some configurations, the file is transmitted PLAIN */
		    C.MIFARE_DESFIRE (tag).setLastPCDError(CRYPTO_ERROR);
		    nbytes = -1;
		    res = null;
		    
		    throw new IllegalArgumentException("CRC not verified in decyphered stream");
		}

		break;
	    default:
			throw new IllegalArgumentException("Unknown communication settings");

	    }
	    return res;
	}

	public static void mifare_cypher_single_block (MifareDESFireKey key, byte[] data, int dataOffset, byte[] ivect, int ivectOffset, MifareCryptoDirection direction, MifareCryptoOperation operation, int block_size) throws Exception
	{
		
	    //AES_KEY k;
	    byte[] ovect = new byte[MAX_CRYPTO_BLOCK_SIZE];

	    if (direction == MifareCryptoDirection.MCD_SEND) {
	    	xor (ivect, 0, data, dataOffset, block_size);
	    } else {
	    	C.memcpy (ovect, 0, data, dataOffset, block_size);
	    }

	    byte[] edata = new byte[MAX_CRYPTO_BLOCK_SIZE];

	    switch (key.getType()) {
	    case DES:
		switch (operation) {
		case MCO_ENCYPHER:
		    Crypt.DES_ecb_encrypt (data, dataOffset, edata, 0, key.getKs1(), DESType.DES_ENCRYPT);
		    break;
		case MCO_DECYPHER:
		    Crypt.DES_ecb_encrypt (data, dataOffset, edata, 0, key.getKs1(), DESType.DES_DECRYPT);
		    
		    //Log.d(TAG, "DES encypher: " + toHexString(data, dataOffset, key.getKs1().length, true) + " -> " + toHexString(edata));
		    break;
		}
		break;
	    case TDES:
		switch (operation) {
		case MCO_ENCYPHER:
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs1(), DESType.DES_ENCRYPT);
		    Crypt.DES_ecb_encrypt (edata, 0,  data, dataOffset, key.getKs2(), DESType.DES_DECRYPT);
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs1(), DESType.DES_ENCRYPT);
		    break;
		case MCO_DECYPHER:
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs1(), DESType.DES_DECRYPT);
		    Crypt.DES_ecb_encrypt (edata, dataOffset,  data, dataOffset, key.getKs2(), DESType.DES_ENCRYPT);
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs1(), DESType.DES_DECRYPT);
		    break;
		}
		break;
	    case TKTDES:
		switch (operation) {
		case MCO_ENCYPHER:
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs1(), DESType.DES_ENCRYPT);
		    Crypt.DES_ecb_encrypt (edata, 0,  data, dataOffset, key.getKs2(), DESType.DES_DECRYPT);
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs3(), DESType.DES_ENCRYPT);
		    break;
		case MCO_DECYPHER:
			//Log.d(TAG, "3K3DES decode");
			
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs3(), DESType.DES_DECRYPT);
			//Log.d(TAG, "Decyphered 1 " + toHexString(edata, 0, 8, true) + " with key " + toHexString(key.getKs3()));

		    Crypt.DES_ecb_encrypt (edata, 0,  data, dataOffset, key.getKs2(), DESType.DES_ENCRYPT);
			//Log.d(TAG, "Decyphered 2 " + toHexString(data, 0, 8, true) + " with key " + toHexString(key.getKs2()));
		    Crypt.DES_ecb_encrypt (data,  dataOffset, edata, 0, key.getKs1(), DESType.DES_DECRYPT);
		    
			//Log.d(TAG, "Decyphered 3 " + toHexString(edata, 0, 8, true) + " with key " + toHexString(key.getKs1()));

		    break;
		}
		break;
	    case AES:
		switch (operation) {
		case MCO_ENCYPHER: {
				Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		        cipher.init(Cipher.ENCRYPT_MODE, key.toKey()); 
		        
		        cipher.doFinal(data, dataOffset, edata.length, edata, 0);
			}	        
		    break;
		case MCO_DECYPHER: {
				Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		        cipher.init(Cipher.DECRYPT_MODE, key.toKey()); 

		        cipher.doFinal(data, dataOffset, edata.length, edata, 0);
			}			
		    break;
		}
		break;
	    }

    	System.arraycopy(edata, 0, data, dataOffset, block_size);
	    //memcpy (data, edata, block_size);

	    if (direction == MifareCryptoDirection.MCD_SEND) {
	    	
	    	System.arraycopy(data, dataOffset, ivect, 0, block_size);
	    } else {
	    	xor (ivect, 0, data, dataOffset, block_size);
	    	
	    	System.arraycopy(ovect, 0, ivect, 0, block_size);
	    }

	}

	/*
	 * This function performs all CBC cyphering / deciphering.
	 *
	 * The tag argument may be null, in which case both key and ivect shall be set.
	 * When using the tag session_key and ivect for processing data, these
	 * arguments should be set to null.
	 *
	 * Because the tag may contain additional data, one may need to call this
	 * function with tag, key and ivect defined.
	 */
	
	public static void mifare_cypher_blocks_chained (MifareTag tag, MifareDESFireKey key, byte[] ivect, byte[] data, int data_size, MifareCryptoDirection direction, MifareCryptoOperation operation) throws Exception
	{
		mifare_cypher_blocks_chained(tag, key, ivect, 0, data, 0, data_size, direction, operation);
	}

	public static void mifare_cypher_blocks_chained (MifareTag tag, MifareDESFireKey key, byte[] ivect, int ivectOffset, byte[] data, int dataOffset, int data_size, MifareCryptoDirection direction, MifareCryptoOperation operation) throws Exception
	{
	    int block_size;

	    if (tag != null) {
			if (key == null)
			    key = C.MIFARE_DESFIRE (tag).getSessionKey();
			if (ivect == null)
			    ivect = C.MIFARE_DESFIRE (tag).getInitializationVector();
	
			switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
			case AS_LEGACY:
			    C.memset (ivect, C.zero, MAX_CRYPTO_BLOCK_SIZE);
			    break;
			case AS_NEW:
			    break;
			}
	    }

	    if (key == null || ivect == null) {
	    	C.abort();
	    }
	    
	    block_size = key_block_size (key);

	    int offset = 0;
	    while (offset < data_size) {
	    	mifare_cypher_single_block (key, data, dataOffset + offset, ivect, ivectOffset, direction, operation, block_size);
	    	
	    	offset += block_size;
	    }
	}	
}
