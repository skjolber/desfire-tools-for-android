package com.github.skjolber.desfire.libfreefare;

import static com.github.skjolber.desfire.libfreefare.C.BUFFER_APPEND;
import static com.github.skjolber.desfire.libfreefare.C.BUFFER_APPEND_BYTES;
import static com.github.skjolber.desfire.libfreefare.C.memcmp;
import static com.github.skjolber.desfire.libfreefare.C.memcpy;
import static com.github.skjolber.desfire.libfreefare.C.memset;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireCrypto.mifare_cryto_preprocess_data;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireCrypto.mifare_cypher_blocks_chained;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireCrypto.rol;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

import android.util.Log;

public class MifareDesfire {
	
	private static final String TAG = MifareDesfire.class.getName();
	
	public static final int MAX_APPLICATION_COUNT = 28;
	public static final int MAX_FILE_COUNT = 32;

	public static final int CMAC_LENGTH = 8;

    public static final byte AUTHENTICATE_LEGACY = 0x0A;
    public static final byte AUTHENTICATE_ISO = 0x1A;
    public static final byte AUTHENTICATE_AES = (byte) 0xAA;


    /*
	static struct mifare_desfire_file_settings cached_file_settings[MAX_FILE_COUNT];
	static bool cached_file_settings_current[MAX_FILE_COUNT];
*/
	public static final int NOT_YET_AUTHENTICATED = 255;
	
	protected static DesfireFile[] cached_file_settings = new DesfireFile[MAX_FILE_COUNT];

	public static void ASSERT_AUTHENTICATED(MifareTag tag) {
		if (C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() == NOT_YET_AUTHENTICATED) {
		    throw new IllegalArgumentException();
		} 
	}
	
	/*
	 * XXX: cs < 0 is a CommunicationSettings detection error. Other values are
	 * user errors. We may need to distinguish them.
	 */
	public static void ASSERT_CS(int cs) {
		if (cs < 0) {
		    throw new IllegalArgumentException(Integer.toString(cs));
		} else if (cs == 0x02) { 
		    throw new IllegalArgumentException(Integer.toString(cs));
		} else if (cs > 0x03) { 
		     throw new IllegalArgumentException(Integer.toString(cs));
		}
	}

	public static void ASSERT_NOT_NULL(Object argument) {
		if (argument == null) {
		    throw new IllegalArgumentException();
		}
    }
	
	/*
	 * Convenience macros.
	 */

	/* Max APDU sizes to be ISO encapsulated by DESFIRE_TRANSCEIVE()
	   From MIFARE DESFire Functional specification:
	   MAX_CAPDU_SIZE:   "The length of the total wrapped DESFire
	                      command is not longer than 55 byte long."
	   MAX_RAPDU_SIZE:   1 status byte + 59 bytes
	 */
	public static final int MAX_CAPDU_SIZE = 55;
	public static final int MAX_RAPDU_SIZE = 60;

	/*
	 * Transmit the message msg to the NFC tag and receive the response res.  The
	 * response buffer's size is set according to the quantity of data received.
	 *
	 * The Mifare DESFire function return value which is returned at the end of the
	 * response is copied at the beginning to match the PICC documentation.
	 */
	/*
	#define DESFIRE_TRANSCEIVE(tag, msg, res) \
	    DESFIRE_TRANSCEIVE2 (tag, msg, __##msg##_n, res)
	/* Native DESFire APDUs will be wrapped in ISO7816-4 APDUs:
	   CAPDUs will be 5 bytes longer (CLA+P1+P2+Lc+Le)
	   RAPDUs will be 1 byte longer  (SW1 SW2 instead of 1 status byte)
	 */
	
	// SINGLE COMMAND
	public static final byte[] DESFIRE_TRANSCEIVE_SINGLE(MifareTag tag, ByteBuffer msg, byte expected) throws Exception {
		return DESFIRE_TRANSCEIVE_SINGLE(tag, msg, msg.position(), expected);
	}

	public static final byte[] DESFIRE_TRANSCEIVE_SINGLE(MifareTag tag, ByteBuffer msg, int length, byte expected) throws Exception {
		return tag.getIo().sendCommand(msg.get(0), msg.array(), 1, length - 1, expected);
	}

	public static final byte[] DESFIRE_TRANSCEIVE2_SINGLE(MifareTag tag, byte[] buffer, byte expected) throws Exception {
		return DESFIRE_TRANSCEIVE2_SINGLE(tag, buffer, buffer.length, expected);
	}

	public static final byte[] DESFIRE_TRANSCEIVE2_SINGLE(MifareTag tag, byte[] buffer, int length, byte expected) throws Exception {
		return tag.getIo().sendCommand(buffer[0], buffer, 1, buffer.length - 1, expected);
	}

	// COMMAND CHAIN
	public static final byte[] DESFIRE_TRANSCEIVE2(MifareTag tag, byte[] msg, int length) throws Exception {
		return tag.getIo().sendCommandChain(msg[0], msg, 1, length - 1);
	}

	public static final byte[] DESFIRE_TRANSCEIVE2(MifareTag tag, byte[] buffer) throws Exception {
		return DESFIRE_TRANSCEIVE2(tag, buffer, buffer.length);
	}
	
	/*
	public static final byte[] DESFIRE_TRANSCEIVE(MifareTag tag, ByteBuffer msg) throws Exception {
		return DESFIRE_TRANSCEIVE(tag, msg, msg.position());
	}
	*/

	public static final byte[] DESFIRE_TRANSCEIVE(MifareTag tag, ByteBuffer msg, int length) throws Exception {
		return tag.getIo().sendCommandChain(msg.get(0), msg.array(), 1, length - 1);
	}

	/*
	public static final void DESFIRE_TRANSCEIVE2(MifareTag tag, msg, msg_len, res) {
	    do { \
		static uint8_t __msg[MAX_CAPDU_SIZE + 5] = { 0x90, 0x00, 0x00, 0x00, 0x00, /* ..., */ /* 0x00 }; 
		/*                                       CLA   INS   P1    P2    Lc    PAYLOAD    LE
		/*
		static uint8_t __res[MAX_RAPDU_SIZE + 1]; \
		size_t __len = 5; \
		errno = 0; \
		if (!msg) return errno = EINVAL, -1; \
		__msg[1] = msg[0]; \
		if (msg_len > 1) { \
		    __len += msg_len; \
		    __msg[4] = msg_len - 1; \
		    memcpy (__msg + 5, msg + 1, msg_len - 1); \
		} \
		// reply length  \
		__msg[__len-1] = 0x00; \
		MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK; \
		MIFARE_DESFIRE (tag)->last_pcd_error = OPERATION_OK; \
		DEBUG_XFER (__msg, __len, "===> "); \
		int _res; \
		if ((_res = nfc_initiator_transceive_bytes (tag->device, __msg, __len, __res, __##res##_size + 1, 0)) < 0) { \
		    return errno = EIO, -1; \
		} \
		__##res##_n = _res; \
		DEBUG_XFER (__res, __##res##_n, "<=== "); \
		res[__##res##_n-2] = __res[__##res##_n-1]; \
		__##res##_n--; \
		if ((1 == __##res##_n) && (ADDITIONAL_FRAME != res[__##res##_n-1]) && (OPERATION_OK != res[__##res##_n-1])) { \
		    return MIFARE_DESFIRE (tag)->last_picc_error = res[0], -1; \
		} \
		memcpy (res, __res, __##res##_n - 1); \
	    } while (0)

	
	/*
	 * Miscellaneous low-level memory manipulation functions.
	 */

	//static int32_t	 le24toh (uint8_t data[3]);

	public static int madame_soleil_get_read_communication_settings (MifareTag tag, byte file_no) throws Exception
	{
		
	    DesfireFile settings = mifare_desfire_get_file_settings (tag, file_no);
	    if(settings == null) {
	    	throw new IllegalArgumentException();
	    }

	    if (C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() == settings.getReadAccessKey() || C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() == settings.getReadWriteAccessKey()) {
	    	return settings.getCommunicationSettings().getValue();
	    } 
		return 0;
	}
	
	public static int madame_soleil_get_write_communication_settings (MifareTag tag, byte file_no) throws Exception {
	    DesfireFile settings = mifare_desfire_get_file_settings (tag, file_no);

	    if (C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() == settings.getWriteAccessKey() || C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() == settings.getReadWriteAccessKey()) {
	    	return settings.getCommunicationSettings().getValue();
	    } 
	    Log.w(TAG, "No write access file " + file_no + " (" +  C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() + " != " + settings.getWriteAccessKey() + " / " + settings.getReadWriteAccessKey() + ")");
		return 0;
	}

	public static int le24toh (byte[] data) {
	    return (data[2] << 16) | (data[1] << 8) | data[0];
	}

	/*
	 * Memory management functions.
	 */

	/*
	 * Allocates and initialize a MIFARE DESFire tag.
	 */
	public static MifareTag mifare_desfire_tag_new () {
	    MifareTag tag = new MifareTag();
        C.MIFARE_DESFIRE (tag).setLastPICCError(DefaultIsoDepAdapter.OPERATION_OK);
        C.MIFARE_DESFIRE (tag).setLastPCDError(DefaultIsoDepAdapter.OPERATION_OK);
        C.MIFARE_DESFIRE (tag).setSessionKey(null);
        C.MIFARE_DESFIRE (tag).setCryptoBuffer(null);
	    return tag;
	}

	/*
	 * MIFARE card communication preparation functions
	 *
	 * The following functions send NFC commands to the initiator to prepare
	 * communication with a MIFARE card, and perform required cleannups after using
	 * the target.
	 */

	/*
	 * Establish connection to the provided tag.
	 */
	public static int mifare_desfire_connect (MifareTag tag)
	{
	    ASSERT_INACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    /*
	    nfc_target pnti;
	    nfc_modulation modulation = {
		.nmt = NMT_ISO14443A,
		.nbr = NBR_106
	    };
	    if (nfc_initiator_select_passive_target (tag->device, modulation, tag->info.abtUid, tag->info.szUidLen, &pnti) >= 0) {
	    */
		tag.setActive(1);
		
		C.MIFARE_DESFIRE (tag).setSessionKey(null);
		C.MIFARE_DESFIRE (tag).setLastPICCError(DefaultIsoDepAdapter.OPERATION_OK);
		C.MIFARE_DESFIRE (tag).setLastPCDError(DefaultIsoDepAdapter.OPERATION_OK);
		C.MIFARE_DESFIRE (tag).setAuthenticatedKeyNumber(NOT_YET_AUTHENTICATED);
		C.MIFARE_DESFIRE (tag).setSelectedApplication(0);
		
	    return 0;
	}

	private static void ASSERT_MIFARE_DESFIRE(MifareTag tag) {
		
	}

	/*
	 * Terminate connection with the provided tag.
	 */
	public static int mifare_desfire_disconnect (MifareTag tag)
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    C.MIFARE_DESFIRE(tag).setSessionKey(null);

	    tag.setActive(0);
	    
	    return 0;
	}

	public static int authenticate (MifareTag tag, byte cmd, byte key_no, MifareDESFireKey key) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    C.memset (C.MIFARE_DESFIRE (tag).getInitializationVector(), C.zero, MifareDesfireCrypto.MAX_CRYPTO_BLOCK_SIZE);

	    C.MIFARE_DESFIRE (tag).setAuthenticatedKeyNumber(NOT_YET_AUTHENTICATED);
	    //free (MIFARE_DESFIRE (tag)->session_key);
	    C.MIFARE_DESFIRE (tag).setSessionKey(null);

	    C.MIFARE_DESFIRE (tag).setAuthenticationScheme((AUTHENTICATE_LEGACY == cmd) ? AuthenticationScheme.AS_LEGACY : AuthenticationScheme.AS_NEW);

	    ByteBuffer cmd1 = C.BUFFER_INIT (2);
	    
	    C.BUFFER_APPEND (cmd1, cmd);
	    C.BUFFER_APPEND (cmd1, key_no);
	    
	    byte[] res = DESFIRE_TRANSCEIVE_SINGLE(tag, cmd1, DefaultIsoDepAdapter.ADDITIONAL_FRAME);

	    int key_length = res.length;

	    byte[] PICC_E_RndB = new byte[key_length];
	    C.memcpy (PICC_E_RndB, res, key_length);

	    byte[] PICC_RndB = new byte[16];
	    C.memcpy (PICC_RndB, PICC_E_RndB, key_length);
	    
	    MifareDesfireCrypto.mifare_cypher_blocks_chained (tag, key, C.MIFARE_DESFIRE (tag).getInitializationVector(), 0, PICC_RndB, 0, key_length, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_DECYPHER);

	    byte[] PCD_RndA = new byte[key_length];
	    Crypt.RAND_bytes (PCD_RndA, key_length);

	    byte[] PCD_r_RndB = new byte[key_length];
	    C.memcpy (PCD_r_RndB, PICC_RndB, key_length);
	    MifareDesfireCrypto.rol (PCD_r_RndB, key_length);

	    byte[] token = new byte[2 * key_length];
	    C.memcpy (token, PCD_RndA, key_length);
	    C.memcpy (token, key_length, PCD_r_RndB, 0, key_length);

	    MifareDesfireCrypto.mifare_cypher_blocks_chained (tag, key, C.MIFARE_DESFIRE (tag).getInitializationVector(), token, 2 * key_length, MifareCryptoDirection.MCD_SEND, (AUTHENTICATE_LEGACY == cmd) ? MifareCryptoOperation.MCO_DECYPHER : MifareCryptoOperation.MCO_ENCYPHER);

	    ByteBuffer cmd2 = C.BUFFER_INIT (1 + 2*key_length);

	    C.BUFFER_APPEND (cmd2, (byte)0xAF);
	    C.BUFFER_APPEND_BYTES (cmd2, token, 2*key_length);

	    res = DESFIRE_TRANSCEIVE_SINGLE (tag, cmd2, 1 + 2*key_length, DefaultIsoDepAdapter.OPERATION_OK);

	    byte[] PICC_E_RndA_s = new byte[16];
	    C.memcpy (PICC_E_RndA_s, res, key_length);

	    byte[] PICC_RndA_s = new byte[16];
	    C.memcpy (PICC_RndA_s, PICC_E_RndA_s, key_length);
	    MifareDesfireCrypto.mifare_cypher_blocks_chained (tag, key, C.MIFARE_DESFIRE (tag).getInitializationVector(), PICC_RndA_s, key_length, MifareCryptoDirection.MCD_RECEIVE, MifareCryptoOperation.MCO_DECYPHER);

	    byte[] PCD_RndA_s = new byte[key_length];
	    C.memcpy (PCD_RndA_s, PCD_RndA, key_length);
	    MifareDesfireCrypto.rol (PCD_RndA_s, key_length);


		//hexdump (PCD_RndA_s, key_length, "PCD  ");
		//hexdump (PICC_RndA_s, key_length, "PICC ");

	    if (0 != C.memcmp (PCD_RndA_s, PICC_RndA_s, key_length)) {
	    	Log.d(TAG, "Expected recieve token " + Utils.getHexString(PICC_E_RndA_s) + " equal to sent " + Utils.getHexString(PCD_RndA_s));
	    	return -1;
	    }

	    C.MIFARE_DESFIRE (tag).setAuthenticatedKeyNumber(key_no);
	    C.MIFARE_DESFIRE (tag).setSessionKey(MifareDesfireKey.mifare_desfire_session_key_new (PCD_RndA, PICC_RndB, key));
	    C.memset (C.MIFARE_DESFIRE (tag).getInitializationVector(), C.zero, MifareDesfireCrypto.MAX_CRYPTO_BLOCK_SIZE);

	    switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
	    case AS_LEGACY:
		break;
	    case AS_NEW:
		MifareDesfireCrypto.cmac_generate_subkeys (C.MIFARE_DESFIRE (tag).getSessionKey());
		break;
	    }

	    return 0;
	}

	private static void ASSERT_ACTIVE(MifareTag tag) {
		if(tag.getActive() == 0) {
			throw new IllegalArgumentException("Tag not active");
		}
	}

	private static void ASSERT_INACTIVE(MifareTag tag) {
		if(tag.getActive() == 1) {
			throw new IllegalArgumentException("Tag active");
		}
	}

	public static int mifare_desfire_authenticate (MifareTag tag, byte key_no, MifareDESFireKey key) throws Exception
	{
	    switch (key.getType()) {
	    case DES:
	    case TDES:
		return authenticate (tag, AUTHENTICATE_LEGACY, key_no, key);
	    case TKTDES:
		return authenticate (tag, AUTHENTICATE_ISO, key_no, key);
	    case AES:
		return authenticate (tag, AUTHENTICATE_AES, key_no, key);
	    }

	    return -1; /* NOTREACHED */
	}

	public static int
	mifare_desfire_authenticate_iso (MifareTag tag, byte key_no, MifareDESFireKey key) throws Exception
	{
	    return authenticate (tag, AUTHENTICATE_ISO, key_no, key);
	}

	public static int
	mifare_desfire_authenticate_aes (MifareTag tag, byte key_no, MifareDESFireKey key) throws Exception
	{
	    return authenticate (tag, AUTHENTICATE_AES, key_no, key);
	}

	public static int
	mifare_desfire_change_key_settings (MifareTag tag, byte settings) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_AUTHENTICATED (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (9);
	    
	    //BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0x54);
	    C.BUFFER_APPEND (cmd, settings);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, 2, 1, MifareDesfireCrypto.MDCM_ENCIPHERED | MifareDesfireCrypto.ENC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, buffer.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY | MifareDesfireCrypto.MAC_COMMAND | MifareDesfireCrypto.MAC_VERIFY);

	    if (p == null) {
			return -1;
	    }

	    return 0;
	}
	
	public static DesfireApplicationKeySettings mifare_desfire_get_key_settings (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1);
	    C.BUFFER_APPEND (cmd, 0x45);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, 1, 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[3 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data(tag, buffer, buffer.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if(p == null) {
	    	throw new IllegalArgumentException();
	    }
	    
	    byte[] settings = new byte[2];
	    System.arraycopy(p, 0, settings, 0, settings.length);

	    return new DesfireApplicationKeySettings(settings);
	}
	
	public static int
	mifare_desfire_change_key (MifareTag tag, byte key_no, MifareDESFireKey new_key, MifareDESFireKey old_key) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_AUTHENTICATED (tag);

	    byte[] cmd = new byte[52];
	    
	    //ByteBuffer cmd = BUFFER_INIT (52);
	    
	    // BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    key_no &= 0x0F;
	    
	     // Because new crypto methods can be setup only at application creation,
	     // changing the card master key to one of them require a key_no tweak.
	     //
	    if (0x000000 == C.MIFARE_DESFIRE (tag).getSelectedApplication()) {
		switch (new_key.getType()) {
		case DES:
		case TDES:
		    break;
		case TKTDES:
		    key_no |= 0x40;
		    break;
		case AES:
		    key_no |= 0x80;
		    break;
		}
	    }

	    int count = 0;
	    
	    cmd[count++] = (byte) 0xC4;
	    cmd[count++] = key_no;
	    
	    int new_key_length;
	    switch (new_key.getType()) {
	    case DES:
	    case TDES:
	    case AES:
		new_key_length = 16;
		break;
	    case TKTDES:
		new_key_length = 24;
		break;
		default : {
			throw new IllegalArgumentException();
		}
	    }

	    System.arraycopy(new_key.getData(), 0, cmd, count, new_key_length);
	    count += new_key_length;
	    
	    //cmd.put(new_key.getData(), 0, new_key_length)
	    //memcpy (cmd, 2, new_key.getData(), new_key_length);

	    if ((C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() & 0x0f) != (key_no & 0x0f)) {
			if (old_key != null) {
			    for (int n = 0; n < new_key_length; n++) {
			    	cmd[count + n] ^= old_key.getData()[n];
			    }
			}
	    }

	    // 2 + new_key_length + new_key_length
	    //__cmd_n += new_key_length;

	    if (new_key.getType() == DesfireKeyType.AES) {
	    	cmd[count++] = new_key.getAESVersion();
	    }
	    
	    if ((C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo() & 0x0f) != (key_no & 0x0f)) {
		switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		case AS_LEGACY:
		    ISO14443.iso14443a_crc_append (cmd, 2, count - 2);
		    count += 2;
		    ISO14443.iso14443a_crc (new_key.getData(), 0, new_key_length, cmd, count);
		    count += 2;
		    break;
		case AS_NEW:
		    MifareDesfireCrypto.desfire_crc32_append (cmd, count);
		    count += 4;

		    MifareDesfireCrypto.desfire_crc32 (new_key.getData(), new_key_length, cmd, count);
		    count += 4;
		    break;
		}
	    } else {
		switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
		case AS_LEGACY:
		    ISO14443.iso14443a_crc_append (cmd, 2, count - 2);
		    count += 2;
		    break;
		case AS_NEW:
		    MifareDesfireCrypto.desfire_crc32_append (cmd, count);
		    count += 4;
		    break;
		}
	    }

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, 0, count, 2, MifareDesfireCrypto.MDCM_ENCIPHERED | MifareDesfireCrypto.ENC_COMMAND | MifareDesfireCrypto.NO_CRC);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);
	    
	    // empty response really
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	     // If we changed the current authenticated key, we are not authenticated
	     // anymore.
	    if (key_no == C.MIFARE_DESFIRE (tag).getAuthenticatedKeyNo()) {
	    	C.MIFARE_DESFIRE (tag).setSessionKey(null);
	    }

	    return 0;
	}

	 // Retrieve version information for a given key.
	
	public static byte mifare_desfire_get_key_version (MifareTag tag, byte key_no) throws Exception {
		byte[] version = new byte[1];
		
		int result = mifare_desfire_get_key_version(tag, key_no, version);
		
		if(result == 0) {
			return version[0];
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	
	public static int mifare_desfire_get_key_version (MifareTag tag, byte key_no, byte[] version) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd1 = C.BUFFER_INIT (2);
	    
	    C.BUFFER_APPEND (cmd1, 0x64);
	    C.BUFFER_APPEND (cmd1, key_no);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd1, cmd1.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[2 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY | MifareDesfireCrypto.MAC_VERIFY);

	    if (p == null) {
			return -1;
	    }

	    version[0] = p[0];

	    return 0;
	}

	public static int
	create_application (MifareTag tag, DesfireApplicationId aid, byte settings1, byte settings2, int want_iso_application, int want_iso_file_identifiers, /* uint16 */ int iso_file_id, byte[] iso_file_name, int iso_file_name_len) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (22);

	    //BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    if (want_iso_file_identifiers != 0)
		settings2 |= 0x20;

	    C.BUFFER_APPEND (cmd, 0xCA);
	    C.BUFFER_APPEND_LE (cmd, aid.getId(), aid.getId().length, aid.getId().length);
	    C.BUFFER_APPEND (cmd, settings1);
	    C.BUFFER_APPEND (cmd, settings2);

	    if (want_iso_application != 0) {
	    	byte[] bytes = new byte[] {
    			(byte) ((iso_file_id >>> 8) & 0xFF),
	    		(byte) ((iso_file_id >>> 0) & 0xFF)
	    	};
	    	
	    	C.BUFFER_APPEND_LE (cmd, bytes, 2, 2);
	    }
	    if (iso_file_name_len != 0) {
	    	C.BUFFER_APPEND_BYTES (cmd, iso_file_name, iso_file_name_len);
	    }
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY | MifareDesfireCrypto.MAC_VERIFY);

	    if (p == null) {
			return -1;
	    }

	    return 0;
	}
	
	public static int
	mifare_desfire_create_application (MifareTag tag, DesfireApplicationId aid, byte settings, byte key_no) throws Exception
	{
	    return create_application (tag, aid, settings, key_no, 0, 0, 0, null, 0);
	}

	public static int
	mifare_desfire_create_application_iso (MifareTag tag, DesfireApplicationId aid, byte settings, byte key_no, int want_iso_file_identifiers, short iso_file_id, byte[] iso_file_name, int iso_file_name_len) throws Exception
	{
	    return create_application (tag, aid, settings, key_no, 1, want_iso_file_identifiers, iso_file_id, iso_file_name, iso_file_name_len);
	}

	public static int
	mifare_desfire_create_application_3k3des (MifareTag tag, DesfireApplicationId aid, byte settings, byte key_no) throws Exception
	{
	    return create_application (tag, aid, settings, (byte)(MifareDesfireCrypto.APPLICATION_CRYPTO_3K3DES | key_no), 0, 0, 0, null, 0);
	}

	public static int
	mifare_desfire_create_application_3k3des_iso (MifareTag tag, DesfireApplicationId aid, byte settings, byte key_no, int want_iso_file_identifiers, short iso_file_id, byte[] iso_file_name, int iso_file_name_len) throws Exception
	{
	    return create_application (tag, aid, settings, (byte)(MifareDesfireCrypto.APPLICATION_CRYPTO_3K3DES | key_no), 1, want_iso_file_identifiers, iso_file_id, iso_file_name, iso_file_name_len);
	}
	
	public static int
	mifare_desfire_create_application_aes (MifareTag tag, DesfireApplicationId aid, byte settings, byte key_no) throws Exception
	{
	    return create_application (tag, aid, settings, (byte) (MifareDesfireCrypto.APPLICATION_CRYPTO_AES | key_no), 0, 0, 0, null, 0);
	}

	public static int
	mifare_desfire_create_application_aes_iso (MifareTag tag, DesfireApplicationId aid, byte settings, byte key_no, int want_iso_file_identifiers, short iso_file_id, byte[] iso_file_name, int iso_file_name_len) throws Exception
	{
	    return create_application (tag, aid, settings, (byte)(MifareDesfireCrypto.APPLICATION_CRYPTO_AES | key_no), 1, want_iso_file_identifiers, iso_file_id, iso_file_name, iso_file_name_len);
	}
	
	public static int
	mifare_desfire_delete_application (MifareTag tag, DesfireApplicationId aid) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (4 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xDA);
	    C.BUFFER_APPEND_LE (cmd, aid.getId(), aid.getId().length, aid.getId().length);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);
	    
	    // If we have deleted the current application, we are not authenticated
	    // anymore.
	    
	    if (C.MIFARE_DESFIRE (tag).getSelectedApplication() == aid.getIdInt()) {
			C.MIFARE_DESFIRE (tag).setSessionKey(null);
			C.MIFARE_DESFIRE (tag).setSelectedApplication(0x000000);
	    }

	    return 0;
	}
	
	public static List<DesfireApplicationId> mifare_desfire_get_application_ids (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1);
	    
	    C.BUFFER_APPEND (cmd, 0x6A);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    if (p == null) {
			return null;
	    }

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[res.length + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY | MifareDesfireCrypto.MAC_VERIFY);

	    if (p == null) {
			return null;
	    }

	    int count = (res.length)/3; // discard last byte
	    
	    List<DesfireApplicationId> aids = new ArrayList<DesfireApplicationId>();
        for (int app = 0; app < count * 3; app += 3) {
            byte[] appId = new byte[]{buffer[app + 2], buffer[app + 1], buffer[app]};

            aids.add(new DesfireApplicationId(appId));
        }

	    return aids;
	}

	public static List<MifareDESFireDF>
	mifare_desfire_get_df_names (MifareTag tag, int count) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1);
	    
	    C.BUFFER_APPEND (cmd, 0x6D);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);
	    
	    if (p == null) {
			return null;
	    }

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[res.length + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    List<MifareDESFireDF> dfs = new ArrayList<MifareDESFireDF>();

	    // TODO
	    /*
        for (int app = 0; app < count * 3; app += 3) {
            aids.add(new MifareDESFireDF());
        }
        */

	    return dfs;
	
	    /*
	    *count = 0;
	    *dfs = NULL;

	    BUFFER_INIT (cmd, 1);
	    BUFFER_INIT (res, 22 + CMAC_LENGTH);

	    BUFFER_APPEND (cmd, 0x6D);

	    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);
		
	    do {
		DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

		if (__res_n > 1) {
		    MifareDESFireDF *new_dfs;
		    if ((new_dfs = realloc (*dfs, sizeof (*new_dfs) * (*count + 1)))) {
			new_dfs[*count].aid = le24toh (res);
			new_dfs[*count].fid = le16toh (*(uint16_t *)(res + 3));
			memcpy (new_dfs[*count].df_name, res + 5, __res_n - 6);
			new_dfs[*count].df_name_len = __res_n - 6;
			*dfs = new_dfs;
			*count += 1;
		    }
		}

		p[0] = 0XAF;
	    } while (res[__res_n-1] == 0xAF);

	    return 0;
	    */
	}
	
	/*
	 * Select the application specified by aid for further operation.  If aid is
	 * NULL, the master application is selected (equivalent to aid = 0x00000).
	 */
	public static int mifare_desfire_select_application (MifareTag tag, DesfireApplicationId aid) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);


        DesfireApplicationId null_aid = new DesfireApplicationId(new byte[]{ 0x00, 0x00, 0x00 });

	    if (aid == null) {
	    	aid = null_aid;
	    }

	    ByteBuffer cmd = C.BUFFER_INIT (4);

	    C.BUFFER_APPEND (cmd, 0x5A);
	    C.BUFFER_APPEND_LE (cmd, aid.getId(), 3, 3);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p, p.length);

	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    if (p == null)
		return -1;

	    for (int n = 0; n < MAX_FILE_COUNT; n++) {
	    	cached_file_settings[n] = null;
	    }
	    
	    //free (MIFARE_DESFIRE (tag)->session_key);
	    C.MIFARE_DESFIRE (tag).setSessionKey(null);;

	    C.MIFARE_DESFIRE (tag).setSelectedApplication(aid.getIdInt());

	    return 0;
	}

	public static int
	mifare_desfire_format_picc (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_AUTHENTICATED (tag);
	    
	    ByteBuffer cmd = C.BUFFER_INIT (1);

	    //BUFFER_INIT (cmd, 1 + CMAC_LENGTH);
	    //BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xFC);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p, p.length);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, 1 + CMAC_LENGTH, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }

	    C.MIFARE_DESFIRE (tag).setSessionKey(null);
	    C.MIFARE_DESFIRE (tag).setSelectedApplication(0x000000);

	    return 0;
	}

	/*
	 * Retrieve version information form the PICC.
	 */
	
	public static VersionInfo
	mifare_desfire_get_version (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1);
	    //ByteBuffer res = BUFFER_INIT (15 + CMAC_LENGTH); // 8, 8, then 15 byte results

	    byte[] buffer = new byte[28 + CMAC_LENGTH + 1];

	    C.BUFFER_APPEND (cmd, 0x60);
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    if (p == null) {
			return null;
	    }	    
	    
	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);
	    C.memcpy (buffer, res, 7 + 7 + 14);

	    /*
	    memcpy (buffer, res, 7);

	    p[0] = (byte) 0xAF;
	    res = DESFIRE_TRANSCEIVE2 (tag, p);
	    //memcpy (&(version_info->software), res, 7);
	    memcpy (buffer, 7, res, 7);

	    DESFIRE_TRANSCEIVE2 (tag, p);
	    //memcpy (&(version_info->uid), res, 14);
	    memcpy (buffer, 14, res, res.length);
		*/
	    
	    VersionInfo version_info = new VersionInfo();
	    version_info.read(buffer);
	    
	    int sn = 28 + CMAC_LENGTH + 1;
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, sn, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
			return null;
	    }
	    
	    return version_info;
	}
/*
	int
	mifare_desfire_free_mem (MifareTag tag, int *size)
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ASSERT_NOT_NULL (size);

	    BUFFER_INIT (cmd, 1);
	    BUFFER_INIT (res, 4 + CMAC_LENGTH);

	    BUFFER_APPEND (cmd, 0x6E);

	    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

	    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	    ssize_t sn = __res_n;
	    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

	    if (!p)
		return errno = EINVAL, -1;

	    *size = p[0] | (p[1] << 8) | (p[2] << 16);

	    return 0;
	}
*/
	public static int
	mifare_desfire_set_configuration (MifareTag tag, boolean disable_format, boolean enable_random_uid) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (10);
	    // BUFFER_INIT (res, 1 + CMAC_LENGTH);
	    
	    C.BUFFER_APPEND (cmd, 0x5C);
	    C.BUFFER_APPEND (cmd, 0x00);
	    C.BUFFER_APPEND (cmd, (enable_random_uid ? 0x02 : 0x00) | (disable_format ? 0x01 : 0x00));

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 2, MifareDesfireCrypto.MDCM_ENCIPHERED | MifareDesfireCrypto.ENC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[CMAC_LENGTH + 1];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	    return 0;
	}

	/*
	int
	mifare_desfire_set_default_key (MifareTag tag, MifareDESFireKey key)
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    BUFFER_INIT (cmd, 34);
	    BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    BUFFER_APPEND (cmd, 0x5C);
	    BUFFER_APPEND (cmd, 0x01);
	    size_t key_data_length;
	    switch (key->type) {
	    case DES:
	    case TDES:
	    case AES:
		key_data_length = 16;
		break;
	    case TKTDES:
		key_data_length = 24;
		break;
	    }
	    BUFFER_APPEND_BYTES (cmd, key->data, key_data_length);
	    while (__cmd_n < 26)
		BUFFER_APPEND (cmd, 0x00);
	    BUFFER_APPEND (cmd, mifare_desfire_key_get_version (key));

	    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, MDCM_ENCIPHERED | ENC_COMMAND);

	    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	    ssize_t sn = __res_n;
	    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

	    if (!p)
		return errno = EINVAL, -1;

	    return 0;
	}

	int
	mifare_desfire_set_ats (MifareTag tag, uint8_t *ats)
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    BUFFER_INIT (cmd, 34);
	    BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    BUFFER_APPEND (cmd, 0x5C);
	    BUFFER_APPEND (cmd, 0x02);
	    BUFFER_APPEND_BYTES (cmd, ats, *ats);
	    switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	    case AS_LEGACY:
		iso14443a_crc_append (cmd + 2 , __cmd_n - 2);
		__cmd_n += 2;
		break;
	    case AS_NEW:
		desfire_crc32_append (cmd, __cmd_n);
		__cmd_n += 4;
		break;
	    }
	    BUFFER_APPEND (cmd, 0x80);

	    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, MDCM_ENCIPHERED | NO_CRC | ENC_COMMAND);

	    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	    ssize_t sn = __res_n;
	    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

	    if (!p)
		return errno = EINVAL, -1;

	    return 0;
	}

	int
	mifare_desfire_get_card_uid (MifareTag tag, char **uid)
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ASSERT_NOT_NULL (uid);

	    BUFFER_INIT (cmd, 1);
	    BUFFER_INIT (res, 17 + CMAC_LENGTH);

	    BUFFER_APPEND (cmd, 0x51);

	    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 1, MDCM_PLAIN | CMAC_COMMAND);

	    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	    ssize_t sn = __res_n;
	    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_ENCIPHERED);

	    if (!p)
		return errno = EINVAL, -1;

	    if (!(*uid = malloc (2*7+1))) {
		return -1;
	    }

	    sprintf (*uid, "%02x%02x%02x%02x%02x%02x%02x",
		     p[0], p[1], p[2], p[3],
		     p[4], p[5], p[6]);

	    return 0;
	}
	

	// Application level commands

*/
	public static byte[]
	mifare_desfire_get_file_ids (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1);
	    
	    /*
	    BUFFER_INIT (res, 16 + CMAC_LENGTH);
	    */
	    
	    C.BUFFER_APPEND (cmd, 0x6F);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[16 + 1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
			return null;
	    }

	    int count = res.length;

	    byte[] files = new byte[count];
	    
	    C.memcpy (files, res, count);

	    return files;
	}

	public static int[]
	mifare_desfire_get_iso_file_ids (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1);
	    
	    /*
	    BUFFER_INIT (res, 16 + CMAC_LENGTH);
	    */
	    
	    C.BUFFER_APPEND (cmd, 0x61);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[2*27 + 1];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);
	    
	    int count = res.length - CMAC_LENGTH;
	    int[] files = new int[count / 2];
	    for (int i = 0; i < count; i++) {
	    	files[i] =  (p[2 * i+1] << 8) + (p[2 * i] << 0);
	    }
	    
	    return files;
	}

	public static DesfireFile
	mifare_desfire_get_file_settings (MifareTag tag, byte file_no) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    if (cached_file_settings[file_no] != null) {
			return cached_file_settings[file_no];
	    }
	    
	    ByteBuffer cmd = C.BUFFER_INIT (2);

	    // BUFFER_INIT (res, 18 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xF5);
	    C.BUFFER_APPEND (cmd, file_no);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[18 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
			return null;
	    }	    
	    
	    DesfireFile settings = DesfireFile.newInstance(file_no, p);

	    cached_file_settings[file_no] = settings;

	    return settings;
	}
/*
	int
	mifare_desfire_change_file_settings (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights)
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    struct mifare_desfire_file_settings settings;
	    int res = mifare_desfire_get_file_settings (tag, file_no, &settings);
	    if (res < 0)
		return res;

	    cached_file_settings_current[file_no] = false;

	    if (MDAR_CHANGE_AR(settings.access_rights) == MDAR_FREE) {
		BUFFER_INIT (cmd, 5 + CMAC_LENGTH);
		BUFFER_INIT (res, 1 + CMAC_LENGTH);

		BUFFER_APPEND (cmd, 0x5F);
		BUFFER_APPEND (cmd, file_no);
		BUFFER_APPEND (cmd, communication_settings);
		BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));

		uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);
		DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

		ssize_t sn = __res_n;
		p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

		if (!p)
		    return errno = EINVAL, -1;
	    } else {
		BUFFER_INIT (cmd, 10);
		BUFFER_INIT (res, 1 + CMAC_LENGTH);

		BUFFER_APPEND (cmd, 0x5F);
		BUFFER_APPEND (cmd, file_no);
		BUFFER_APPEND (cmd, communication_settings);
		BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));

		uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, MDCM_ENCIPHERED | ENC_COMMAND);

		DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

		ssize_t sn = __res_n;
		p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

		if (!p)
		    return errno = EINVAL, -1;
	    }

	    return 0;
	}
*/
	public static int
	create_file1 (MifareTag tag, byte command, byte file_no, int has_iso_file_id, /* uint16_t */ int iso_file_id,  byte communication_settings, /* uint16 */ int access_rights, /* int  */ int file_size) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (10);

	    // BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, command);
	    C.BUFFER_APPEND (cmd, file_no);
	    if (has_iso_file_id != 0) {
	    	C.BUFFER_APPEND_LE (cmd, C.getBytes2(iso_file_id), 2, 2);
	    }
	    C.BUFFER_APPEND (cmd, communication_settings);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes2(access_rights), 2, 2);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes3(file_size), 3, 3);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);
	    
	    // 90 CD 00 00 04 0F 03 54 12 00
	    // 90 cd 00 00 07 0f 03 54 12 64 00 00 00
	    // 90 CD 00 00 07 0F 03 54 12 64 00 00 00 (13)
	    
	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
			return -1;
	    }	    

	    cached_file_settings[file_no] = null;

	    return 0;
	}

	public static int
	mifare_desfire_create_std_data_file (MifareTag tag, byte file_no, byte communication_settings, int access_rights, int file_size) throws Exception
	{
	    return create_file1 (tag, (byte) 0xCD, file_no, 0, 0x0000, communication_settings, access_rights, file_size);
	}

	public static int
	mifare_desfire_create_std_data_file_iso (MifareTag tag, byte file_no, byte communication_settings, int access_rights, int file_size, int iso_file_id) throws Exception
	{
	    return create_file1 (tag, (byte) 0xCD, file_no, 1, iso_file_id, communication_settings, access_rights, file_size);
	}

	public static int
	mifare_desfire_create_backup_data_file  (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int file_size) throws Exception
	{
	    return create_file1 (tag, (byte)0xCB, file_no, 0, 0x0000, communication_settings, access_rights, file_size);
	}

	public static int
	mifare_desfire_create_backup_data_file_iso (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int file_size, short iso_file_id) throws Exception
	{
	    return create_file1 (tag, (byte)0xCB, file_no, 1, iso_file_id, communication_settings, access_rights, file_size);
	}

	public static int
	mifare_desfire_create_value_file (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int lower_limit, int upper_limit, int value, byte limited_credit_enable) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (18 + CMAC_LENGTH);
	    
	    C.BUFFER_APPEND (cmd, 0xCC);
	    C.BUFFER_APPEND (cmd, file_no);
	    C.BUFFER_APPEND (cmd, communication_settings);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes2(access_rights), 2, 2);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(lower_limit), 4, 4);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(upper_limit), 4, 4);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(value), 4, 4);
	    C.BUFFER_APPEND (cmd, limited_credit_enable);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	    cached_file_settings[file_no] = null;
	    
	    return 0;
	}

	public static int
	create_file2 (MifareTag tag, byte command, byte file_no, boolean has_iso_file_id, short iso_file_id, byte communication_settings, short access_rights, int record_size, int max_number_of_records) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (11 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, command);
	    C.BUFFER_APPEND (cmd, file_no);
	    if (has_iso_file_id)
	    	
		C.BUFFER_APPEND_LE (cmd, C.getBytes2(iso_file_id), 2, 2);
	    C.BUFFER_APPEND (cmd, communication_settings);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes2(access_rights), 2, 2);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(record_size), 3, 4);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(max_number_of_records), 3, 4);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	    cached_file_settings[file_no] = null;
	    
	    return 0;
	}

	public static int
	mifare_desfire_create_linear_record_file (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int record_size, int max_number_of_records) throws Exception
	{
	    return create_file2 (tag, (byte)0xC1, file_no, false, (short)0x0000, communication_settings, access_rights, record_size, max_number_of_records);
	}

	public static int
	mifare_desfire_create_linear_record_file_iso (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int record_size, int max_number_of_records, short iso_file_id) throws Exception
	{
	    return create_file2 (tag, (byte)0xC1, file_no, true, iso_file_id, communication_settings, access_rights, record_size, max_number_of_records);
	}

	public static int
	mifare_desfire_create_cyclic_record_file (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int record_size, int max_number_of_records) throws Exception
	{
	    return create_file2 (tag, (byte)0xC0, file_no, false, (short)0x000, communication_settings, access_rights, record_size, max_number_of_records);
	}

	public static int
	mifare_desfire_create_cyclic_record_file_iso (MifareTag tag, byte file_no, byte communication_settings, short access_rights, int record_size, int max_number_of_records, short iso_file_id) throws Exception
	{
	    return create_file2 (tag, (byte)0xC0, file_no, true, iso_file_id, communication_settings, access_rights, record_size, max_number_of_records);
	}

	public static int
	mifare_desfire_delete_file (MifareTag tag, byte file_no) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (2 + CMAC_LENGTH);
	    
	    C.BUFFER_APPEND (cmd, 0xDF);
	    C.BUFFER_APPEND (cmd, file_no);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);
    
	    byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);

	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
			return -1;
	    }	    

	    return 0;
	}

	// Data manipulation commands.

	public static byte[] 
	read_data (MifareTag tag, byte command, byte file_no, int offset, int length, int cs) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_CS (cs);

	    ByteBuffer cmd = C.BUFFER_INIT (8);
	    
	    // BUFFER_INIT (res, MAX_RAPDU_SIZE);

	    C.BUFFER_APPEND (cmd, command);
	    C.BUFFER_APPEND (cmd, file_no);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes3(offset), 3, 3);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes3(length), 3, 3);

	    int ocs = cs;
	    if ((C.MIFARE_DESFIRE (tag).getSessionKey() != null && ((cs | MifareDesfireCrypto.MDCM_MACED) != 0))) {
			switch (C.MIFARE_DESFIRE (tag).getAuthenticationScheme()) {
			case AS_LEGACY:
			    break;
			case AS_NEW:
			    cs = MifareDesfireCrypto.MDCM_PLAIN;
			    break;
			}
	    }
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 8, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);
	    cs = ocs;
	    
    	byte[] res = DESFIRE_TRANSCEIVE2 (tag, p);
    	
	    byte[] buffer = new byte[res.length + 1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);

	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, cs | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY | MifareDesfireCrypto.MAC_VERIFY);

	    if (p == null) {
			return null;
	    }

	    return p;
	}

	public static byte[] 
	mifare_desfire_read_data (MifareTag tag, byte file_no, int offset, int length) throws Exception
	{
	    return mifare_desfire_read_data_ex (tag, file_no, offset, length, madame_soleil_get_read_communication_settings (tag, file_no));
	}

	public static byte[] 
	mifare_desfire_read_data_ex (MifareTag tag, byte file_no, int offset, int length, int cs) throws Exception
	{
	    return read_data (tag, (byte) 0xBD, file_no, offset, length, cs);
	}
	
	public static int 
	write_data (MifareTag tag, byte command, byte file_no, int offset, int length, byte[] data, int cs) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_CS (cs);

	    ByteBuffer cmd = C.BUFFER_INIT (8 + length + CMAC_LENGTH);

	    //BUFFER_INIT (res, 1 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, command);
	    C.BUFFER_APPEND (cmd, file_no);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes3(offset), 3, 3);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes3(length), 3, 3);
	    C.BUFFER_APPEND_BYTES (cmd, data, length);
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 8, cs | MifareDesfireCrypto.MAC_COMMAND | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.ENC_COMMAND); // 1110
	    // int overhead_size = cmd.position() - length; // (CRC | padding) + headers

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);

	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length + 1, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
			return -1;
	    }

	    cached_file_settings[file_no] = null;

	    return data.length;
	}

	public static int 
	mifare_desfire_write_data (MifareTag tag, byte file_no, int offset, int length, byte[] data) throws Exception
	{
	    return mifare_desfire_write_data_ex (tag, file_no, offset, length, data, madame_soleil_get_write_communication_settings (tag, file_no));
	}

	public static int
	mifare_desfire_write_data_ex (MifareTag tag, byte file_no, int offset, int length, byte[] data, int cs) throws Exception
	{
	    return write_data (tag, (byte) 0x3D, file_no, offset, length, data, cs);
	}

	public static Integer
	mifare_desfire_get_value (MifareTag tag, byte file_no) throws Exception
	{
	    return mifare_desfire_get_value_ex (tag, file_no, madame_soleil_get_read_communication_settings (tag, file_no));
	}
	public static Integer
	mifare_desfire_get_value_ex (MifareTag tag, byte file_no, int cs) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_CS (cs);

	    ByteBuffer cmd = C.BUFFER_INIT (2 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0x6C);
	    C.BUFFER_APPEND (cmd, file_no);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 8, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[9 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, 9, cs | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY | MifareDesfireCrypto.MAC_VERIFY);

	    if (p == null) {
	    	return null;
	    }

	    return C.le32toh(p);
	}

	public static int
	mifare_desfire_credit (MifareTag tag, byte file_no, int amount) throws Exception
	{
	    return mifare_desfire_credit_ex (tag, file_no, amount, madame_soleil_get_write_communication_settings (tag, file_no));
	}

	public static int
	mifare_desfire_credit_ex (MifareTag tag, byte file_no, int amount, int cs) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_CS (cs);

	    ByteBuffer cmd = C.BUFFER_INIT (10 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0x0C);
	    C.BUFFER_APPEND (cmd, file_no);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(amount), 4, 4);
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 2, cs | MifareDesfireCrypto.MAC_COMMAND | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.ENC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }

	    cached_file_settings[file_no] = null;

	    return 0;
	}

	public static int
	mifare_desfire_debit (MifareTag tag, byte file_no, int amount) throws Exception
	{
	    return mifare_desfire_debit_ex (tag, file_no, amount, madame_soleil_get_write_communication_settings (tag, file_no));
	}
	public static int
	mifare_desfire_debit_ex (MifareTag tag, byte file_no, int amount, int cs) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_CS (cs);

	    ByteBuffer cmd = C.BUFFER_INIT (10 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xDC);
	    C.BUFFER_APPEND (cmd, file_no);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(amount), 4, 4);
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 2, cs | MifareDesfireCrypto.MAC_COMMAND | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.ENC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }

	    cached_file_settings[file_no] = null;

	    return 0;
	}

	public static int
	mifare_desfire_limited_credit (MifareTag tag, byte file_no, int amount) throws Exception
	{
	    return mifare_desfire_limited_credit_ex (tag, file_no, amount, madame_soleil_get_write_communication_settings (tag, file_no));
	}
	public static int
	mifare_desfire_limited_credit_ex (MifareTag tag, byte file_no, int amount, int cs) throws Exception
	{
		
		ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);
	    ASSERT_CS (cs);

	    ByteBuffer cmd = C.BUFFER_INIT (10 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0x1C);
	    C.BUFFER_APPEND (cmd, file_no);
	    C.BUFFER_APPEND_LE (cmd, C.getBytes4(amount), 4, 4);
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 2, cs | MifareDesfireCrypto.MAC_COMMAND | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.ENC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }

	    cached_file_settings[file_no] = null;

	    return 0;
	}

	public static int
	mifare_desfire_write_record (MifareTag tag, byte file_no, int offset, int length, byte[] data) throws Exception
	{
	    return mifare_desfire_write_record_ex (tag, file_no, offset, length, data, madame_soleil_get_write_communication_settings (tag, file_no));
	}
	public static int
	mifare_desfire_write_record_ex (MifareTag tag, byte file_no, int offset, int length, byte[] data, int cs) throws Exception
	{
	    return write_data (tag, (byte)0x3B, file_no, offset, length, data, cs);
	}

	public static byte[]
	mifare_desfire_read_records (MifareTag tag, byte file_no, int offset, int length) throws Exception
	{
	    return mifare_desfire_read_records_ex (tag, file_no, offset, length, madame_soleil_get_read_communication_settings (tag, file_no));
	}

	public static byte[] 
	mifare_desfire_read_records_ex (MifareTag tag, byte file_no, int offset, int length, int cs) throws Exception
	{
	    return read_data (tag, (byte)0xBB, file_no, offset, length, cs);
	}

	public static int
	mifare_desfire_clear_record_file (MifareTag tag, byte file_no) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (2 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xEB);
	    C.BUFFER_APPEND (cmd, file_no);

	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	    cached_file_settings[file_no] = null;

	    return 0;
	}

	public static int
	mifare_desfire_commit_transaction (MifareTag tag) throws Exception
	{
	    ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xC7);
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	    return 0;
	}

	public static int
	mifare_desfire_abort_transaction (MifareTag tag) throws Exception
	{
		ASSERT_ACTIVE (tag);
	    ASSERT_MIFARE_DESFIRE (tag);

	    ByteBuffer cmd = C.BUFFER_INIT (1 + CMAC_LENGTH);

	    C.BUFFER_APPEND (cmd, 0xA7);
	    
	    byte[] p = MifareDesfireCrypto.mifare_cryto_preprocess_data (tag, cmd, cmd.position(), 0, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND);

	    byte[] res = DESFIRE_TRANSCEIVE2(tag, p);
	    
	    byte[] buffer = new byte[1 + CMAC_LENGTH];
	    System.arraycopy(res, 0, buffer, 0, res.length);
	    
	    p = MifareDesfireCrypto.mifare_cryto_postprocess_data (tag, buffer, res.length, MifareDesfireCrypto.MDCM_PLAIN | MifareDesfireCrypto.CMAC_COMMAND | MifareDesfireCrypto.CMAC_VERIFY);

	    if (p == null) {
	    	return -1;
	    }
	    
	    return 0;		
	}

}
