package com.github.skjolber.desfire.libfreefare;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfire.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireAutoAuthenticate.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireKey.*;

import java.util.Arrays;

import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.stubbing.OngoingStubbing;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.random.StaticRandomSource;

import android.util.Log;

import nfcjlib.core.DESFireAdapter;
import nfcjlib.core.DESFireEV1;
import nfcjlib.core.KeyType;

public class AESEncryptionTest {
	
	private static final String TAG = AESEncryptionTest.class.getName();

   @Test
   public void testAES1() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];
		
		// Select application
		request[requestCount++] = new byte[]{(byte) 0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
		response[responseCount++] = new byte[]{(byte) 0x91, 0x00};
		
		//Get version info  
		//hardware
		request[requestCount++] = new byte[]{(byte) 0x90, 0x60, 0x00, 0x00, 0x00};
		response[responseCount++] = new byte[]{0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05, (byte) 0x91, (byte) 0xaf};
		//software
		request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0xaf, 0x00, 0x00, 0x00};
		response[responseCount++] = new byte[]{0x04, 0x01, 0x01, 0x01, 0x04, 0x18, 0x05, (byte) 0x91, (byte) 0xaf};
		//uid
		request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0xaf, 0x00, 0x00, 0x00};
		response[responseCount++] = new byte[]{0x04, 0x14, 0x59, (byte) 0x92, (byte) 0xda, 0x2c, (byte) 0x80, (byte) 0xba, 0x34, (byte) 0x98, (byte) 0xba, (byte) 0xd0, 0x29, 0x12, (byte) 0x91, 0x00};
		
		//Auto authenticate
		request[requestCount++] = new byte[]{(byte) 0x90, 0x64, 0x00, 0x00, 0x01, 0x00, 0x00};
		response[responseCount++] = new byte[]{0x42, (byte) 0x91, 0x00};

		//Authenticate AES
		request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0xaa, 0x00, 0x00, 0x01, 0x00, 0x00};
		response[responseCount++] = TestUtils.hexStringToByteArray("b1 1d c2 43 87 da bb ea 5b a8 ff 44 57 1e 70 d4 91 af");

		byte[] a = TestUtils.hexStringToByteArray("f0 26 60 9e 4a b8 80 9d 3d 8a c7 29 f6 19 a5 fb");
		Crypt.randomSource = new StaticRandomSource(a);
		
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 7d 9a 73 cf f7 a4 62 83 9c e2 e1 b0 7b 82 36 bb f2 a6 bf 03 43 c7 02 6f f0 d3 61 3b 9b 94 b2 ce 00"); //new byte[]{(byte)0x90, (byte)0xaf, 0x00, 0x00, 0x20, 0x15, (byte)0xfc, (byte)0xd8, (byte)0xf3, 0x09, 0x6c, (byte)0xf5, 0x79, 0x06, 0x1e, (byte)0xe1, (byte)0xab, 0x7e, 0x10, (byte)0xec, 0x15, (byte)0xe9, 0x2d, 0x5c, 0x11, 0x11, (byte)0xb8, 0x76, 0x68, (byte)0xdb, (byte)0xe8, (byte)0xb8, 0x2e, 0x3a, 0x73, (byte)0xc8, (byte)0xa4, 0x00};
		response[responseCount++] = TestUtils.hexStringToByteArray("2a 71 a8 72 df e3 00 fa d9 0e 06 f3 fe a4 8c b5 91 00");
		
		//Change key settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 54 00 00 10 4b 18 9a d1 7d d6 d8 48 d7 76 91 d5 b2 fd 73 a3 00");
		
		response[responseCount++] = TestUtils.hexStringToByteArray("c2 c1 42 4f 83 11 12 77 91 00");
		
		//Change master key to AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 c4 00 00 21 80 30 ee 2c 20 33 07 9b 67 7d 6e 0b 85 56 9c 5b fe 95 42 b8 58 19 b9 03 42 76 4d 6e bb 3b 32 7e ca 00"); // new byte[]{(byte)0x90, (byte)0xc4, 0x00, 0x00, 0x21, (byte)0x80, (byte)0xb8, (byte)0xde, 0x30, (byte)0x93, (byte)0xc0, (byte)0x8c, 0x27, 0x26, (byte)0x83, 0x14, (byte)0xaf, 0x31, 0x1a, 0x01, (byte)0x8a, (byte)0x91, 0x67, (byte)0x94, 0x71, 0x76, (byte)0xaf, 0x14, (byte)0xd8, (byte)0xbc, (byte)0xa1, (byte)0xf1, 0x6e, (byte)0xa2, (byte)0x90, 0x2c, (byte)0x9f, 0x55, 0x00};
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		
		//Authenticate using AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("69 0d 62 65 df f9 03 23 f9 ec 65 c6 e1 bb 57 0f 91 af");

		//RndB0000   ca 59 18 38 88 c8 23 81 fd 1a 0a cc df a8 06 d5
		//RndA0000   f8 b9 c7 8d 72 ad e8 82 4f d5 71 88 97 8a e5 71 
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 49 81 d9 63 7f a1 31 f3 da d3 2f 28 4d c8 d6 41 cc e9 49 cc 9f e8 b5 f8 cf 93 fd 6b e6 5b 59 e4 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f0 16 fb 6c 31 e6 55 3a a2 12 d0 1d 1f 4f fd e0 91 00");

		//Format PICC
		request[requestCount++] = TestUtils.hexStringToByteArray("90 fc 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f2 c6 a1 5c d7 cf 97 34 91 00");
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		Log.d(TAG, "Select application");
		int res = mifare_desfire_select_application(tag, null);
		assertEquals(0, res);
		
		Log.d(TAG, "Get version");
		VersionInfo versionInfo = mifare_desfire_get_version(tag);

		Log.d(TAG, "Auto authenticate");
		mifare_desfire_auto_authenticate(tag, (byte)0x00);
		
		Log.d(TAG, "Change key settings");
		res = mifare_desfire_change_key_settings(tag, (byte)0xF);
		assertEquals(0, res);
		
		Log.d(TAG, "Change master key");
		MifareDESFireKey key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
		res = mifare_desfire_change_key (tag, (byte)0, key, null);
		assertEquals(0, res);
		
		a = TestUtils.hexStringToByteArray("e1 83 4f ae 03 6a 7e 3b 71 e8 25 b5 84 4d 8b 56");
		Crypt.randomSource = new StaticRandomSource(a);

		Log.d(TAG, "Reauthentiacte using new key");
		res = mifare_desfire_authenticate_aes (tag, (byte)0, key);
		assertEquals(0, res);
		
		Log.d(TAG, "Wipe card");
		/* Wipeout the card */
		res = mifare_desfire_format_picc (tag);
		assertEquals(0, res);

		// verify
		InOrder inOrder = inOrder(wrapper);

		for(int i = 0; i < requestCount; i++) {
			byte[] r = request[i];

			Log.d(TAG, "Verify request " + i + ": " + Utils.getHexString(r, true));

			int k = 0;
			while(k + i < requestCount && Arrays.equals(r, request[k + i])) {
				k++;
			}
			inOrder.verify(wrapper, times(k)).transceive(request[i]);
			
			i += k - 1;
			
		}
		inOrder.verifyNoMoreInteractions();
		
	}

    @Test
	public void testAES2() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];


		// Connect.Select application
		request[requestCount++] = TestUtils.hexStringToByteArray("90 5a 00 00 03 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		// Get version info 
		request[requestCount++] = TestUtils.hexStringToByteArray("90 60 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 01 01 01 00 18 05 91 af");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 01 01 01 04 18 05 91 af");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 1f 5b 92 da 2c 80 ba 34 98 ba d0 29 12 91 00");
		// Auto authenticate 0
		request[requestCount++] = TestUtils.hexStringToByteArray("90 64 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("42 91 00");
		// key_data_aes_version
		// Authenticate AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("70 7a 8a 39 fa 7c a7 58 71 de b4 ab 9d 6d 3e 33 91 af");
		//  25 e0 b2 b5 62 03 87 f4 2c a1 55 6c f3 ed 65 ee                                                
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 46 1b 4d ce e9 d6 c6 d6 a0 b6 aa 2d e2 d7 44 5b 3b 3c dc f6 88 6b 65 18 ec 11 18 6b f9 7a 3a 04 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("c3 77 d8 47 54 43 ae 5d 19 62 40 83 28 92 10 f9 91 00");
		// Change key settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 54 00 00 10 5d 83 df e5 66 49 f4 05 df b6 f3 b9 3d a7 19 fe 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f0 6d 30 8b 21 c8 90 d9 91 00");
		// Change master key to AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 c4 00 00 21 80 0a 96 97 92 0f 1a 2f c6 5e 39 32 57 61 0e c4 0d 96 27 82 1b 75 cd 9b b3 50 0d de 5e ab e4 8f db 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		// Authenticate using AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("a0 f0 8e b0 de c8 ef 45 4e 1b 7c 2d ae f1 48 27 91 af");
		//  61 75 57 df 97 72 e0 10 77 1b 3e 63 29 25 bb a7                                                
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 c2 6a c5 15 0c 7d e2 e4 be 7f 28 17 27 2b 3c 07 40 4d ee b0 2e 83 c7 03 e6 04 fb f5 9c 04 70 90 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f1 b4 a0 bb 8b bd 5a 97 87 8d 4e c4 b7 4d 5d 19 91 00");
		// Format PICC
		request[requestCount++] = TestUtils.hexStringToByteArray("90 fc 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("8e 20 68 3c f4 52 50 90 91 00");
		// Create application
		request[requestCount++] = TestUtils.hexStringToByteArray("90 ca 00 00 05 aa aa aa 02 8e 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("15 5f ff 8b 3c f5 4f e5 91 00");
		// Select application
		request[requestCount++] = TestUtils.hexStringToByteArray("90 5a 00 00 03 aa aa aa 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("e7 26 d1 cc 04 af 0b 34 6a 4a ef 1d 16 ef 33 6c 91 af");
		//  ba 43 50 b0 48 a7 0c 3a 1d e9 84 ec 77 39 13 96                                                
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 65 87 84 43 ec 6f 40 cd 95 16 a1 02 b6 2c 3d 08 b5 8a 07 14 4a dd 00 79 92 da 9a 25 91 52 22 39 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("75 01 b9 0c 87 14 8c bb e8 36 9f af a9 27 16 7a 91 00");
		// Change key 0
		request[requestCount++] = TestUtils.hexStringToByteArray("90 c4 00 00 21 05 48 28 c6 71 fb 09 0a 02 4a e0 a5 11 ae e8 db cc b1 91 22 9c b8 e9 35 15 0d a4 76 cd 11 ac ec 4f 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("bd 52 99 e6 95 af ee 07 91 00");
		// Create standard data file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 cd 00 00 07 0f 03 54 12 64 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("d5 ec e1 d1 e0 aa 97 8a 91 00");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 64 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("42 eb 58 49 47 7b ae 90 5a 91 00");
		// key_data_aes_version
		// Authenticate AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("7a 4f be 87 79 2e 6f f1 3d f9 b5 30 4c 65 f4 84 91 af");
		//  41 b4 71 9a 6c 7f 5e dd dd a1 e5 55 8a 49 11 96                                                
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 bd eb f8 b5 14 a2 c0 bf 2b 8b 98 92 c2 f2 3b 5b 1a af 13 94 46 18 2d ed c9 86 3f 6b 67 b1 5b 90 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("bd f4 33 83 ac 37 96 87 f9 3f 35 77 b9 35 b8 ef 91 00");
		// Write to data file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 0f 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("00 03 54 12 64 00 00 7e fd e2 c2 c8 1a d2 36 91 00");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 3d 00 00 36 0f 00 00 00 1e 00 00 81 99 5d f0 a7 5c f3 9b f6 59 1b bf 98 2a 9e fa 05 5b 94 d4 f6 88 b0 8c 2b 7e c7 18 63 14 8d 28 21 20 65 97 72 53 6e 33 d3 50 7e 07 1d ed 14 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 af");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 01 64 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("d5 1c 9d c8 12 42 8d 40 91 00");
		// Write more to data file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 0f 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("00 03 54 12 64 00 00 cc a2 08 ab 50 d8 bc 87 91 00");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 3d 00 00 27 0f 22 00 00 16 00 00 df 04 33 1a 73 7e 43 1c 75 48 d0 c3 58 ac 15 82 57 8a 96 0b 5e e5 1b d4 50 b7 c7 4d 04 79 c0 de 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("86 cd c7 62 82 29 9c af 91 00");
		// Read file part
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 0f 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("00 03 54 12 64 00 00 e1 68 3b a6 06 7a 09 a2 91 00");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 0f 0a 00 00 32 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("99 ee 41 fc cc 29 9f 4d 7f 2a ef af 54 b1 48 0f af 0d cc f7 93 2b 02 0a a5 a2 1e 34 a3 8a 30 f3 67 32 5a 5b 82 ea f8 f4 a8 45 f5 f2 ca 9e 0d 24 91 af");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("6b e1 29 6b 82 19 3c 71 d0 c8 5e b4 43 ec 00 3c 91 00");
		// Read full file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 0f 00 00 00 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("9c 3e 97 7a d9 f2 57 b7 6b d6 68 21 d3 0b c9 a5 a4 cd 23 ad 7e d4 fe 9e e0 58 06 56 cb 60 9d 06 eb 26 1a 0d 7b 84 2d 25 e2 12 3b c6 19 53 71 d5 91 af");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("d9 d0 51 86 af ad 6b c9 ae 5c a0 55 71 06 a2 24 c7 9a ab 27 f8 df ab 72 15 f7 ed 93 6c f1 b7 f8 31 e5 89 80 69 39 b2 be cf b6 3c 94 64 a8 c1 2c 91 af");
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("cd 9e 41 32 ef 54 a8 c6 c3 a1 36 83 55 59 d6 dd 91 00");
	
		
		
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}
		
		

		
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		int res = mifare_desfire_select_application(tag, null);
		assertEquals(0, res);
		
		VersionInfo versionInfo = mifare_desfire_get_version(tag);
		
	Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray("25 e0 b2 b5 62 03 87 f4 2c a1 55 6c f3 ed 65 ee "));

		mifare_desfire_auto_authenticate(tag, (byte)0x00);
		
		Log.d(TAG, "Change key settings");
		res = mifare_desfire_change_key_settings(tag, (byte)0xF);
		assertEquals(0, res);
		
		Log.d(TAG, "Change master key");
		MifareDESFireKey key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
		res = mifare_desfire_change_key (tag, (byte)0, key, null);
		assertEquals(0, res);
		
	Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray(" 61 75 57 df 97 72 e0 10 77 1b 3e 63 29 25 bb a7     "));

		Log.d(TAG, "Reauthentiacte using new key");
		res = mifare_desfire_authenticate_aes (tag, (byte)0, key);
		assertEquals(0, res);

		Log.d(TAG, "Wipe card");
		// Wipeout the card 
		res = mifare_desfire_format_picc (tag);
		assertEquals(0, res);


		Log.d(TAG, "Create application");
        DesfireApplicationId aid_a = new DesfireApplicationId(C.getBytes3(0x00AAAAAA));
		res = mifare_desfire_create_application_aes (tag, aid_a, (byte)0x02, (byte)14);
		assertEquals(0, res);


		Log.d(TAG, "Select application");
		res = mifare_desfire_select_application(tag, aid_a);
		assertEquals(0, res);

		Log.d(TAG, "Authenticate AES");
	Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray("ba 43 50 b0 48 a7 0c 3a 1d e9 84 ec 77 39 13 96"));
		res = mifare_desfire_authenticate_aes (tag, (byte)0, key);
		assertEquals(0, res);
		
		Log.d(TAG, "Change key 5");
	    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
 		res = mifare_desfire_change_key (tag, (byte)5, key, null);
		assertEquals(0, res);
		
		byte std_data_file_id = 15;
				
		Log.d(TAG, "Create standard file");
	    res = mifare_desfire_create_std_data_file (tag, std_data_file_id, MifareDesfireCrypto.MDCM_ENCIPHERED, 0x1254, 100); // read key, write key, read/write key, change key.
		assertEquals(0, res);

		Log.d(TAG, "Auto authenticate");
	Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray(" 41 b4 71 9a 6c 7f 5e dd dd a1 e5 55 8a 49 11 96 "));
		mifare_desfire_auto_authenticate (tag, (byte)5);
		
		assertEquals(5, tag.getAuthenticatedKeyNo());
		
		Log.d(TAG, "Write to data file");
		res = mifare_desfire_write_data (tag, std_data_file_id, 0, 30, TestUtils.hexStringToByteArray("53 6f 6d 65 20 64 61 74 61 20 74 6f 20 77 72 69 74 65 20 74 6f 20 74 68 65 20 63 61 72 64"));
		assertEquals(30, res);
		
		Log.d(TAG, "Write more to data file");
	    res = mifare_desfire_write_data (tag, std_data_file_id, 34, 22, "Another block of data.".getBytes());
		assertEquals(22, res);

		Log.d(TAG, "Read file part");
	    byte[] data = mifare_desfire_read_data (tag, std_data_file_id, 10, 50);
	    Log.d(TAG, "Data length " + data.length);
	    Log.d(TAG, "Got data " + new String(data));
	    Log.d(TAG, "Got data " + Utils.getHexString(data, true));
		assertEquals(50, data.length);
		assertEquals("to write to the card\0\0\0\0Another block of data.\0\0\0\0", new String(data));

		Log.d(TAG, "Read full file");
	    data = mifare_desfire_read_data (tag, std_data_file_id, 0, 0);
	    assertNotNull(data);
		assertEquals(100, data.length);
		
		Log.d(TAG, "Read full file");

		// verify
		InOrder inOrder = inOrder(wrapper);

		for(int i = 0; i < requestCount; i++) {
			byte[] r = request[i];

			Log.d(TAG, "Verify request " + i + ": " + Utils.getHexString(r, true));

			int k = 0;
			while(k + i < requestCount && Arrays.equals(r, request[k + i])) {
				k++;
			}
			inOrder.verify(wrapper, times(k)).transceive(request[i]);
			
			i += k - 1;
			
		}
		inOrder.verifyNoMoreInteractions();
	}

    @Test
    public void testAES3() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];

		request[requestCount++] = TestUtils.hexStringToByteArray("90 5a 00 00 03 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");

		request[requestCount++] = TestUtils.hexStringToByteArray("90 60 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 01 01 01 00 18 05 91 af");

		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 01 01 01 04 18 05 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 1f 5b 92 da 2c 80 ba 34 98 ba d0 29 12 91 00");
		
		// auto authenticate
		request[requestCount++] = TestUtils.hexStringToByteArray("90 64 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("42 91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("97 e6 cd a4 2c e6 dd 23 9b 74 67 92 03 52 b1 8d 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 01 a2 57 62 dc b7 c6 cd 89 bc 0d e0 82 2e b4 6f 96 5a 18 15 59 80 0b a8 ae b6 98 0b 6b 72 33 92 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("da 2c a9 3d eb ca fe 45 37 88 07 8b 8e 5e 1d 57 91 00");
		
		// change key settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 54 00 00 10 cc b3 e7 a4 6b bf 6a b3 a2 6e 47 98 55 98 5d 77 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("d0 ab e5 43 f2 9e 1d 62 91 00");
		
		// Change master key to AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 c4 00 00 21 80 ff c7 99 a6 d9 51 eb 74 6e 1e 1f 89 df d3 76 ec 2e 49 0b 9c 9f ad 2e 0d 29 6c 6c a0 b7 31 30 c8 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("37 9b 3f 89 47 f9 4a af 40 95 17 9d 21 9b 01 52 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 09 e0 ec 4d d6 f6 2f 21 f4 75 b4 e7 b5 7e 9d 67 81 87 93 16 e2 9f b8 6b 2d 6e f9 b3 df 27 1b cd 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("99 f2 1d 9e 96 89 32 cb ad da 64 72 cd fb a6 1c 91 00");
		
		// format PICC
		request[requestCount++] = TestUtils.hexStringToByteArray("90 fc 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("5c 31 7d 34 14 50 56 f2 91 00");
		

		// Create application
		request[requestCount++] = TestUtils.hexStringToByteArray("90 ca 00 00 05 aa aa aa 02 8e 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("5a 4a d3 f0 a3 9e e5 16 91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 5a 00 00 03 aa aa aa 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		
		// authenticate aes
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("31 17 8a c4 8c 9f 7b 82 37 62 c7 1b 17 b2 2e 35 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 d0 69 11 cd 20 12 4c ec c6 9e ed ae 02 71 c5 17 4f 1b 6b f4 80 d6 c0 47 33 66 6e 91 f6 4c 1d ef 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("12 e6 16 63 fa a7 2d 5d 92 6d 54 74 1a 8b d9 12 91 00");
		
		// Change key 5
		request[requestCount++] = TestUtils.hexStringToByteArray("90 c4 00 00 21 05 cf b2 64 cd 30 ca 4d c3 c8 a5 d1 d5 2a f0 75 a4 55 46 4b c4 49 65 63 7d 68 5b e6 c9 88 d8 91 c4 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("8f 58 e5 a2 6f 8f e0 41 91 00");
		
		// create standard data file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 cd 00 00 07 0f 03 54 12 64 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("ff c5 22 2f 48 83 3f da 91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 64 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("42 45 46 8f 1d 68 27 af 1c 91 00");
		
		// authenticate aes
		// RndA 5a 77 d1 10 16 db 9e eb a1 d9 1c f5 22 31 18 2a 
		request[requestCount++] = TestUtils.hexStringToByteArray("90 aa 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("53 e3 a2 17 99 4c d6 20 aa a2 96 26 3c 06 81 d8 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 cd 69 21 b7 87 fd 71 d8 26 5d 9f 9d a1 59 89 74 66 64 35 2d d8 fb c3 81 f7 65 c2 de 30 4b be 4e 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("ef 14 e5 dc f0 35 a1 97 7a b1 3f a4 01 96 b5 52 91 00");
		
		// write data to file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 0f 00");
		response[responseCount++] = TestUtils.hexStringToByteArray(" 00 03 54 12 64 00 00 4c 4f fd 20 54 e6 dc 1a 91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 3d 00 00 36 0f 00 00 00 1e 00 00 90 30 cf d5 0c 3e ec ff 62 0a 20 5b c9 8d 7b ef e1 d3 05 1b ac 17 30 de b0 9d 13 7d 24 25 41 95 9f a6 ed e9 4f 55 f8 84 2c 2a 42 ec 32 3e ba 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 01 de 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("63 87 b9 fb 6e 13 71 0e 91 00");
		
		// write more to data file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 0f 00 ");
		response[responseCount++] = TestUtils.hexStringToByteArray("00 03 54 12 64 00 00 e0 54 19 6e 15 a7 30 59 91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 3d 00 00 27 0f 22 00 00 16 00 00 0c 48 fd d8 a3 19 4b 15 3f fd ab 9e 80 4a e0 7d 39 6f a1 a5 ce b8 22 32 21 16 7a 30 4f d9 19 b2 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("86 5d 79 b7 04 fe 67 d9 91 00");
		
		// read file part
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 0f 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("00 03 54 12 64 00 00 0f c9 d7 49 d8 85 f4 d5 91 00");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 0f 0a 00 00 32 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f7 8f 40 20 75 1a e3 4a 14 5e 15 95 b2 95 0e f0 70 8c 68 a6 3f 6d 33 37 98 75 51 0d 22 aa 65 0b 1b 5d e3 04 93 a7 20 d0 19 ca d1 01 e3 83 3a 12 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("da e3 a6 26 f0 05 08 22 d6 2a 04 d2 4b 38 3a 18 91 00 ");
		
		// read full file
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 0f 00 00 00 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("ec 3e 9e 51 18 02 22 25 f3 d4 b7 5f 2f 72 18 1a f0 d5 af 9a 34 7c f2 34 a3 2a ea 3d 3f 86 0f 3c 4e ab c5 eb bf f7 cd 73 38 a6 71 87 4d 63 f9 8e 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("26 2e ff c2 4b 5a ba 72 b5 74 2f 8c 3f 3f c6 16 b9 08 45 83 0e ff 31 0d 71 0c 3b e2 cc e6 ff 94 72 bf 9a d5 5e 45 fb 10 89 d1 8f 72 09 0d 47 0e 91 af");
		
		//
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("64 50 17 ca 2a c8 4f f7 92 c2 16 b8 d5 5a ee 87 91 00");
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}
		
		Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray("8a 1d 47 85 b7 f0 e3 6d 20 3e 68 45 85 91 05 4f"));
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		int res = mifare_desfire_select_application(tag, null);
		assertEquals(0, res);
		
		VersionInfo versionInfo  = mifare_desfire_get_version(tag);
		
		mifare_desfire_auto_authenticate(tag, (byte)0x00);
		
		Log.d(TAG, "Change key settings");
		res = mifare_desfire_change_key_settings(tag, (byte)0xF);
		assertEquals(0, res);
		
		Log.d(TAG, "Change master key");
		MifareDESFireKey key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
		res = mifare_desfire_change_key (tag, (byte)0, key, null);
		assertEquals(0, res);
		
		Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray("7d fb d3 c2 e0 f4 0f a8 aa a9 c4 68 9d 59 b7 38"));

		Log.d(TAG, "Reauthentiacte using new key");
		res = mifare_desfire_authenticate_aes (tag, (byte)0, key);
		assertEquals(0, res);

		Log.d(TAG, "Wipe card");
		// Wipeout the card 
		res = mifare_desfire_format_picc (tag);
		assertEquals(0, res);


		Log.d(TAG, "Create application");
        DesfireApplicationId aid_a = new DesfireApplicationId(C.getBytes3(0x00AAAAAA));
		res = mifare_desfire_create_application_aes (tag, aid_a, (byte)0x02, (byte)14);
		assertEquals(0, res);


		Log.d(TAG, "Select application");
		res = mifare_desfire_select_application(tag, aid_a);
		assertEquals(0, res);

		Log.d(TAG, "Authenticate AES");
		Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray("a9 e5 ba a2 90 d9 86 a0 cf 5b 29 81 0c 9d 0e ad"));
		res = mifare_desfire_authenticate_aes (tag, (byte)0, key);
		assertEquals(0, res);
		
		Log.d(TAG, "Change key 5");
	    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
 		res = mifare_desfire_change_key (tag, (byte)5, key, null);
		assertEquals(0, res);
		
		byte std_data_file_id = 15;
				
		Log.d(TAG, "Create standard file");
	    res = mifare_desfire_create_std_data_file (tag, std_data_file_id, MifareDesfireCrypto.MDCM_ENCIPHERED, 0x1254, 100); // read key, write key, read/write key, change key.
		assertEquals(0, res);

		Log.d(TAG, "Auto authenticate");
		Crypt.randomSource = new StaticRandomSource(TestUtils.hexStringToByteArray("5a 77 d1 10 16 db 9e eb a1 d9 1c f5 22 31 18 2a"));
		mifare_desfire_auto_authenticate (tag, (byte)5);
		
		
		Log.d(TAG, "Write to data file");
		res = mifare_desfire_write_data (tag, std_data_file_id, 0, 30, "Some data to write to the card".getBytes());
		assertEquals(30, res);
		
		Log.d(TAG, "Write more to data file");
	    res = mifare_desfire_write_data (tag, std_data_file_id, 34, 22, "Another block of data.".getBytes());
		assertEquals(22, res);

		Log.d(TAG, "Read file part");
	    byte[] data = mifare_desfire_read_data (tag, std_data_file_id, 10, 50);
		assertEquals(50, data.length);

		Log.d(TAG, "Read full file");
	    data = mifare_desfire_read_data (tag, std_data_file_id, 0, 0);
		assertEquals(100, data.length);

		// verify
		InOrder inOrder = inOrder(wrapper);

		for(int i = 0; i < requestCount; i++) {
			byte[] r = request[i];

			Log.d(TAG, "Verify request " + i + ": " + Utils.getHexString(r, true));

			int k = 0;
			while(k + i < requestCount && Arrays.equals(r, request[k + i])) {
				k++;
			}
			inOrder.verify(wrapper, times(k)).transceive(request[i]);
			
			i += k - 1;
			
		}
		inOrder.verifyNoMoreInteractions();
	}

    @Test
    public void testAES4() throws Exception {

        IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

        DESFireAdapter defaultIsoDepAdapter = new DESFireAdapter(wrapper, true);

        int requestCount = 0;
        int responseCount = 0;
        byte[][] request = new byte[99][];
        byte[][] response = new byte[99][];

        // Select application
        request[requestCount++] = new byte[]{(byte) 0x90, 0x5a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};
        response[responseCount++] = new byte[]{(byte) 0x91, 0x00};

        //Get version info
        //hardware
        request[requestCount++] = new byte[]{(byte) 0x90, 0x60, 0x00, 0x00, 0x00};
        response[responseCount++] = new byte[]{0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05, (byte) 0x91, (byte) 0xaf};
        //software
        request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0xaf, 0x00, 0x00, 0x00};
        response[responseCount++] = new byte[]{0x04, 0x01, 0x01, 0x01, 0x04, 0x18, 0x05, (byte) 0x91, (byte) 0xaf};
        //uid
        request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0xaf, 0x00, 0x00, 0x00};
        response[responseCount++] = new byte[]{0x04, 0x14, 0x59, (byte) 0x92, (byte) 0xda, 0x2c, (byte) 0x80, (byte) 0xba, 0x34, (byte) 0x98, (byte) 0xba, (byte) 0xd0, 0x29, 0x12, (byte) 0x91, 0x00};

        //Auto authenticate
        request[requestCount++] = new byte[]{(byte) 0x90, 0x64, 0x00, 0x00, 0x01, 0x00, 0x00};
        response[responseCount++] = new byte[]{0x42, (byte) 0x91, 0x00};

        //Authenticate AES
        request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0xaa, 0x00, 0x00, 0x01, 0x00, 0x00};
        response[responseCount++] = TestUtils.hexStringToByteArray("b1 1d c2 43 87 da bb ea 5b a8 ff 44 57 1e 70 d4 91 af");

        byte[] a = TestUtils.hexStringToByteArray("f0 26 60 9e 4a b8 80 9d 3d 8a c7 29 f6 19 a5 fb");

        request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 7d 9a 73 cf f7 a4 62 83 9c e2 e1 b0 7b 82 36 bb f2 a6 bf 03 43 c7 02 6f f0 d3 61 3b 9b 94 b2 ce 00"); //new byte[]{(byte)0x90, (byte)0xaf, 0x00, 0x00, 0x20, 0x15, (byte)0xfc, (byte)0xd8, (byte)0xf3, 0x09, 0x6c, (byte)0xf5, 0x79, 0x06, 0x1e, (byte)0xe1, (byte)0xab, 0x7e, 0x10, (byte)0xec, 0x15, (byte)0xe9, 0x2d, 0x5c, 0x11, 0x11, (byte)0xb8, 0x76, 0x68, (byte)0xdb, (byte)0xe8, (byte)0xb8, 0x2e, 0x3a, 0x73, (byte)0xc8, (byte)0xa4, 0x00};
        response[responseCount++] = TestUtils.hexStringToByteArray("2a 71 a8 72 df e3 00 fa d9 0e 06 f3 fe a4 8c b5 91 00");

        //Change key settings
        request[requestCount++] = TestUtils.hexStringToByteArray("90 54 00 00 10 4b 18 9a d1 7d d6 d8 48 d7 76 91 d5 b2 fd 73 a3 00");

        response[responseCount++] = TestUtils.hexStringToByteArray("c2 c1 42 4f 83 11 12 77 91 00");

        OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
        for(int i = 0; i < responseCount; i++) {
            when = when.thenReturn(response[i]);
        }


        DESFireEV1 tag = new DESFireEV1();
        tag.setPrint(true);
        tag.setAdapter(defaultIsoDepAdapter);
        tag.setRandomSource(new StaticRandomSource(a));

        Log.d(TAG, "Select application");
        tag.selectApplication(new byte[]{0x00, 0x00, 0x00});

        Log.d(TAG, "Get version");
        tag.getVersion();

        Log.d(TAG, "Auto authenticate");

        tag.getKeyVersion((byte)0x00);

        tag.authenticate(key_data_aes, (byte)0x00, KeyType.AES);

        Log.d(TAG, "Change key settings");
        tag.changeKeySettings((byte)0xF);

        // verify
        InOrder inOrder = inOrder(wrapper);

        for(int i = 0; i < requestCount; i++) {
            byte[] r = request[i];

            Log.d(TAG, "Verify request " + i + ": " + Utils.getHexString(r, true));

            int k = 0;
            while(k + i < requestCount && Arrays.equals(r, request[k + i])) {
                k++;
            }
            inOrder.verify(wrapper, times(k)).transceive(request[i]);

            i += k - 1;

        }
        inOrder.verifyNoMoreInteractions();

    }

} 