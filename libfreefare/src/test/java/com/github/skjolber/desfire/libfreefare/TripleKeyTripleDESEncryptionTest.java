package com.github.skjolber.desfire.libfreefare;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfire.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireKey.*;

import java.util.Arrays;

import junit.framework.Assert;

import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.stubbing.OngoingStubbing;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.random.StaticRandomSource;

import android.util.Log;

public class TripleKeyTripleDESEncryptionTest {
	
	private byte[] key_data_3k3des = { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	
	private static final String TAG = TripleKeyTripleDESEncryptionTest.class.getName();

    @Test
    public void test3K3DES1() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];
		
		// Select application
		request[requestCount++] = new byte[]{(byte) 0x90, 0x5a, 0x00, 0x00, 0x03, (byte) 0xcc, (byte) 0xcc, (byte) 0xcc, 0x00};
		response[responseCount++] = new byte[]{(byte) 0x91, 0x00};
				
		//Authenticate 3K3DES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 1a 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("dd d0 38 1e fe e8 79 0f fe cd 21 ad 7d 1e 62 1f 91 af");
		
		byte[] a = TestUtils.hexStringToByteArray("ff ff ff ff 00 00 00 00 a6 e8 e0 33 35 00 00 00");
		Crypt.randomSource = new StaticRandomSource(a);

		
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 86 54 1a 99 b9 fd 28 41 ee b4 5c 3e 74 4b ae e3 c9 14 8d 4f eb cc 0c f6 f4 82 c4 22 23 6c 2e 41 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("27 3a 5a 6b cc 5a c4 af 58 6c 40 96 6d 80 86 90 91 00");
		
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}

        DesfireApplicationId aid_c = new DesfireApplicationId(TestUtils.hexStringToByteArray("CC CC CC"));
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		Log.d(TAG, "Select application");
		int res = mifare_desfire_select_application(tag, aid_c);
		assertEquals(0, res);

		MifareDESFireKey key = mifare_desfire_3k3des_key_new_with_version (key_data_3k3des);
		
		Log.d(TAG, "Authenticate");
		res = mifare_desfire_authenticate_iso (tag, (byte)0, key);


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

	public void test3K3DES2() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];
		
		// Select application
		request[requestCount++] =  TestUtils.hexStringToByteArray("90 5a 00 00 03 bb bb bb 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
				
		//Authenticate 3K3DES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 1a 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("a6 b5 ee c1 0a 88 a5 7d 3a e4 66 0a 27 e2 6a 7d 91 af");
		
		byte[] a = TestUtils.hexStringToByteArray(" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
		Crypt.randomSource = new StaticRandomSource(a);

		
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 aa 76 4b 63 45 03 74 4a 3a e4 66 0a 27 e2 6a 7d 51 82 c3 49 bb 04 e4 44 9b f0 b6 80 cc 6a fa 99 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("92 27 61 06 30 d5 d3 bd 9b f0 b6 80 cc 6a fa 99 91 00");

		//file settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("01 03 54 12 40 00 00 a2 c8 ae 79 b6 c8 42 e1 91 00");

		//read data 1
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 05 00 00 00 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f0 f7 26 2f 33 c8 9b 36 78 62 2e bd ef f1 41 4f 93 44 31 8e a1 9c 68 cb d7 5a 15 7a 2e 10 22 16 fb d4 6a b8 00 8b d4 01 e9 64 fa a1 b6 77 31 d7 06 d6 1e a6 c2 70 e1 4a 91 af");

		//read data 2
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("5c ef 8b d4 7a ba 40 9c 52 39 ac 57 5d d6 d5 bd 91 00");

		//file settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 04 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("02 03 54 12 00 00 00 00 e8 03 00 00 61 00 00 00 00 28 dc c7 50 26 c9 b6 98 91 00");

		//mifare_desfire_get_value_ex
		request[requestCount++] = TestUtils.hexStringToByteArray("90 6c 00 00 01 04 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("06 a4 e5 1a 88 3c be 32 91 00");
	
		//mifare_desfire_get_file_settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 03 54 12 04 00 00 0a 00 00 01 00 00 23 f2 3d 6c ac 45 7b 09 91 00");
		
		// read_data
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bb 00 00 07 00 00 00 00 01 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("f8 16 ba a5 b8 10 ca 31 91 00");
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}

        DesfireApplicationId aid = new DesfireApplicationId(TestUtils.hexStringToByteArray("BB BB BB"));
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		Log.d(TAG, "Select application");
		int res = mifare_desfire_select_application(tag, aid);
		assertEquals(0, res);

		MifareDESFireKey key = mifare_desfire_3k3des_key_new_with_version (key_data_3k3des);
		
		Log.d(TAG, "Authenticate");
		res = mifare_desfire_authenticate_iso (tag, (byte)5, key);

		byte[] mifare_desfire_read_data = mifare_desfire_read_data(tag, (byte)5, 0, 0);
		Log.d(TAG, "Read " + Utils.getHexString(mifare_desfire_read_data) + " " + new String(mifare_desfire_read_data));
		
		Integer value = mifare_desfire_get_value(tag, (byte)4);
		Log.d(TAG, "Read value " + (value));
		
		byte[] mifare_desfire_read_records = mifare_desfire_read_records (tag, (byte)0, 0, 1);
		Log.d(TAG, "Read " + Utils.getHexString(mifare_desfire_read_records));
		
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
	
	public void test3K3DES3() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];
		
		// Select application
		request[requestCount++] =  TestUtils.hexStringToByteArray("90 5a 00 00 03 bb bb bb 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
				
		//Authenticate 3K3DES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 1a 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("86 db 6e 91 ea fa a5 62 84 de 5e b3 7d f7 0f 9b 91 af");
		
		byte[] a = TestUtils.hexStringToByteArray(" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
		Crypt.randomSource = new StaticRandomSource(a);

		
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 05 f2 ae 9b 72 49 ef fa 84 de 5e b3 7d f7 0f 9b 53 8c 2e 64 10 e4 39 7d 2c 17 ad e1 a7 f3 8c f8 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("7a 4c 24 fc a3 ae a1 c8 2c 17 ad e1 a7 f3 8c f8 91 00");

		//file settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("01 03 54 12 40 00 00 80 28 d1 d3 b0 a9 37 fb 91 00");

		//read data 1
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 05 00 00 00 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("b1 af 8d b9 43 d5 2b b9 ec 2a c8 dd 79 88 e2 69 8d b7 d8 01 97 16 75 0e db 44 a8 38 c8 41 18 f4 12 c7 a4 62 bf d2 1e f1 e6 86 e0 27 1a f2 aa fd 57 ce e8 92 2a 9a b7 36 91 af");

		//read data 2
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("c4 c9 e4 30 f7 aa ab 00 61 22 aa 12 2c b2 29 cc 91 00 ");

		//file settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 04 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("02 03 54 12 00 00 00 00 e8 03 00 00 61 00 00 00 00 52 02 62 7d 89 2c f3 33 91 00");

		//mifare_desfire_get_value_ex
		request[requestCount++] = TestUtils.hexStringToByteArray("90 6c 00 00 01 04 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("2c b5 af e6 f0 99 88 2d 91 00");
	
		//mifare_desfire_get_file_settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("04 03 54 12 04 00 00 0a 00 00 01 00 00 6c eb d2 3a 95 96 a8 b5 91 00 ");
		
		// read_data
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bb 00 00 07 00 00 00 00 01 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("7e 78 40 2c c7 b7 f3 fb 91 00");

		//mifare_desfire_get_value_ex
		request[requestCount++] = TestUtils.hexStringToByteArray("90 6c 00 00 01 04 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("6b f1 1a 4d ad 53 86 d0 91 00");

		// read_data
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bb 00 00 07 00 00 00 00 01 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("56 af 07 3f 4e 69 b0 32 91 00");

		// get files ids
		request[requestCount++] = TestUtils.hexStringToByteArray("90 6f 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("0f 05 04 00 e6 03 02 83 ec 4b 1c aa 91 00");
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}

        DesfireApplicationId aid = new DesfireApplicationId(TestUtils.hexStringToByteArray("BB BB BB"));
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		Log.d(TAG, "Select application");
		int res = mifare_desfire_select_application(tag, aid);
		assertEquals(0, res);

		MifareDESFireKey key = mifare_desfire_3k3des_key_new_with_version (key_data_3k3des);
		
		Log.d(TAG, "Authenticate");
		res = mifare_desfire_authenticate_iso (tag, (byte)5, key);

		byte[] mifare_desfire_read_data = mifare_desfire_read_data(tag, (byte)5, 0, 0);
		Log.d(TAG, "Read " + Utils.getHexString(mifare_desfire_read_data) + " " + new String(mifare_desfire_read_data));
		
		Integer value = mifare_desfire_get_value(tag, (byte)4);
		Log.d(TAG, "Read value " + (value));
		
		byte[] mifare_desfire_read_records = mifare_desfire_read_records (tag, (byte)0, 0, 1);
		Log.d(TAG, "Read " + Utils.getHexString(mifare_desfire_read_records));

		value = mifare_desfire_get_value(tag, (byte)4);
		Log.d(TAG, "Read value " + (value));
		
		mifare_desfire_read_records = mifare_desfire_read_records (tag, (byte)0, 0, 1);
		Log.d(TAG, "Read " + Utils.getHexString(mifare_desfire_read_records));

		byte[] mifare_desfire_get_file_ids = mifare_desfire_get_file_ids(tag);
		Log.d(TAG, "File ids " + Utils.getHexString(mifare_desfire_get_file_ids));
		
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

	public void test3K3DES4() throws Exception {
		
		IsoDepWrapper wrapper = mock(IsoDepWrapper.class);

		DefaultIsoDepAdapter defaultIsoDepAdapter = new DefaultIsoDepAdapter(wrapper, true);
		
		int requestCount = 0;
		int responseCount = 0;
		byte[][] request = new byte[99][];
		byte[][] response = new byte[99][];
		
		// Select application
		request[requestCount++] =  TestUtils.hexStringToByteArray("90 5a 00 00 03 bb bb bb 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
				
		//Authenticate 3K3DES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 1a 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("a6 81 49 e9 17 cb 4e a6 37 df 6f 10 dc 51 9a 6e 91 af");
		
		byte[] a = TestUtils.hexStringToByteArray(" 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
		Crypt.randomSource = new StaticRandomSource(a);

		// auth step 2
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 20 ea 8e 2a 6e 21 3e 20 5f 37 df 6f 10 dc 51 9a 6e a9 46 83 4d 66 4e a6 5e c7 62 a9 45 a5 b6 3e 91 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("a6 25 04 7b 93 20 5f b4 c7 62 a9 45 a5 b6 3e 91 91 00");

		//file settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 f5 00 00 01 05 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("01 03 54 12 40 00 00 b6 b6 1c 44 68 1d 3b 08 91 00");

		//read data 1
		request[requestCount++] = TestUtils.hexStringToByteArray("90 bd 00 00 07 05 00 00 00 00 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("a8 ae 57 80 d8 ae 0f c1 38 b1 54 7e 1c 37 4f 26 27 d9 cd f6 31 8b 54 f7 b4 5b 08 c5 23 24 84 06 0f b7 d2 96 2f a3 95 3d b9 e9 8e f6 03 8e fa 72 8a 52 49 fb 6a 4e 40 0c 91 af");

		//read data 2
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("34 d2 f3 60 01 16 63 b2 8b d8 68 1e 9d 62 14 60 91 00");

		
		// get files ids
		request[requestCount++] = TestUtils.hexStringToByteArray("90 6f 00 00 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("0f 05 04 00 2b c1 20 d1 fa 65 1f 9d 91 00");
		
		OngoingStubbing<byte[]> when = when(wrapper.transceive(any(byte[].class)));
		for(int i = 0; i < responseCount; i++) {
			when = when.thenReturn(response[i]);
		}

        DesfireApplicationId aid = new DesfireApplicationId(TestUtils.hexStringToByteArray("BB BB BB"));
		
		// perform commands
		MifareTag tag = mifare_desfire_tag_new();
		tag.setActive(1);
		tag.setIo(defaultIsoDepAdapter);
		
		Log.d(TAG, "Select application");
		int res = mifare_desfire_select_application(tag, aid);
		assertEquals(0, res);

		MifareDESFireKey key = mifare_desfire_3k3des_key_new_with_version (key_data_3k3des);
		
		Log.d(TAG, "Authenticate");
		res = mifare_desfire_authenticate_iso (tag, (byte)5, key);

		Log.d(TAG, "CMAC " + Utils.getHexString(tag.getCMAC()));
		Log.d(TAG, "IVECT " + Utils.getHexString(tag.getInitializationVector()));
		
		byte[] mifare_desfire_read_data = mifare_desfire_read_data(tag, (byte)5, 0, 0);
		Log.d(TAG, "Read " + Utils.getHexString(mifare_desfire_read_data) + " " + new String(mifare_desfire_read_data));

		Log.d(TAG, "CMAC " + Utils.getHexString(tag.getCMAC()));
		Log.d(TAG, "IVECT " + Utils.getHexString(tag.getInitializationVector()));

		byte[] mifare_desfire_get_file_ids = mifare_desfire_get_file_ids(tag);
		if(mifare_desfire_get_file_ids != null) {
			Log.d(TAG, "File ids " + Utils.getHexString(mifare_desfire_get_file_ids));
		}
		
		Log.d(TAG, "CMAC " + Utils.getHexString(tag.getCMAC()));
		Log.d(TAG, "IVECT " + Utils.getHexString(tag.getInitializationVector()));

		Assert.assertNotNull(mifare_desfire_get_file_ids);
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