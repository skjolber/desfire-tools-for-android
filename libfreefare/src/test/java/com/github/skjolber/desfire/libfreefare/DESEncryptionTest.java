package com.github.skjolber.desfire.libfreefare;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfire.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireAutoAuthenticate.*;
import static com.github.skjolber.desfire.libfreefare.MifareDesfireKey.*;

import java.util.Arrays;

import org.junit.Test;
import org.mockito.InOrder;
import org.mockito.stubbing.OngoingStubbing;

import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.random.StaticRandomSource;

import android.util.Log;

public class DESEncryptionTest {
	
	private static final String TAG = DESEncryptionTest.class.getName();

    @Test
   public void testDES1() throws Exception {
		
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
		response[responseCount++] = new byte[]{04, 0x4c, 0x59, (byte) 0x92, (byte) 0xda, 0x2c, (byte) 0x80, (byte) 0xba, 0x34, (byte) 0x98, (byte) 0xba, (byte) 0xd0, 0x29, 0x12, (byte) 0x91, 0x00};
		
		//Auto authenticate
		request[requestCount++] = new byte[]{(byte) 0x90, 0x64, 0x00, 0x00, 0x01, 0x00, 0x00};
		response[responseCount++] = new byte[]{0x00, (byte) 0x91, 0x00};

		//Authenticate DES
		request[requestCount++] = new byte[]{(byte) 0x90, (byte) 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00};
		response[responseCount++] = TestUtils.hexStringToByteArray("c9 36 93 a0 cd 32 ac 39 91 af");

		byte[] a = TestUtils.hexStringToByteArray("71 cb 90 3a 2c ae 7c 9c d6 f2 ad 17 74 f5 6d 2a");
		Crypt.randomSource = new StaticRandomSource(a);
		
		request[requestCount++] = TestUtils.hexStringToByteArray("90 af 00 00 10 e9 6a 7e 6d 79 03 10 e8 c0 b3 6e d9 70 78 24 06 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("89 b5 d3 8c 76 03 da b2 91 00 ");
		
		//Change key settings
		request[requestCount++] = TestUtils.hexStringToByteArray("90 54 00 00 08 73 40 52 86 c5 c8 a1 41 00");
		
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		
		//Change master key to AES
		request[requestCount++] = TestUtils.hexStringToByteArray("90 c4 00 00 19 80 0b 74 92 5d 1b 18 71 77 bd af 1c 2c 0a 1a 36 29 f6 c1 33 5b 8f e6 b1 66 00");
		response[responseCount++] = TestUtils.hexStringToByteArray("91 00");
		
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