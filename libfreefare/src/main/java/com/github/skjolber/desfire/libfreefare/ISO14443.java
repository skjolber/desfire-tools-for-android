package com.github.skjolber.desfire.libfreefare;

public class ISO14443 {
	
	private static final String TAG = ISO14443.class.getName();

	private static final int maskB = 0xFF;
	private static final int maskW = 0xFFFF;
		
	public static void iso14443a_crc (byte[] pbtData, int pbtDataOffset, int szLen, byte[] pbtCrc, int pbtCrcOffset)
	{
	  int bt;
	  int wCrc = 0x6363;

	  int offset = 0;
	  do {
		  bt = pbtData[pbtDataOffset + offset] & maskB;
		  offset++;
		  bt = (bt ^ (wCrc & 0x00FF)) & maskB;
		  bt = (bt ^ (bt << 4)) & maskB;
		  wCrc = ((wCrc >> 8) ^ (bt << 8) ^ (bt << 3) ^ (bt >> 4)) & maskW;
		  
		  //Log.d(TAG, "CRC " + Integer.toHexString((wCrc & 0xFF)) + " " + Integer.toHexString(((wCrc >> 8) & 0xFF)));

	  } while (--szLen != 0);

	  pbtCrc[pbtCrcOffset] = (byte) (wCrc & 0xFF);
	  pbtCrc[pbtCrcOffset + 1] = (byte) ((wCrc >> 8) & 0xFF);
	  
	  //Log.d(TAG, "Place at " + pbtCrcOffset);
	}

	public static void iso14443a_crc_append (byte[] pbtData, int pbtDataOffset, int szLen) {
	  iso14443a_crc (pbtData, pbtDataOffset, szLen, pbtData, pbtDataOffset + szLen);
	}
}
