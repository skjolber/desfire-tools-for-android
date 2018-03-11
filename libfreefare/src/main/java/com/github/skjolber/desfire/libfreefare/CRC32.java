package com.github.skjolber.desfire.libfreefare;

/**
 * Implements a general CRC class that lets you change the polynomial.
 * 
 * CRC-32 has this wonderful property that appending a CRC to the end of message allows you to 
 * perform verification of the message by calculating a CRC of the entire thing, and if the checksum passes, the final result will be zero.
 * 
 */
public class CRC32 {
	private int polynomial = 0xEDB88320;
	private int crc = 0xFFFFFFFF;

	/**
	 * Calculates a CRC value for a byte to be used by CRC calculation functions.
	 */
	private int CRC32Value(int i) {
		int crc = i;

		for (int j = 8; j > 0; j--) {
			if ((crc & 1) == 1)
				crc = (crc >>> 1) ^ polynomial;
			else
				crc >>>= 1;
		}
		return crc;

	}

	/**
	 * Calculates the CRC-32 of a block of data all at once
	 */
	public int calculateCRC32(byte[] buffer, int offset, int length) {
		for (int i = offset; i < offset + length; i++) {
			int tmp1 = (crc >>> 8) & 0x00FFFFFF;
			int tmp2 = CRC32Value(((int) crc ^ buffer[i]) & 0xff);
			crc = tmp1 ^ tmp2;
		}
		return crc;
	}

	/**
	 * Calculates the CRC-32 of a block of data all at once
	 */
	public int calculateCRC32(byte[] buffer) {
		return calculateCRC32(buffer, 0, buffer.length);
	}

	/**
	 * Resets the state to process more data.
	 */
	public void reset() {
		crc = 0;
	}

	public void setPolynomial(int polynomial) {
		this.polynomial = polynomial;
	}
}
