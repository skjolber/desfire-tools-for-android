package nfcjlib.core.util;

/**
 * Compute the CRC16.
 * 
 * <p>The internal methods {@link #crcA(byte[])} and
 * {@link #addByte(int, byte)} are based on the scala version
 * created by Tuomas Aura.
 * 
 * @author Daniel Andrade
 */
public class CRC16 {

	/**
	 * Compute the CRC16 of the byte array.
	 * 
	 * @param a	the byte array
	 * @return	the 2-byte CRC
	 */
	public static byte[] get(byte[] a) {
		return get(a, 0, a.length);
	}

	/**
	 * Compute the CRC16 of the byte array.
	 * 
	 * @param a			the byte array
	 * @param offset	the offset in the array
	 * @param length	the length
	 * @return			2-byte CRC
	 */
	public static byte[] get(byte[] a, int offset, int length) {
		int crc = crcA(a, offset, length);

		byte[] ret = new byte[2];
		//ret[0] = (byte) (crc >>> 8 & 0xff);
		//ret[1] = (byte) (crc & 0xff);
		ret[1] = (byte) (crc >>> 8 & 0xff);
		ret[0] = (byte) (crc & 0xff);

		// invert bit pattern
		//for (int i = 0; i < 2; i++) {
		//ret[i] = (byte) ~ret[i];
		//}

		return ret;
	}

	// adapted from Tuomas Aura's scala version
	private static int crcA(byte[] a, int offset, int length) {
		int crc = 0x6363;
		for (int i = offset; i < offset + length; i++) {
			crc = addByte(crc, a[i]);
		}
		return crc;
	}

	// converted from Tuomas Aura's scala version
	private static int addByte(int crc, byte b) {
		int bb = (((int)b) ^ crc) & 0xFF;
		bb = (bb ^ (bb << 4)) & 0xFF;
		return (crc >> 8) ^ (bb << 8) ^ (bb << 3) ^ (bb >> 4);
	}

}