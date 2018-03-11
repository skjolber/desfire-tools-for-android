package nfcjlib.core.util;

/**
 * Work in progress: manipulate integers...
 * 
 * @author Daniel Andrade
 */
public class BitOp {

	/**
	 * Convert int to byte array (LSB).
	 * 
	 * @param value	the value to convert
	 * @return		4-byte byte array
	 */
	public static byte[] intToLsb(int value) {
		byte[] a = new byte[4];

		for (int i = 0; i < 4; i++) {
			a[i] = (byte) (value & 0xFF);
			value >>>= 8;
		}

		return a;
	}

	/**
	 * Convert an int value to a byte array. The conversion is
	 * placed in byte array <code>a</code> at offset <code>offset</code>.
	 * The value is represent in the byte array using LSB first.
	 * 
	 * @param value		the value to convert
	 * @param a			the byte array to store the converted value
	 * @param offset	the offset in <code>a</code>
	 */
	public static void intToLsb(int value, byte[] a, int offset) {
		for (int i = offset; i < offset + 4; i++) {
			a[i] = (byte) (value & 0xFF);
			value >>>= 8;
		}
	}

	/**
	 * Convert a 4-byte value from a byte array into an int value.
	 * The 4-byte value is assumed to be stored LSB first in the byte array.
	 * 
	 * @param a			the byte array containing the value to convert
	 * @param offset	the offset in the byte array
	 * @return			a Java int
	 */
	public static int lsbToInt(byte[] a, int offset) {
		int ret = 0;

		ret |= (a[3 + offset] & 0xff) << 24;
		ret |= (a[2 + offset] & 0xff) << 16;
		ret |= (a[1 + offset] & 0xff) << 8;
		ret |= (a[0 + offset] & 0xff) << 0;

		return ret;
	}

}