package nfcjlib.core.util;

/**
 * Dump data in hexadecimal and other formats.
 * 
 * @author Daniel Andrade
 */
public class Dump {

	/**
	 * Hex dump of the argument.
	 * 
	 * @param b		a byte
	 * @return		hex dump of the byte
	 */
	public static String hex(byte b) {
		return String.format("%02x", b);
	}

	/**
	 * Hex dump a byte array. A space is added between bytes.
	 * 
	 * @param a	the byte array
	 * @return	the hex dump
	 */
	public static String hex(byte[] a) {
		return hex(a, true);
	}

	/**
	 * Hex dump a byte array with or without spaces in between bytes.
	 * 
	 * @param a		the byte array
	 * @param space	<code>true</code> to include a space between values
	 * @return		the hexadecimal representation of the byte array
	 */
	public static String hex(byte[] a, boolean space) {
		StringBuilder sb = new StringBuilder();

		if (space) {
			for (byte b : a) {
				sb.append(hex(b) + ' ');
			}
			if (sb.length() > 0) {
				sb.deleteCharAt(sb.length() - 1);
			}
		} else {
			for (byte b : a) {
				sb.append(hex(b));
			}
		}

		return sb.toString();
	}

}