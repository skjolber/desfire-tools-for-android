package nfcjlib.core.util;

import java.util.Arrays;

/**
 * CMAC implementation according to NIST 800-38B.
 * 
 * @author Daniel Andrade
 */
public class CMAC {

	private final static byte Rb64 = 0x1B;
	private final static byte Rb128 = (byte) 0x87;

	/**
	 * Calculate the CMAC of <code>data</code>.
	 * 
	 * @param type	Defines the block size and cipher to use.
	 * @param key	the secret key
	 * @param data	the data
	 * @return		the CMAC
	 */
	public static byte[] get(Type type, byte[] key, byte[] data) {
		byte[] zeros = null;

		switch (type) {
		case TKTDES:
			zeros = new byte[8];
			break;
		case AES:
			zeros = new byte[16];
			break;
		default:
			assert false : type;
		}

		return get(type, key, data, zeros);
	}

	// same as above but with external IV as argument
	public static byte[] get(Type type, byte[] key, byte[] data, byte[] aesIv) {
		int blockSize = -1;
		byte rb = -1;
		byte[] nistL = null;

		switch (type) {
		case TKTDES:
			blockSize = 8;
			rb = Rb64;
			byte[] zeros8 = new byte[blockSize];
			nistL = TripleDES.encrypt(zeros8, key, zeros8);
			break;
		case AES:
			blockSize = 16;
			rb = Rb128;
			byte[] zeros16 = new byte[blockSize];
			nistL = AES.encrypt(zeros16, key, zeros16);
			break;
		default:
			assert false : type;
		}

		byte[] nistK1 = getSubK1(nistL, blockSize, rb);
		byte[] nistK2 = getSubK2(nistK1, blockSize, rb);

		return getCMAC(key, nistK1, nistK2, data, aesIv, blockSize, type);
	}

	// size is the block size in bytes
	private static byte[] getCMAC(byte[] k, byte[] k1, byte[] k2, byte[] block, byte[] eIv, int size, Type type) {
		byte[] newBlock = block;
		if (block.length == 0) {
			newBlock = new byte[size];
			newBlock[0] = (byte) 0x80;
		}
		if (block.length % size != 0) {
			int index = block.length;
			newBlock = new byte[block.length - block.length % size + size];  // ??
			System.arraycopy(block, 0, newBlock, 0, block.length);
			newBlock[index] = (byte) 0x80;
			// the last bytes of newBlock are zero by default
		}

		if (block.length != 0 && block.length % size == 0) {
			// complete block: K1
			for (int i = newBlock.length - size; i < newBlock.length; i++)
				newBlock[i] ^= k1[i - newBlock.length + size];

		} else {
			// incomplete block: K2
			for (int i = newBlock.length - size; i < newBlock.length; i++)
				newBlock[i] ^= k2[i - newBlock.length + size];
		}
		byte[] formattedMessage = null;
		switch (type) {
		case TKTDES:
			formattedMessage = TripleDES.encrypt(eIv, k, newBlock);
			break;
		case AES:
			formattedMessage = AES.encrypt(eIv, k, newBlock);
			break;
		default:
			assert false : type;
		}
		//System.out.println("formattedMessage: " + Helper.valueOf(formattedMessage, true));
		byte[] cmac = new byte[size];
		System.arraycopy(formattedMessage, formattedMessage.length - size, cmac, 0, size);

		return cmac;
	}

	// size is the block size in bytes, poly is Rb64 or Rb128
	private static byte[] getSubK2(byte[] k1, int size, byte poly) {
		final byte[] rb = new byte[size];
		rb[rb.length - 1] = poly;
		byte[] k2 = shiftLeft(k1);

		if ((k1[0] & 0x80) != 0) {
			for (int i = 0; i < size; i++) {
				k2[i] = (byte) (k2[i] ^ rb[i]);
			}
		}

		return k2;
	}

	// size is the block size in bytes, poly is Rb64 or Rb128
	private static byte[] getSubK1(byte[] l, int size, byte poly) {
		final byte[] rb = new byte[size];
		rb[rb.length - 1] = poly;
		byte[] k1 = shiftLeft(l);

		if ((l[0] & 0x80) != 0) {
			for (int i = 0; i < size; i++) {
				k1[i] = (byte) (k1[i] ^ rb[i]);
			}
		}

		return k1;
	}

	// shift the entire byte array 1 bit to the left (could've done it more generic..)
	private static byte[] shiftLeft(byte[] a) {
		return toByte(shiftLeft(toBit(a)));
	}

	// aux: convert binary string to byte array (takes groups of 8 bits at a time so must be multiple of 8)
	private static byte[] toByte(String s) {
		byte[] a = new byte[s.length() / 8];

		for (int index = 0, i = 0; i < s.length(); index++, i+=8) {
			a[index] = (byte) Integer.parseInt(s.substring(i, i + 8), 2);
		}

		return a;
	}

	// aux: drop MSChar of string and add 0 to the right
	private static String shiftLeft(String s) {
		return s.substring(1) + "0";
	}

	// aux: convert byte array to String of bits (no spaces, zeros to left: multiple of 8)
	private static String toBit(byte[] a) {
		StringBuilder sb = new StringBuilder();

		for (byte b : a) {
			String s = Integer.toBinaryString(0x100 + b);
			sb.append(s.subSequence(s.length()-8, s.length()));
		}

		return sb.toString();
	}

	public enum Type {
		TKTDES,
		AES;
	}

}