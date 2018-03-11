package com.github.skjolber.desfire.libfreefare;

import java.nio.ByteBuffer;

import android.util.Log;

public class C {
	
	public static final byte zero = (byte)0;
	private static final String TAG = C.class.getName();

	public static void memset(byte[] array, byte value, int length) {
		memset(array, 0, value, length);
	}

	public static void memset(byte[] array, int offset, byte value, int length) {
		for(int i = offset; i < offset + length; i++) {
			array[i] = value;
		}
	}
	
	public static byte[] memcpy(byte[] destination, byte[] source, int length) {
		return memcpy(destination, 0, source, 0, length);
	}

	public static byte[] memcpy(byte[] destination, int destOffset, byte[] source, int sourceOffset, int length) {
		// overwrites overlaps
		for(int i = 0; i < length; i++) {
			destination[i + destOffset] = source[i + sourceOffset];
		}
		return destination;
	}
	
	public static void memcpy(byte[] destination, int destOffset, byte[] source, int length) {
		memcpy(destination, destOffset, source, 0, length);
	}

	public static void memcpy(byte[] destination, byte[] source, int sourceOffset, int length) {
		memcpy(destination, 0, source, sourceOffset, length);
	}

	public static byte[] malloc(int size) {
		return new byte[size];
	}
	
	public static byte[] memmove(byte[] destination, byte[] source, int length) {
		return memmove(destination, source, length);
	}

	public static byte[] memmove(byte[] destination, int destOffset, byte[] source, int sourceOffset, int length) {
		// does not overwrite overlaps
		System.arraycopy(source, sourceOffset, destination, destOffset, length);
		return destination;
	}

	public static final void htole32(long value, byte[] buffer, int bufferOffset) {
		buffer[bufferOffset + 3] = (byte) ((value >>> 24) & 0xFF);
		buffer[bufferOffset + 2] = (byte) ((value >>> 16) & 0xFF);
		buffer[bufferOffset + 1] = (byte) ((value >>> 8) & 0xFF);
		buffer[bufferOffset + 0] = (byte) ((value >>> 0) & 0xFF);
				
		// reversert!
	}
	
	public static byte[] htole32(int value) {
		byte[] buffer = new byte[4];
		
		htole32(value, buffer, 0);
		
		return buffer;
	}
	
	public static int le32toh(byte[] value) {
		return ((value[3] << 24) + (value[2] << 16) + (value[1] << 8) + (value[0] << 0));
	}
	
	public static MifareTag MIFARE_DESFIRE(MifareTag tag) {
		return tag;
	}

	public static int memcmp(byte[] a, byte[] b, int length) {
		return memcmp(a, 0, b, 0, length);
	}
	
	public static int memcmp(byte[] a, int aOffset, byte[] b, int bOffset, int length) {
		for(int i = 0; i < length; i++) {
			int compare = compareTo(a[aOffset + i], b[bOffset + i]);
			
			if(compare != 0) {
				return compare;
			}
		}
		
		return 0;
	}
	
	public static int compareTo(byte a, byte b) {
		return a - b;
	}
	
	public static byte[] realloc(byte[] buffer, int size) {
		if(buffer == null) {
			return new byte[size];
		}
		if(buffer.length >= size) {
			throw new IllegalArgumentException();
		}
		byte[] allocated = new byte[size];
		System.arraycopy(buffer, 0, allocated, 0, Math.min(buffer.length, size));
		return allocated;
	}
	
	public static void abort() {
		throw new IllegalArgumentException();
	}
	
	public static void hexdump(byte[] data, int offset, int length, String string, int expect) {
		log(toHexString(data, offset, length) + " Expect " + expect);
	}
	
	public static void log(String string) {
		Log.d(TAG, string);
	}
	
    /**
     * Converts the byte array to HEX string.
     * 
     * @param buffer
     *            the buffer.
     * @return the HEX string.
     */
    public static String toHexString(byte[] buffer) {
		StringBuilder sb = new StringBuilder();
		for(byte b: buffer)
			sb.append(String.format("%02x", b&0xff));
		return sb.toString();
    }
    
    /**
     * Converts the byte array to HEX string.
     * 
     * @param buffer
     *            the buffer.
     * @return the HEX string.
     */
    public static String toHexString(byte[] buffer, int offset, int length) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < length; i++) {
			byte b = buffer[i + offset];
			
			sb.append(String.format("%02x", b&0xff));
		}
		return sb.toString();
    }

	public static void warnx(String string) {
		// TODO Auto-generated method stub
		
	}

	public static void BUFFER_APPEND(ByteBuffer buffer, byte cmd) {
		buffer.put(cmd);
	}
	
	public static ByteBuffer BUFFER_INIT(int capacity) {
	    return ByteBuffer.allocate(capacity);
	}
	
	public static void BUFFER_APPEND_BYTES(ByteBuffer buffer, byte[] bytes, int length) {
		BUFFER_APPEND_BYTES(buffer, bytes, 0, length);
	}
	
	public static void BUFFER_APPEND_BYTES(ByteBuffer buffer, byte[] bytes, int offset, int length) {
		buffer.put(bytes, offset, length);
	}
	
	public static void BUFFER_APPEND(ByteBuffer buffer, int intByte) {
		if((intByte & ~0xFF) != 0) {
			throw new IllegalArgumentException();
		}
		BUFFER_APPEND(buffer, (byte)intByte);
	}
	
	/*
	 * Append data_size bytes of data at the end of the buffer.  Since data is
	 * copied as a little endian value, the storage size of the value has to be
	 * passed as the field_size parameter.
	 *
	 * Example: to copy 24 bits of data from a 32 bits value:
	 * BUFFER_APPEND_LE (buffer, data, 3, 4);
	 */
	
	public static void BUFFER_APPEND_LE(ByteBuffer buffer, byte[] data, int dataSize, int fieldSize) {
		// XXX migt be reversed
		
		int count = dataSize / fieldSize;
		for(int i = 0; i < count; i++) {
			for(int k = 0; k < fieldSize; k++) {
				buffer.put(data[i * fieldSize + fieldSize - 1 - k]);
			}
		}
	}
	
	public static byte[] getBytes2(int value) {
		return new byte[] {
    			(byte) ((value >>> 8) & 0xFF),
	    		(byte) ((value >>> 0) & 0xFF)
	    	};
	}
	
	public static byte[] getBytes3(int value) {
		return new byte[] {
    			(byte) ((value >>> 16) & 0xFF),
    			(byte) ((value >>> 8) & 0xFF),
	    		(byte) ((value >>> 0) & 0xFF)
	    	};
	}

	public static byte[] getBytes4(int value) {
		return new byte[] {
    			(byte) ((value >>> 24) & 0xFF),
    			(byte) ((value >>> 16) & 0xFF),
    			(byte) ((value >>> 8) & 0xFF),
	    		(byte) ((value >>> 0) & 0xFF)
	    	};
	}

}
