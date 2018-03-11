package com.github.skjolber.desfire.ev1.model;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * 
 * Interface for reading and writing to a binary format. Conventions: <br/>
 * <br/>
 * - Add a byte indicating which version of the data we are using.<br/>
 * - (advanced) If forward-compatibility is necessary, start the format by writing the size of the data. Combine with mark / reset of stream. <br/>
 * 
 * @author thomas
 *
 */

public interface Persistent {
	
	/**
	 * 
	 * Read data from stream
	 * 
	 * @param in
	 * @throws IOException
	 */

	void read(DataInputStream in) throws IOException;

	/**
	 * 
	 * Write data to stream
	 * 
	 * @param out
	 * @throws IOException
	 */
	void write(DataOutputStream out) throws IOException;
	
}
