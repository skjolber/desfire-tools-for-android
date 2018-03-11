package nfcjlib.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import android.util.Log;

import com.github.skjolber.desfire.ev1.model.command.IsoDepWrapper;

public class DESFireAdapter {

	private static final String TAG = DESFireAdapter.class.getName();
	
    /* Status codes */
    public static final byte OPERATION_OK = (byte)0x00;
    public static final byte ADDITIONAL_FRAME = (byte)0xAF;
    public static final byte STATUS_OK = (byte) 0x91;

	public static final int MAX_CAPDU_SIZE = 55;
	public static final int MAX_RAPDU_SIZE = 60;

	private IsoDepWrapper isoDep;
	private boolean print;

	public DESFireAdapter(IsoDepWrapper isoDep, boolean print) {
		this.isoDep = isoDep;
		this.print = print;
	}
	
	public IsoDepWrapper getIsoDep() {
		return isoDep;
	}
	
	/**
	 * Send compressed command message 
	 * 
	 * @param adpu
	 * @return
	 * @throws Exception 
	 */

	public byte[] transmitChain(byte[] adpu) throws Exception {
		return receieveResponseChain(sendRequestChain(adpu));
    }
	
	public byte[] receieveResponseChain(byte[] response) throws IOException, Exception {
		
		if(response[response.length - 2] == STATUS_OK && response[response.length - 1] == OPERATION_OK) {
			return response;
		}
		
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        do {
            if (response[response.length - 2] != STATUS_OK) {
                throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }
            
            output.write(response, 0, response.length - 2);

            byte status = response[response.length - 1];
            if (status == OPERATION_OK) {
            	return output.toByteArray();
            } else if (status != ADDITIONAL_FRAME) {
                throw new Exception("PICC error code while reading response: " + Integer.toHexString(status & 0xFF));
        	}

        	response = transmit(wrapMessage(ADDITIONAL_FRAME));
        } while(true);
	}

	public byte[] sendRequestChain(byte[] apdu) throws Exception {
		
		if(apdu.length <= MAX_CAPDU_SIZE) {
			return transmit(apdu);
		}
        int offset = 5; // data area of apdu
        
        byte nextCommand =  apdu[1];
        while(true) {
        	int nextLength = Math.min(MAX_CAPDU_SIZE - 1, apdu.length - offset);
        	
            byte[] request = wrapMessage(nextCommand, apdu, offset, nextLength);

            byte[] response = transmit(request);
            if (response[response.length - 2] != STATUS_OK) {
                throw new Exception("Invalid response " + String.format("%02x", response[response.length - 2] & 0xff));
            }

            offset += nextLength;
            if(offset == apdu.length) {
            	return response;
            }

            if(response.length != 2) {
        		throw new IllegalArgumentException("Expected empty response payload while transmitting request");
            }
            byte status = response[response.length - 1];
        	if (status != ADDITIONAL_FRAME) {
                throw new Exception("PICC error code: " + Integer.toHexString(status & 0xFF));
        	}
        	nextCommand = ADDITIONAL_FRAME;
        }
		
	}
	
    public static byte[] wrapMessage (byte command) throws Exception {
    	return new byte[]{(byte) 0x90, command, 0x00, 0x00, 0x00};
    }
	
    public static byte[] wrapMessage (byte command, byte[] parameters, int offset, int length) throws Exception {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null && length > 0) {
        	// actually no length if empty length
            stream.write(length);
            stream.write(parameters, offset, length);
        }
        stream.write((byte) 0x00);

        return stream.toByteArray();
    }
    
	/**
	 * Send a command to the card and return the response.
	 * 
	 * @param command	the command
	 * @return			the PICC response
	 * @throws IOException 
	 */
	public byte[] transmit(byte[] command) throws IOException {
		
		if(print) {
			Log.d(TAG, "===> " + getHexString(command, true) + " (" + command.length + ")");
		}
		
		byte[] response = isoDep.transceive(command);
		
		if(print) {
			Log.d(TAG, "<=== " + getHexString(response, true) + " (" + command.length + ")");
		}

		return response;
	}

    public static String getHexString(byte[] a, boolean space) {
		StringBuilder sb = new StringBuilder();
		for (byte b : a) {
			sb.append(String.format("%02x", b & 0xff));
			if(space) {
				sb.append(' ');
			}
		}
		return sb.toString().trim().toUpperCase();
    }

}
