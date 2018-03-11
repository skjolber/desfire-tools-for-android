package nfcjlib.core.util;


public class CommandBuilder {

	private byte[] command;
	private int offset = 0;
	
	public CommandBuilder(int length) {
		this.command = new byte[length];
	}
	
	public CommandBuilder bytes1(byte b) {
		command[offset] = b;
		
		offset++;
		
		return this;
	}
	
	public CommandBuilder bytes3(int value) {
		command[offset] = (byte) ((value >>> 16) & 0xFF);
		command[offset + 1] = (byte) ((value >>> 8) & 0xFF);
		command[offset + 2] = (byte) ((value >>> 0) & 0xFF);
		
		offset += 3;
		
		return this;
	}
	
	public byte[] bytes() {
		return command;
	}
}
