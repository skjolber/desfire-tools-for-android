package com.github.skjolber.desfire.ev1.model.random;

public class StaticRandomSource implements RandomSource {

	private byte[] bytes;
	
	public StaticRandomSource(byte[] bytes) {
		this.bytes = bytes;
	}
	
	@Override
	public byte[] getRandom(int length) {
		byte[] random = new byte[length];
		fillRandom(new byte[length]);
		return random;
	}

	@Override
	public void fillRandom(byte[] bytes) {
		System.arraycopy(this.bytes, 0, bytes, 0, bytes.length);
	}

	
}
