package com.github.skjolber.desfire.ev1.model.random;

import java.security.SecureRandom;

public class DefaultRandomSource implements RandomSource {

	private SecureRandom random = new SecureRandom();
	
	@Override
	public byte[] getRandom(int length) {
		byte[] bytes = new byte[length];
		fillRandom(bytes);
		return bytes;
	}

	@Override
	public void fillRandom(byte[] bytes) {
		random.nextBytes(bytes);
	}

}
