package com.github.skjolber.desfire.ev1.model.random;

public interface RandomSource {

	byte[] getRandom(int length);
	
	void fillRandom(byte[] bytes);

}
