package com.github.skjolber.desfire.ev1.model.command;

import java.io.IOException;

public interface IsoDepWrapper {

	byte[] transceive(byte[] data) throws IOException;
	
	
}
