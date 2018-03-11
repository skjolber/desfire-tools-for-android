package com.github.skjolber.desfire.ev1.model.file;

public enum DesfireFileCommunicationSettings {

	// key 0xE: Plain for all. key 0x00-0xD
	PLAIN(0x00, "Plain communication"), 
	PLAIN_MAC(0x01, "Plain communication secured by MACing"), 
	ENCIPHERED(0x03, "Fully enciphered communication");
	
	private String description;
	private int value;
	
	private DesfireFileCommunicationSettings(int value, String description) {
		this.value = value;
		this.description = description;
	}
	
	public int getValue() {
		return value;
	}

	public static DesfireFileCommunicationSettings parse(int value) {
		for(DesfireFileCommunicationSettings settings : values()) {
			if(settings.value == value) {
				return settings;
			}
		}
		throw new IllegalArgumentException("Unknown communications settings " + value);
	}
	
	public String getDescription() {
		return description;
	}
}
