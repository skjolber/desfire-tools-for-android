package com.github.skjolber.desfire.ev1.model.file;


public enum DesfireFileType {

    STANDARD_DATA_FILE(0x00),
    BACKUP_DATA_FILE(0x01),
    VALUE_FILE(0x02),
    LINEAR_RECORD_FILE(0x03),
    CYCLIC_RECORD_FILE(0x04),
    UNKNOWN_FILE_TYPE	(0xFF);
    
	private final int id;
	
	private DesfireFileType(int id) {
		this.id = id;
	}
	
	public int getId() {
		return id;
	}
	
	public static DesfireFileType getType(int id) {
		for(DesfireFileType type : values()) {
			if(type.getId() == id) {
				return type;
			}
		}
		throw new IllegalArgumentException("Unknown id " + id);
	}
}
