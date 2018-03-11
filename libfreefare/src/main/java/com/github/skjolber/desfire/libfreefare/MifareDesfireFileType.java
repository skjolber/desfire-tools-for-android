package com.github.skjolber.desfire.libfreefare;

public enum MifareDesfireFileType {
	
    MDFT_STANDARD_DATA_FILE(0x00),
    MDFT_BACKUP_DATA_FILE(0x01),
    MDFT_VALUE_FILE_WITH_BACKUP(0x02),
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP(0x03),
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP(0x04);
    
    private final byte code;
    
    private MifareDesfireFileType(int code) {
    	this.code = (byte) code;
    }
    
    public byte getCode() {
		return code;
	}
    
    
    
}