package com.github.skjolber.desfire.ev1.model.file;

import java.io.ByteArrayInputStream;

import android.os.Parcel;
import android.os.Parcelable;

public class UnsupportedDesfireFile extends DesfireFile implements Parcelable {
	
    public UnsupportedDesfireFile(int id, ByteArrayInputStream settings) {
    	this.id = id;
    	
        read(settings);
    }
    
    public UnsupportedDesfireFile() {
	}
    
    public UnsupportedDesfireFile (int id, DesfireFileType fileType, byte commSetting,  int readAccessKey, int writeAccessKey, int readWriteAccessKey, int changeAccessKey) {
    	super(id, fileType, commSetting, readAccessKey, writeAccessKey, readWriteAccessKey, changeAccessKey);
    }

    @Override
    protected void read(ByteArrayInputStream stream) {
    	super.read(stream);
    }
    
	public static final Creator<UnsupportedDesfireFile> CREATOR = new Creator<UnsupportedDesfireFile>() {
        public UnsupportedDesfireFile createFromParcel(Parcel source) {
        	UnsupportedDesfireFile recordDesfireFile = new UnsupportedDesfireFile();
        	recordDesfireFile.readFromParcel(source);
        	return recordDesfireFile;
        }

        public UnsupportedDesfireFile[] newArray(int size) {
            return new UnsupportedDesfireFile[size];
        }
    };
    
    public boolean isContent() {
    	return false;
    };

}