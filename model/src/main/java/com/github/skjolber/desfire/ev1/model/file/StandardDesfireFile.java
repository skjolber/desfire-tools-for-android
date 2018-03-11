package com.github.skjolber.desfire.ev1.model.file;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import android.os.Parcel;
import android.os.Parcelable;

public class StandardDesfireFile extends DesfireFile implements Parcelable {
	
	private int fileSize;
	private byte[] data;

    public StandardDesfireFile (int id, ByteArrayInputStream settings) {
    	this.id = id;
    	
        read(settings);
    }
    
    public void read(ByteArrayInputStream stream) {
    	super.read(stream);

        byte[] buf = new byte[3];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        fileSize = byteArrayToInt(buf);
    }

    public StandardDesfireFile (int id, DesfireFileType fileType, byte commSetting,  int readAccessKey, int writeAccessKey, int readWriteAccessKey, int changeAccessKey, int fileSize) {
    	super(id, fileType, commSetting, readAccessKey, writeAccessKey, readWriteAccessKey, changeAccessKey);
        this.fileSize = fileSize;
    }

    public StandardDesfireFile() {
	}

    @Override
    public void readFromParcel(Parcel source) {
    	super.readFromParcel(source);
    	fileSize = source.readInt();
    	
    	int size = source.readInt();
    	if(size > 0) {
    		data = new byte[size];
    		source.readByteArray(data);
    	} else {
    		data = null;
    	}
    }
    
    @Override
    public void writeToParcel (Parcel parcel, int flags) {
        super.writeToParcel(parcel, flags);
        parcel.writeInt(fileSize);
        if(data != null) {
        	parcel.writeInt(data.length);
        	parcel.writeByteArray(data);
        } else {
        	parcel.writeInt(0);
        }
    }
    
    public int getFileSize() {
		return fileSize;
	}
    
	public static final Creator<StandardDesfireFile> CREATOR = new Creator<StandardDesfireFile>() {
        public StandardDesfireFile createFromParcel(Parcel source) {
        	StandardDesfireFile recordDesfireFile = new StandardDesfireFile();
        	recordDesfireFile.readFromParcel(source);
        	return recordDesfireFile;
        }

        public StandardDesfireFile[] newArray(int size) {
            return new StandardDesfireFile[size];
        }
    };
    
    public void setData(byte[] data) {
		this.data = data;
	}
    
    public byte[] getData() {
		return data;
	}
    
    public boolean isData() {
    	return data != null && data.length > 0;
    }

	@Override
	public String toString() {
		return "StandardDesfireFile [fileSize=" + fileSize + ", data=" + Arrays.toString(data) + "]";
	}
    
	@Override
	public boolean isContent() {
		return isData();
	}
    
}