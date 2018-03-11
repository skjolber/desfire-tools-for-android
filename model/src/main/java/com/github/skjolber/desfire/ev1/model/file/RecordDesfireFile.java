package com.github.skjolber.desfire.ev1.model.file;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import android.os.Parcel;
import android.os.Parcelable;
public class RecordDesfireFile extends DesfireFile implements Parcelable {
	
	private int recordSize;
	private int maxRecords;
	private int currentRecords;
	
	private byte[] records;

	public RecordDesfireFile() {
		super();
	}
	
    public RecordDesfireFile(int id, ByteArrayInputStream settings) {
    	this.id = id;
    	
        read(settings);
    }
    
    public void read(ByteArrayInputStream stream) {
    	super.read(stream);

        byte[] buf = new byte[3];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        recordSize = byteArrayToInt(buf);

        buf = new byte[3];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        maxRecords = byteArrayToInt(buf);

        buf = new byte[3];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        currentRecords = byteArrayToInt(buf);
    }

    public RecordDesfireFile (int id, DesfireFileType fileType, byte commSetting,  int readAccessKey, int writeAccessKey, int readWriteAccessKey, int changeAccessKey, int recordSize, int maxRecords, int curRecords) {
        super(id, fileType, commSetting, readAccessKey, writeAccessKey, readWriteAccessKey, changeAccessKey);
        this.recordSize = recordSize;
        this.maxRecords = maxRecords;
        this.currentRecords = curRecords;
    }

    @Override
    public void readFromParcel(Parcel source) {
    	super.readFromParcel(source);
    	recordSize = source.readInt();
    	maxRecords = source.readInt();
    	currentRecords = source.readInt();
    	
    	int size = source.readInt();
    	if(size > 0) {
    		this.records = new byte[size];
    		source.readByteArray(records);
    	}
    }
    
    @Override
    public void writeToParcel (Parcel parcel, int flags) {
        super.writeToParcel(parcel, flags);
        parcel.writeInt(recordSize);
        parcel.writeInt(maxRecords);
        parcel.writeInt(currentRecords);
        
    	if(records != null) {
    		parcel.writeInt(records.length);
    		parcel.writeByteArray(records);
    	} else {
    		parcel.writeInt(0);
    	}

    }

	public int getRecordSize() {
		return recordSize;
	}

	public int getMaxRecords() {
		return maxRecords;
	}

	public int getCurrentRecords() {
		return currentRecords;
	}
    
    public static final Creator<RecordDesfireFile> CREATOR = new Creator<RecordDesfireFile>() {
        public RecordDesfireFile createFromParcel(Parcel source) {
        	RecordDesfireFile recordDesfireFile = new RecordDesfireFile();
        	recordDesfireFile.readFromParcel(source);
        	return recordDesfireFile;
        }

        public RecordDesfireFile[] newArray(int size) {
            return new RecordDesfireFile[size];
        }
    };

    public byte[] getRecords() {
		return records;
	}
    
    public void setRecords(byte[] records) {
		this.records = records;
	}
    
    public boolean isRecords() {
    	return records != null;
    }

	@Override
	public String toString() {
		return "RecordDesfireFile [recordSize=" + recordSize + ", maxRecords=" + maxRecords + ", currentRecords=" + currentRecords + ", records=" + Arrays.toString(records) + ", fileType=" + fileType
				+ ", communicationSettings=" + communicationSettings + ", readAccessKey=" + readAccessKey + ", writeAccessKey=" + writeAccessKey + ", readWriteAccessKey=" + readWriteAccessKey
				+ ", changeAccessKey=" + changeAccessKey + ", id=" + id + "]";
	}

	@Override
	public boolean isContent() {
		return isRecords();
	}
}