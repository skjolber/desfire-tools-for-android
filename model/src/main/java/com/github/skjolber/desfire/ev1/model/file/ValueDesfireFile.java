package com.github.skjolber.desfire.ev1.model.file;

import java.io.ByteArrayInputStream;

import android.os.Parcel;
import android.os.Parcelable;

public class ValueDesfireFile extends DesfireFile implements Parcelable {
	
    private int lowerLimit;
    private int upperLimit;
    private int limitedCreditValue;
    private boolean limitedCredit;
    private boolean freeGetValue;
    
    private Integer value;

    public ValueDesfireFile(int id, ByteArrayInputStream settings) {
    	this.id = id;
    	
        read(settings);
    }
    
    public void read(ByteArrayInputStream stream) {
    	super.read(stream);

        byte[] buf = new byte[4];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        lowerLimit = byteArrayToInt(buf);

        buf = new byte[4];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        upperLimit = byteArrayToInt(buf);

        buf = new byte[4];
        stream.read(buf, 0, buf.length);
        reverse(buf);
        limitedCreditValue = byteArrayToInt(buf);
        
        limitedCredit = (stream.read() & 0x1) != 0;
        freeGetValue = (stream.read() & 0x2) != 0;
        
    }

    public ValueDesfireFile(int id, DesfireFileType fileType, byte commSetting,  int readAccessKey, int writeAccessKey, int readWriteAccessKey, int changeAccessKey, int lowerLimit, int upperLimit, int limitedCreditValue, boolean limitedCredit, boolean freeGetValue) {
        super(id, fileType, commSetting, readAccessKey, writeAccessKey, readWriteAccessKey, changeAccessKey);
		this.lowerLimit = lowerLimit;
		this.upperLimit = upperLimit;
		this.limitedCreditValue = limitedCreditValue;
		this.limitedCredit = limitedCredit;
		this.freeGetValue = freeGetValue;
	}

    public ValueDesfireFile() {
	}

	@Override
    public void readFromParcel(Parcel source) {
    	super.readFromParcel(source);
    	
    	lowerLimit = source.readInt();
    	upperLimit = source.readInt();
    	limitedCreditValue = source.readInt();
    	limitedCredit = source.readByte() == 0x1;
    	freeGetValue = source.readByte() == 0x1;
    	
    	if(source.readByte() != 0) {
    		value = source.readInt();
    	} else {
    		value = null;
    	}
    }
    
    @Override
    public void writeToParcel (Parcel parcel, int flags) {
        super.writeToParcel(parcel, flags);
        parcel.writeInt(lowerLimit);
        parcel.writeInt(upperLimit);
        parcel.writeInt(limitedCreditValue);
        parcel.writeByte((byte)(limitedCredit ? 0x1 : 0x0));
        parcel.writeByte((byte)(freeGetValue ? 0x1 : 0x0));
        
        if(value != null) {
        	parcel.writeByte((byte)1);
        	parcel.writeInt(value);
        } else {
        	parcel.writeByte((byte)0);
        }
    }

	public int getLowerLimit() {
		return lowerLimit;
	}

	public int getUpperLimit() {
		return upperLimit;
	}

	public int getLimitedCreditValue() {
		return limitedCreditValue;
	}

	public boolean isLimitedCredit() {
		return limitedCredit;
	}
    
    public static final Creator<ValueDesfireFile> CREATOR = new Creator<ValueDesfireFile>() {
        public ValueDesfireFile createFromParcel(Parcel source) {
        	ValueDesfireFile recordDesfireFile = new ValueDesfireFile();
        	recordDesfireFile.readFromParcel(source);
        	return recordDesfireFile;
        }

        public ValueDesfireFile[] newArray(int size) {
            return new ValueDesfireFile[size];
        }
    };
    
    public void setValue(Integer value) {
		this.value = value;
	}
    
    public Integer getValue() {
		return value;
	}
    
    public boolean isValue() {
    	return value != null;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + (freeGetValue ? 1231 : 1237);
		result = prime * result + (limitedCredit ? 1231 : 1237);
		result = prime * result + limitedCreditValue;
		result = prime * result + lowerLimit;
		result = prime * result + upperLimit;
		result = prime * result + ((value == null) ? 0 : value.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		ValueDesfireFile other = (ValueDesfireFile) obj;
		if (freeGetValue != other.freeGetValue)
			return false;
		if (limitedCredit != other.limitedCredit)
			return false;
		if (limitedCreditValue != other.limitedCreditValue)
			return false;
		if (lowerLimit != other.lowerLimit)
			return false;
		if (upperLimit != other.upperLimit)
			return false;
		if (value == null) {
			if (other.value != null)
				return false;
		} else if (!value.equals(other.value))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "ValueDesfireFile [lowerLimit=" + lowerLimit + ", upperLimit=" + upperLimit + ", limitedCreditValue=" + limitedCreditValue + ", limitedCredit=" + limitedCredit + ", freeGetValue="
				+ freeGetValue + ", value=" + value + ", fileType=" + fileType + ", communicationSettings=" + communicationSettings + ", readAccessKey=" + readAccessKey + ", writeAccessKey="
				+ writeAccessKey + ", readWriteAccessKey=" + readWriteAccessKey + ", changeAccessKey=" + changeAccessKey + ", id=" + id + "]";
	}
    
    @Override
    public boolean isContent() {
    	return isValue();
    }

}