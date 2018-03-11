package com.github.skjolber.desfire.ev1.model.file;

import android.os.Parcel;
import android.os.Parcelable;

import static java.util.Locale.ENGLISH;

public class DesfireFileId implements Parcelable {

    protected int id;

    public int getId() {
		return id;
	}
    
    public void setId(int id) {
		this.id = id;
	}
    
    public String getIdString() {
    	return "0x" + Integer.toHexString(id).toUpperCase(ENGLISH);
    }
    
    public void readFromParcel(Parcel source) {
    	id = source.readInt();
    }
    
    @Override
    public void writeToParcel (Parcel parcel, int flags) {
        parcel.writeInt(id);
    }

    public static final Creator<DesfireFileId> CREATOR = new Creator<DesfireFileId>() {
        public DesfireFileId createFromParcel(Parcel source) {
        	DesfireFileId recordDesfireFile = new DesfireFileId();
        	recordDesfireFile.readFromParcel(source);
        	return recordDesfireFile;
        }

        public DesfireFileId[] newArray(int size) {
            return new DesfireFileId[size];
        }
    };

	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + id;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DesfireFileId other = (DesfireFileId) obj;
		if (id != other.id)
			return false;
		return true;
	}

	
}
