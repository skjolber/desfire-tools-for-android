package com.github.skjolber.desfire.ev1.model;

import android.os.Parcel;
import android.os.Parcelable;

import com.github.skjolber.desfire.ev1.model.key.DesfireKey;

public class DesfireApplicationKey implements Parcelable {

	private int index;
	private DesfireKey desfireKey;
	
	public DesfireApplicationKey() {
	}
	
	public DesfireApplicationKey(int index, DesfireKey desfireKey) {
		this.index = index;
		this.desfireKey = desfireKey;
	}

	public int getIndex() {
		return index;
	}
	
	public void setIndex(int index) {
		this.index = index;
	}
	
	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public void writeToParcel(Parcel dest, int flags) {
		dest.writeInt(index);
		dest.writeParcelable(desfireKey, flags);
	}
	
    public static final Creator<DesfireApplicationKey> CREATOR = new Creator<DesfireApplicationKey>() {
        public DesfireApplicationKey createFromParcel(Parcel in) {
       	 
        	DesfireApplicationKey item = new DesfireApplicationKey();

        	item.readFromParcel(in);
       	 	
        	
            return item;
        }

        public DesfireApplicationKey[] newArray(int size) {
            return new DesfireApplicationKey[size];
        }
    };
    
	@Override
	public String toString() {
		return "DesfireKeyReference [index=" + index + ", key=" + desfireKey + "]";
	}

	protected void readFromParcel(Parcel in) {
    	setIndex(in.readInt());
    	setDesfireKey((DesfireKey) in.readParcelable(getClass().getClassLoader()));
	}
	
	public void setDesfireKey(DesfireKey desfireKey) {
		this.desfireKey = desfireKey;
	}
	
	public DesfireKey getDesfireKey() {
		return desfireKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((desfireKey == null) ? 0 : desfireKey.hashCode());
		result = prime * result + index;
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
		DesfireApplicationKey other = (DesfireApplicationKey) obj;
		if (desfireKey == null) {
			if (other.desfireKey != null)
				return false;
		} else if (!desfireKey.equals(other.desfireKey))
			return false;
		if (index != other.index)
			return false;
		return true;
	}

    
}
