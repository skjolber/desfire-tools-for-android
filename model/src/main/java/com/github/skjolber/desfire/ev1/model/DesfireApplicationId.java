package com.github.skjolber.desfire.ev1.model;

import android.os.Parcel;
import android.os.Parcelable;

import java.util.Locale;

import static java.util.Locale.ENGLISH;

public class DesfireApplicationId implements Parcelable {

	private byte[] id;

	public boolean isMaster() {
		return id[0] == 0 && id[1] == 0 && id[2] == 0;
	}
	
	@Override
	public int describeContents() {
		return 0;
	}

	public DesfireApplicationId() {
        this(new byte[]{0x00, 0x00, 0x00});
    }

    public DesfireApplicationId(byte[] id) {
	    this.id = id;
    }

	public void setId(byte[] id) {
		this.id = id;
	}
	
	public byte[] getId() {
		return id;
	}
	
	public int getIdInt() {
		// (uint32_t)(aid->data[0] | aid->data[1] << 8 | aid->data[2] << 16))
	    return (id[0] << 16) + (id[1] << 8) + (id[2] << 0);
	}
	
	public String getIdString() {
		return toHexString(id);
	}
	  
    /**
     * Converts the byte array to HEX string in reverse order.
     * 
     * @param buffer
     *            the buffer.
     * @return the HEX string.
     */
    public static String toHexString(byte[] buffer) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < buffer.length; i++) {
			sb.append(String.format("%02x", buffer[i] & 0xff));
		}
		return sb.toString().toUpperCase(ENGLISH);
    }
	
	@Override
	public void writeToParcel(Parcel dest, int flags) {
		dest.writeInt(id.length);
		dest.writeByteArray(id);
	}
	
	 public void readFromParcel(Parcel in) {
		 id = new byte[in.readInt()];
   	 	 in.readByteArray(id);
	 }
	 
    public static final Creator<DesfireApplicationId> CREATOR = new Creator<DesfireApplicationId>() {
        public DesfireApplicationId createFromParcel(Parcel in) {
       	 
        	DesfireApplicationId item = new DesfireApplicationId();
       	   	item.readFromParcel(in);
            return item;
        }

        public DesfireApplicationId[] newArray(int size) {
            return new DesfireApplicationId[size];
        }
    };


}
