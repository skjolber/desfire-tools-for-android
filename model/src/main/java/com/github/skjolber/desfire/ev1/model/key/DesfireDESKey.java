package com.github.skjolber.desfire.ev1.model.key;

import android.os.Parcel;
import android.os.Parcelable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class DesfireDESKey extends DesfireKey {

	public static DesfireDESKey defaultVersionNull = new DesfireDESKey("DES null", 0x01, new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
	public static DesfireDESKey defaultVersionAA = new DesfireDESKey("Default DES", 0xAA, new byte[]{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' });

	public DesfireDESKey() {
		type = DesfireKeyType.DES;
	}
	public DesfireDESKey(String name, int version, byte[] value) {
		this();
		
		this.name = name;
		this.version = version;
		this.value = value;
	}
	
	public DesfireDESKey(byte[] value) {
		if(value.length != 8) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}

	public void setValue(byte[] value) {
		if(value != null && value.length != 8) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}
	
	public void read(DataInputStream in) throws IOException {
		super.read(in);
		
		value = new byte[8];
		in.readFully(value);
	}

	@Override
	public void write(DataOutputStream dest) throws IOException {
		super.write(dest);
		
		dest.write(value);
	}

    public static final Parcelable.Creator<DesfireDESKey> CREATOR
            = new Parcelable.Creator<DesfireDESKey>() {
        public DesfireDESKey createFromParcel(Parcel in) {
            return new DesfireDESKey(in);
        }

        public DesfireDESKey[] newArray(int size) {
            return new DesfireDESKey[size];
        }
    };

    private DesfireDESKey(Parcel in) {
        readFromParcel(in);
    }

}
