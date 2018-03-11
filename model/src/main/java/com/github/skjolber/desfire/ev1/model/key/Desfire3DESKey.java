package com.github.skjolber.desfire.ev1.model.key;

import android.os.Parcel;
import android.os.Parcelable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Desfire3DESKey extends DesfireKey {

	public static Desfire3DESKey defaultVersionNull = new Desfire3DESKey("3DES null", 0x01, new byte[16]);
	public static Desfire3DESKey defaultVersionC7 = new Desfire3DESKey("Default 3DES", 0xC7, new byte[]{ 'C', 'a', 'r', 'd', ' ', 'M', 'a', 's', 't', 'e', 'r', ' ', 'K', 'e', 'y', '!' });
	
	public Desfire3DESKey(String name, int version, byte[] value) {
		this();
	
		this.name = name;

		this.version = version;
		
		if(value.length != 16) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}

	public Desfire3DESKey() {
		this.type = DesfireKeyType.TDES;
	}

	public void setValue(byte[] value) {
		if(value != null && value.length != 16) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}
		
	public void read(DataInputStream in) throws IOException {
		super.read(in);
		
		value = new byte[16];
		in.readFully(value);
	}

	@Override
	public void write(DataOutputStream dest) throws IOException {
		super.write(dest);
		
		dest.write(value);
	}

    public static final Parcelable.Creator<Desfire3DESKey> CREATOR
            = new Parcelable.Creator<Desfire3DESKey>() {
        public Desfire3DESKey createFromParcel(Parcel in) {
            return new Desfire3DESKey(in);
        }

        public Desfire3DESKey[] newArray(int size) {
            return new Desfire3DESKey[size];
        }
    };

    private Desfire3DESKey(Parcel in) {
        readFromParcel(in);
    }
}
