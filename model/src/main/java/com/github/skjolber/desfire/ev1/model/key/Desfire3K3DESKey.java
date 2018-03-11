package com.github.skjolber.desfire.ev1.model.key;

import android.os.Parcel;
import android.os.Parcelable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class Desfire3K3DESKey extends DesfireKey {

	public static Desfire3K3DESKey defaultVersionNull = new Desfire3K3DESKey("3K 3DES null", 0x01, new byte[24]);
	public static Desfire3K3DESKey defaultVersion55 = new Desfire3K3DESKey("Default 3K 3DES", 0x55, new byte[]{ 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
	
	public Desfire3K3DESKey(String name, int version, byte[] value) {
		this();
		
		this.name = name;

		this.version = version;
		
		if(value.length != 24) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}

	public Desfire3K3DESKey() {
		this.type = DesfireKeyType.TKTDES;
	}

	public void setValue(byte[] value) {
		if(value != null && value.length != 24) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}
	
	public void read(DataInputStream in) throws IOException {
		super.read(in);
		
		value = new byte[24];
		in.readFully(value);
	}

	@Override
	public void write(DataOutputStream dest) throws IOException {
		super.write(dest);
		
		dest.write(value);
	}

    public static final Parcelable.Creator<Desfire3K3DESKey> CREATOR
            = new Parcelable.Creator<Desfire3K3DESKey>() {
        public Desfire3K3DESKey createFromParcel(Parcel in) {
            return new Desfire3K3DESKey(in);
        }

        public Desfire3K3DESKey[] newArray(int size) {
            return new Desfire3K3DESKey[size];
        }
    };

    private Desfire3K3DESKey(Parcel in) {
        readFromParcel(in);
    }
}
