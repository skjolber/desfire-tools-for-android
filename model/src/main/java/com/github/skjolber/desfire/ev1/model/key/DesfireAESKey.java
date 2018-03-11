package com.github.skjolber.desfire.ev1.model.key;

import android.os.Parcel;
import android.os.Parcelable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class DesfireAESKey extends DesfireKey {

	public static DesfireAESKey defaultVersionNull = new DesfireAESKey("AES null", 0x01, new byte[16]);
	public static DesfireAESKey defaultVersion42 = new DesfireAESKey("Default AES", 0x42, new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
	
	public DesfireAESKey(String name, int version, byte[] value) {
		this();
		
		this.name = name;

		this.version = version;
		
		if(value.length != 16) {
			throw new IllegalArgumentException();
		}
		this.value = value;
	}

	public DesfireAESKey() {
		this.type = DesfireKeyType.AES;
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

    public static final Parcelable.Creator<DesfireAESKey> CREATOR
            = new Parcelable.Creator<DesfireAESKey>() {
        public DesfireAESKey createFromParcel(Parcel in) {
            return new DesfireAESKey(in);
        }

        public DesfireAESKey[] newArray(int size) {
            return new DesfireAESKey[size];
        }
    };

    private DesfireAESKey(Parcel in) {
        readFromParcel(in);
    }
}
