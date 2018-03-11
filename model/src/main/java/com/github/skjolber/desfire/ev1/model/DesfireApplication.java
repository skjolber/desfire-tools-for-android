package com.github.skjolber.desfire.ev1.model;

import java.util.ArrayList;
import java.util.List;

import android.os.Parcel;
import android.os.Parcelable;

import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

public class DesfireApplication extends DesfireApplicationId {

	public static final int MAX_FILE_COUNT = 32;

	private List<DesfireFile> files = new ArrayList<DesfireFile>();
	
	private DesfireApplicationKeySettings keySettings;
	
	private DesfireKeyType security;
	
	private List<DesfireApplicationKey> keys = new ArrayList<DesfireApplicationKey>();
	
	public boolean hasFiles() {
		return !files.isEmpty();
	}

	public boolean hasKeys() {
		return !keys.isEmpty();
	}

	public List<DesfireApplicationKey> getKeys() {
		return keys;
	}
	
	public void setKeys(List<DesfireApplicationKey> keys) {
		this.keys = keys;
	}
	
	public List<DesfireFile> getFiles() {
		return files;
	}

	public void setFiles(List<DesfireFile> files) {
		this.files = files;
	}

	public DesfireApplicationKeySettings getKeySettings() {
		return keySettings;
	}
	
	public void setKeySettings(DesfireApplicationKeySettings keySettings) {
		this.keySettings = keySettings;
	}
	
	public DesfireKeyType getSecurity() {
		return security;
	}
	
	public void setSecurity(DesfireKeyType security) {
		this.security = security;
	}

	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public void writeToParcel(Parcel dest, int flags) {
		super.writeToParcel(dest, flags);
		dest.writeInt(files.size());
		for(DesfireFile file : files) {
			dest.writeParcelable(file, flags);
		}
		
		if(keySettings != null) {
			dest.writeByte((byte)0x01);
			dest.writeParcelable(keySettings, flags);
		} else {
			dest.writeByte((byte)0x00);
		}
	}
	
	 public void readFromParcel(Parcel in) {
    	super.readFromParcel(in);
    	
   	 	int count = in.readInt();
   	 	for(int i = 0; i < count; i++) {
   	 		add((DesfireFile)in.readParcelable(getClass().getClassLoader()));
   	 	}
   	 	
   	 	if(in.readByte() == 0x01) {
   	 		setKeySettings((DesfireApplicationKeySettings)in.readParcelable(getClass().getClassLoader()));
   	 	}

	 }
	 
    public static final Parcelable.Creator<DesfireApplication> CREATOR = new Parcelable.Creator<DesfireApplication>() {
        public DesfireApplication createFromParcel(Parcel in) {
       	 
        	DesfireApplication item = new DesfireApplication();

        	item.readFromParcel(in);
        	
            return item;
        }

        public DesfireApplication[] newArray(int size) {
            return new DesfireApplication[size];
        }
    };
    
	public void add(DesfireFile file) {
		this.files.add(file);
	}

	public void add(DesfireApplicationKey key) {
		this.keys.add(key);
	}

}
