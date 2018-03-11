package com.github.skjolber.desfire.ev1.model;

import java.util.ArrayList;
import java.util.List;

import android.os.Parcel;
import android.os.Parcelable;

public class DesfireTag implements Parcelable {

	public static final int MAX_APPLICATION_COUNT = 28;
	
	private List<DesfireApplication> applications = new ArrayList<DesfireApplication>();
	
	private VersionInfo versionInfo;

	public List<DesfireApplication> getApplications() {
		return applications;
	}

	public void setApplications(List<DesfireApplication> applications) {
		this.applications = applications;
	}

	public VersionInfo getVersionInfo() {
		return versionInfo;
	}
	
	public void add(DesfireApplication application) {
		this.applications.add(application);
	}

	public void setVersionInfo(VersionInfo versionInfo) {
		this.versionInfo = versionInfo;
	}
	
	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public void writeToParcel(Parcel dest, int flags) {
		
		dest.writeInt(applications.size());
		for(DesfireApplication application : applications) {
			dest.writeParcelable(application, flags);
		}
		
		if(versionInfo != null) {
			dest.writeByte((byte)0x01);
			dest.writeParcelable(versionInfo, flags);
		} else {
			dest.writeByte((byte)0x00);
		}
	}
	
    public static final Creator<DesfireTag> CREATOR = new Creator<DesfireTag>() {
        public DesfireTag createFromParcel(Parcel in) {
       	 
        	DesfireTag item = new DesfireTag();

        	int count = in.readInt();
        	for(int i = 0; i < count; i++) {
        		item.add((DesfireApplication) in.readParcelable(getClass().getClassLoader()));
        	}
        	
        	if(in.readByte() == 1) {
        		item.setVersionInfo((VersionInfo) in.readParcelable(getClass().getClassLoader()));
        	}
        	
            return item;
        }

        public DesfireTag[] newArray(int size) {
            return new DesfireTag[size];
        }
    };

}
