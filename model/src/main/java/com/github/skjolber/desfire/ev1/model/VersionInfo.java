package com.github.skjolber.desfire.ev1.model;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

import android.os.Parcel;
import android.os.Parcelable;

// https://code.google.com/p/nfc-tools/source/browse/trunk/libfreefare/examples/mifare-desfire-info.c?r=751

public class VersionInfo implements Parcelable {

	private int hardwareVendorId;
	private int hardwareType;
	private int hardwareSubtype;
	private int hardwareVersionMajor;
	private int hardwareVersionMinor;
	private int hardwareStorageSize;
	private int hardwareProtocol;
	
	private int softwareVendorId;
	private int softwareType;
	private int softwareSubtype;
	private int softwareVersionMajor;
	private int softwareVersionMinor;
	private int softwareStorageSize;
	private int softwareProtocol;
	
    byte[] uid = new byte[7]; // [7];
    byte[] batchNumber = new byte[5]; //[5];
    private int productionWeek;
    private int productionYear;		

	public VersionInfo() {
	}

	public VersionInfo(byte[] bytes) throws IOException {
		read(bytes);
	}

	public void read(byte[] bytes) throws IOException {
		DataInputStream din = new DataInputStream(new ByteArrayInputStream(bytes));
		
		hardwareVendorId = din.read();
		hardwareType = din.read();
		hardwareSubtype = din.read();
		hardwareVersionMajor = din.read();
		hardwareVersionMinor = din.read();
		hardwareStorageSize = din.read();
		hardwareProtocol = din.read();
		
		softwareVendorId = din.read();
		softwareType = din.read();
		softwareSubtype = din.read();
		softwareVersionMajor = din.read();
		softwareVersionMinor = din.read();
		softwareStorageSize = din.read();
		softwareProtocol = din.read();
				
		din.readFully(uid);
		din.readFully(batchNumber);
		
		productionWeek = din.read();
		productionYear = din.read();
	}
	
	public String getHardwareVersion() {
		return hardwareVersionMajor + "." + hardwareVersionMinor;
	}

	public String getSoftwareVersion() {
		return softwareVersionMajor + "." + softwareVersionMinor;
	}

	public int getHardwareVendorId() {
		return hardwareVendorId;
	}

	public void setHardwareVendorId(int hardwareVendorId) {
		this.hardwareVendorId = hardwareVendorId;
	}

	public int getHardwareType() {
		return hardwareType;
	}

	public void setHardwareType(int hardwareType) {
		this.hardwareType = hardwareType;
	}

	public int getHardwareSubtype() {
		return hardwareSubtype;
	}

	public void setHardwareSubtype(int hardwareSubtype) {
		this.hardwareSubtype = hardwareSubtype;
	}

	public int getHardwareVersionMajor() {
		return hardwareVersionMajor;
	}

	public void setHardwareVersionMajor(int hardwareVersionMajor) {
		this.hardwareVersionMajor = hardwareVersionMajor;
	}

	public int getHardwareVersionMinor() {
		return hardwareVersionMinor;
	}

	public void setHardwareVersionMinor(int hardwareVersionMinor) {
		this.hardwareVersionMinor = hardwareVersionMinor;
	}

	public int getHardwareStorageSize() {
		if((hardwareStorageSize & 1) > 0) {
			// > 
		} else {
			// =
		}
		
		return (int)Math.pow (2, hardwareStorageSize >> 1);
		
		//return String.format("%s%d", ((hardwareStorageSize & 1) > 0 ? ">" : "="), (int)pow (2, hardwareStorageSize >> 1));
	}

	public void setHardwareStorageSize(int hardwareStorageSize) {
		this.hardwareStorageSize = hardwareStorageSize;
	}

	public int getHardwareProtocol() {
		return hardwareProtocol;
	}

	public void setHardwareProtocol(int hardwareProtocol) {
		this.hardwareProtocol = hardwareProtocol;
	}

	public int getSoftwareVendorId() {
		return softwareVendorId;
	}

	public void setSoftwareVendorId(int softwareVendorId) {
		this.softwareVendorId = softwareVendorId;
	}

	public int getSoftwareType() {
		return softwareType;
	}

	public void setSoftwareType(int softwareType) {
		this.softwareType = softwareType;
	}

	public int getSoftwareSubtype() {
		return softwareSubtype;
	}

	public void setSoftwareSubtype(int softwareSubtype) {
		this.softwareSubtype = softwareSubtype;
	}

	public int getSoftwareVersionMajor() {
		return softwareVersionMajor;
	}

	public void setSoftwareVersionMajor(int softwareVersionMajor) {
		this.softwareVersionMajor = softwareVersionMajor;
	}

	public int getSoftwareVersionMinor() {
		return softwareVersionMinor;
	}

	public void setSoftwareVersionMinor(int softwareVersionMinor) {
		this.softwareVersionMinor = softwareVersionMinor;
	}

	public int getSoftwareStorageSize() {
		return (int)Math.pow (2, softwareStorageSize >> 1);
	}

	public void setSoftwareStorageSize(int softwareStorageSize) {
		this.softwareStorageSize = softwareStorageSize;
	}

	public int getSoftwareProtocol() {
		return softwareProtocol;
	}

	public void setSoftwareProtocol(int softwareProtocol) {
		this.softwareProtocol = softwareProtocol;
	}

	public byte[] getUid() {
		return uid;
	}

	public void setUid(byte[] uid) {
		this.uid = uid;
	}

	public byte[] getBatchNumber() {
		return batchNumber;
	}

	public void setBatchNumber(byte[] batchNumber) {
		this.batchNumber = batchNumber;
	}

	public int getProductionWeek() {
		return productionWeek;
	}

	public void setProductionWeek(int productionWeek) {
		this.productionWeek = productionWeek;
	}

	public int getProductionYear() {
		return productionYear;
	}

	public void setProductionYear(int productionYear) {
		this.productionYear = productionYear;
	}
	
	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public void writeToParcel(Parcel dest, int flags) {
		dest.writeInt(hardwareVendorId);
		dest.writeInt(hardwareType);
		dest.writeInt(hardwareSubtype);
		dest.writeInt(hardwareVersionMajor);
		dest.writeInt(hardwareVersionMinor);
		dest.writeInt(hardwareStorageSize);
		dest.writeInt(hardwareProtocol);
		
		dest.writeInt(softwareVendorId);
		dest.writeInt(softwareType);
		dest.writeInt(softwareSubtype);
		dest.writeInt(softwareVersionMajor);
		dest.writeInt(softwareVersionMinor);
		dest.writeInt(softwareStorageSize);
		dest.writeInt(softwareProtocol);

		dest.writeInt(uid.length);
		dest.writeByteArray(uid);
		
		dest.writeInt(batchNumber.length);
		dest.writeByteArray(batchNumber);
		
		dest.writeInt(productionWeek);
		dest.writeInt(productionYear);
	}
	
    public static final Creator<VersionInfo> CREATOR = new Creator<VersionInfo>() {
        public VersionInfo createFromParcel(Parcel din) {
       	 
        	VersionInfo item = new VersionInfo();
       	
        	item.hardwareVendorId = din.readInt();
        	item.hardwareType = din.readInt();
        	item.hardwareSubtype = din.readInt();
        	item.hardwareVersionMajor = din.readInt();
        	item.hardwareVersionMinor = din.readInt();
        	item.hardwareStorageSize = din.readInt();
        	item.hardwareProtocol = din.readInt();
    		
        	item.softwareVendorId = din.readInt();
        	item.softwareType = din.readInt();
        	item.softwareSubtype = din.readInt();
        	item.softwareVersionMajor = din.readInt();
        	item.softwareVersionMinor = din.readInt();
        	item.softwareStorageSize = din.readInt();
        	item.softwareProtocol = din.readInt();
    			
        	item.uid = new byte[din.readInt()];
        	din.readByteArray(item.uid);

        	item.batchNumber = new byte[din.readInt()];
        	din.readByteArray(item.batchNumber);

        	item.productionWeek = din.readInt();
        	item.productionYear = din.readInt();
       	 
            return item;
        }

        public VersionInfo[] newArray(int size) {
            return new VersionInfo[size];
        }
    };

}
