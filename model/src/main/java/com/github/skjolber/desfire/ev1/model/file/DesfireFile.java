package com.github.skjolber.desfire.ev1.model.file;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import android.annotation.SuppressLint;
import android.os.Parcel;
import android.os.Parcelable;

public abstract class DesfireFile extends DesfireFileId {

    /**
     * <p>Reverses the order of the given array.</p>
     *
     * <p>This method does nothing for a <code>null</code> input array.</p>
     *
     * @param array  the array to reverse, may be <code>null</code>
     */
    public static void reverse(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
    }

    public static int byteArrayToInt(byte[] b) {
        return byteArrayToInt(b, 0);
    }

    public static int byteArrayToInt(byte[] b, int offset) {
        return byteArrayToInt(b, offset, b.length);
    }

    public static int byteArrayToInt(byte[] b, int offset, int length) {
        return (int) byteArrayToLong(b, offset, length);
    }

    public static long byteArrayToLong(byte[] b, int offset, int length) {
        if (b.length < length)
            throw new IllegalArgumentException("length must be less than or equal to b.length");

        long value = 0;
        for (int i = 0; i < length; i++) {
            int shift = (length - 1 - i) * 8;
            value += (b[i + offset] & 0x000000FF) << shift;
        }
        return value;
    }

    @SuppressLint("ParcelCreator")
	public static DesfireFile newInstance (int id, byte[] settings) throws Exception {
    	DesfireFileType fileType = DesfireFileType.getType(settings[0]);

        ByteArrayInputStream stream = new ByteArrayInputStream(settings);

        if (fileType == DesfireFileType.STANDARD_DATA_FILE || fileType == DesfireFileType.BACKUP_DATA_FILE)
            return new StandardDesfireFile(id, stream);
        else if (fileType == DesfireFileType.LINEAR_RECORD_FILE || fileType == DesfireFileType.CYCLIC_RECORD_FILE)
            return new RecordDesfireFile(id, stream);
        else if (fileType == DesfireFileType.VALUE_FILE)
            return new ValueDesfireFile(id, stream); 
        else
           return new UnsupportedDesfireFile(id, stream);
    }

    protected DesfireFileType fileType;
    protected DesfireFileCommunicationSettings communicationSettings;
    
    protected int readAccessKey = -1;
    protected int writeAccessKey = -1;
    protected int readWriteAccessKey = -1;
    protected int changeAccessKey = -1;

    public DesfireFileType getFileType() {
		return fileType;
	}
    
    protected void read(ByteArrayInputStream settings) {
        this.fileType    = DesfireFileType.getType(settings.read());
        this.communicationSettings = DesfireFileCommunicationSettings.parse(settings.read());

        int access1 = settings.read();

        this.readWriteAccessKey = (access1 & 0xF0) >> 4;
        this.changeAccessKey = access1 & 0x0F;

        int access2 = settings.read();
        
        this.readAccessKey = (access2 & 0xF0) >> 4;
        this.writeAccessKey = access2 & 0x0F;
    }

    protected DesfireFile (int id, DesfireFileType fileType, byte communicationSettings, int readAccessKey, int writeAccessKey, int readWriteAccessKey, int changeAccessKey) {
    	this.id = id;
        this.fileType     = fileType;
        this.communicationSettings  = DesfireFileCommunicationSettings.parse(communicationSettings);
        this.readAccessKey = readAccessKey;
        this.writeAccessKey = writeAccessKey;
        this.readWriteAccessKey = readWriteAccessKey;
        this.changeAccessKey = changeAccessKey;
    }

    public DesfireFile() {
	}

	public String getFileTypeName () {
        switch (fileType) {
            case STANDARD_DATA_FILE:
                return "Standard";
            case BACKUP_DATA_FILE:
                return "Backup";
            case VALUE_FILE:
                return "Value";
            case LINEAR_RECORD_FILE:
                return "Linear Record";
            case CYCLIC_RECORD_FILE:
                return "Cyclic Record";
            default:
                return "Unknown";
        }
    }
   
    public void readFromParcel(Parcel source) {
    	super.readFromParcel(source);
        this.fileType = DesfireFileType.getType(source.readInt());
        this.communicationSettings = DesfireFileCommunicationSettings.parse(source.readByte());
        
        this.readAccessKey = source.readInt();
        this.writeAccessKey = source.readInt();
        this.readWriteAccessKey = source.readInt();
        this.changeAccessKey = source.readInt();
    }

    public void writeToParcel (Parcel parcel, int flags) {
    	super.writeToParcel(parcel, flags);
        parcel.writeInt(fileType.getId());
        parcel.writeByte((byte) communicationSettings.getValue());
        
        parcel.writeInt(readAccessKey);
        parcel.writeInt(writeAccessKey);
        parcel.writeInt(readWriteAccessKey);
        parcel.writeInt(changeAccessKey);
    }

    public int describeContents () {
        return 0;
    }

    public int getChangeAccessKey() {
		return changeAccessKey;
	}
    
    public int getReadAccessKey() {
		return readAccessKey;
	}
    
    public int getReadWriteAccessKey() {
		return readWriteAccessKey;
	}
    
    public int getWriteAccessKey() {
		return writeAccessKey;
	}

    public boolean freeReadAccess() {
    	return getReadAccessKey() == 0xE || getReadWriteAccessKey() == 0xE;
    }
    
    public boolean freeWriteAccess() {
    	return getWriteAccessKey() == 0xE || getReadWriteAccessKey() == 0xE;
    }

    public boolean freeChangeAccess() {
    	return getChangeAccessKey() == 0xE;
    }

    /**
     * Desfire key 0x0 to 0xD
     * Plain 00h 
     * Plain communication secured by DES/3K3DES/AES MACing 01h
     * RFU 10h 
     * Fully DES/3DES/3K3DES/AES enciphered communication 11h
     * Desfire key 0xE: Plain for all settings
     * 
     * 
     * @return
     */
    
    public DesfireFileCommunicationSettings getCommunicationSettings() {
    	return communicationSettings;
	}

	@Override
	public String toString() {
		return getClass().getName() + " [fileType=" + fileType + ", communicationSettings=" + communicationSettings + ", readAccessKey=" + readAccessKey + ", writeAccessKey=" + writeAccessKey
				+ ", readWriteAccessKey=" + readWriteAccessKey + ", changeAccessKey=" + changeAccessKey + "]";
	}

	private Set<String>[] getPermissionSets() {
		Set<String>[] rights = new Set[16];
		
		int readAccessKey = getReadAccessKey();
		rights[readAccessKey] = new HashSet<String>();
		rights[readAccessKey].add("R");
		
		int readWriteAccessKey = getReadWriteAccessKey();
		if(rights[readWriteAccessKey] == null) {
			rights[readWriteAccessKey] = new HashSet<String>();
		}
		rights[readWriteAccessKey].add("R");
		rights[readWriteAccessKey].add("W");

		int writeAccessKey = getWriteAccessKey();
		if(rights[writeAccessKey] == null) {
			rights[writeAccessKey] = new HashSet<String>();
		}
		rights[writeAccessKey].add("W");

		int changeAccessKey = getChangeAccessKey();
		if(rights[changeAccessKey] == null) {
			rights[changeAccessKey] = new HashSet<String>();
		}
		rights[changeAccessKey].add("C");
		
		return rights;
	}
	
	public Map<Integer, String> getCompactPermissionMap() {
		Set<String>[] rights = getPermissionSets();
		
		Map<Integer, String> permissions = new HashMap<Integer, String>();
		
		for(int i = 0; i < rights.length; i++) {
			if(rights[i] != null) {
				StringBuffer buffer = new StringBuffer();
				if(rights[i].contains("R")) {
					buffer.append("R");
				}
				if(rights[i].contains("W")) {
					buffer.append("W");
				}
				if(rights[i].contains("C")) {
					buffer.append("C");
				}
				permissions.put(i, buffer.toString());
			}
		}
		
		return permissions;
	}
	
	public boolean isFreeChangeAccess() {
		return changeAccessKey == 0xE;
	}

	public boolean isFreeWriteAccess() {
		return writeAccessKey == 0xE;
	}

	public boolean isFreeReadAccess() {
		return readAccessKey == 0xE;
	}

	public boolean isFreeReadWriteAccess() {
		return readWriteAccessKey == 0xE;
	}

    public boolean isReadAccess(int index) {
    	return readAccessKey == index || readWriteAccessKey == index;
    }
    
    public boolean isChangeAccess(int index) {
    	return changeAccessKey == index;
    }
    
    public boolean isWriteAccess(int index) {
    	return writeAccessKey == index || readWriteAccessKey == index;
    }
    
    public boolean isReadWriteAccess(int index) {
    	return readWriteAccessKey == index;
    }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + changeAccessKey;
		result = prime * result + ((communicationSettings == null) ? 0 : communicationSettings.hashCode());
		result = prime * result + ((fileType == null) ? 0 : fileType.hashCode());
		result = prime * result + readAccessKey;
		result = prime * result + readWriteAccessKey;
		result = prime * result + writeAccessKey;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		DesfireFile other = (DesfireFile) obj;
		if (changeAccessKey != other.changeAccessKey)
			return false;
		if (communicationSettings != other.communicationSettings)
			return false;
		if (fileType != other.fileType)
			return false;
		if (readAccessKey != other.readAccessKey)
			return false;
		if (readWriteAccessKey != other.readWriteAccessKey)
			return false;
		if (writeAccessKey != other.writeAccessKey)
			return false;
		return true;
	}

	public abstract boolean isContent();
    
}
