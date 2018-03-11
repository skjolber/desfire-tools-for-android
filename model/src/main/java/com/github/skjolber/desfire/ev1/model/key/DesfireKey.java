package com.github.skjolber.desfire.ev1.model.key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import android.os.Parcel;
import android.os.Parcelable;

import com.github.skjolber.desfire.ev1.model.Persistent;

import static java.util.Locale.ENGLISH;

public abstract class DesfireKey implements Parcelable, Persistent, Comparable<DesfireKey> {

	private static final int VERSION = 1;
	
	public static DesfireKey newInstance(DesfireKeyType type, int version) {
		
		DesfireKey key;
		switch(type) {
		case DES: {
			key = new DesfireDESKey();
			break;
		}
		case TDES: {
			key = new Desfire3DESKey();
			break;
		}
		case TKTDES: {
			key = new Desfire3K3DESKey();
			break;
		}
		case AES: {
			key = new DesfireAESKey();
			break;
		}
		default : {
			throw new IllegalArgumentException();
		}
	}
		key.setVersion(version);
		
		return key;
	}
	
	public static DesfireKey fromBytes(byte[] bytes) throws IOException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		
		DataInputStream in = new DataInputStream(byteArrayInputStream);

		int version = in.readInt();
		if(version == VERSION) {
			DesfireKeyType type = DesfireKeyType.getType(in.readInt());

			byteArrayInputStream.reset();
			
			DesfireKey key;
			
			switch(type) {
				case DES: {
					key = new DesfireDESKey();
					break;
				}
				case TDES: {
					key = new Desfire3DESKey();
					break;
				}
				case TKTDES: {
					key = new Desfire3K3DESKey();
					break;
				}
				case AES: {
					key = new DesfireAESKey();
					break;
				}
				default : {
					throw new IllegalArgumentException();
				}
			}
			
			key.read(in);;

			return key;
		} else {
			throw new IllegalArgumentException("Unknown version " + version);
		}
		
	}
	
	public static byte[] toBytes(DesfireKey object) throws IOException {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		
		object.write(new DataOutputStream(bout));
		
		return bout.toByteArray();
	}

	protected int version;
	protected DesfireKeyType type;
	protected Long id;
	protected String name;
	protected byte[] value;
	
	public DesfireKey() {
	}
	
	public DesfireKey(DesfireKeyType type, int version) {
		this.type = type;
		this.version = version;
	}

	public int getVersion() {
		return version;
	}
	
	public void setVersion(int version) {
		this.version = version;
	}
	
	public DesfireKeyType getType() {
		return type;
	}
	
	public void setType(DesfireKeyType type) {
		this.type = type;
	}
	
	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public void writeToParcel(Parcel dest, int flags) {
		dest.writeInt(type.getId());
		dest.writeInt(version);
		
		if(id != null) {
			dest.writeByte((byte)1);
			dest.writeLong(id);
		} else {
			dest.writeByte((byte) 0);
		}
		
		if(name != null) {
			dest.writeByte((byte)1);
			dest.writeString(name);
		} else {
			dest.writeByte((byte) 0);
		}
	}

	protected void readFromParcel(Parcel in) {
		setType(DesfireKeyType.getType(in.readInt()));
    	setVersion(in.readInt());

    	if(in.readByte() != 0) {
    		id = in.readLong();
    	}
    	
    	if(in.readByte() != 0) {
    		name = in.readString();
    	}
	}
	
	public Long getId() {
		return id;
	}
	
	public void setId(Long id) {
		this.id = id;
	}

    public void setName(String name) {
		this.name = name;
	}
    
    public String getName() {
		return name;
	}
    
    public byte[] toBytes() throws IOException {
    	return toBytes(this);
    }

	@Override
	public void read(DataInputStream in) throws IOException {
		int version = in.readInt();
		if(version == VERSION) {
			setType(DesfireKeyType.getType(in.readInt()));
	    	setVersion(in.readInt());
	
	    	if(in.readByte() != 0) {
	    		id = in.readLong();
	    	}
	    	
	    	if(in.readByte() != 0) {
	    		name = in.readUTF();
	    	}		
		} else {
			throw new IllegalArgumentException("Unknown version " + version);
		}
	}

	@Override
	public void write(DataOutputStream dest) throws IOException {
		dest.writeInt(VERSION);
		dest.writeInt(type.getId());
		dest.writeInt(version);
		
		if(id != null) {
			dest.writeByte((byte)1);
			dest.writeLong(id);
		} else {
			dest.writeByte((byte) 0);
		}
		
		if(name != null) {
			dest.writeByte((byte)1);
			dest.writeUTF(name);
		} else {
			dest.writeByte((byte) 0);
		}

		
	}

	@Override
	public int compareTo(DesfireKey rhs) {
		
		int compare = getType().compareTo(rhs.getType());
		
		if(compare == 0) {
			
			compare = getName().compareTo(rhs.getName());
			
			if(compare == 0) {
				return (getVersion() < rhs.getVersion() ? -1 : (getVersion() == rhs.getVersion() ? 0 : 1));
			}
		}
		
		return compare;
	}
	
	public String getVersionAsHexString() {
		return Integer.toHexString(version).toUpperCase(ENGLISH);
	}
	
	public abstract void setValue(byte[] value);
	
	public byte[] getValue() {
		return value;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		result = prime * result + Arrays.hashCode(value);
		result = prime * result + version;
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
		DesfireKey other = (DesfireKey) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (type != other.type)
			return false;
		if (!Arrays.equals(value, other.value))
			return false;
		if (version != other.version)
			return false;
		return true;
	}

	
}
 