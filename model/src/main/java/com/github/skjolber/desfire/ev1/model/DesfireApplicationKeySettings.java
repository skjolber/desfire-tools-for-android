package com.github.skjolber.desfire.ev1.model;

import java.util.Arrays;

import android.os.Parcel;
import android.os.Parcelable;

import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

public class DesfireApplicationKeySettings implements Parcelable {

	private static final String TAG = DesfireApplicationKeySettings.class.getName();

	/**
	 * 0x0: Authentication with the key to be changed (same keyNo) is necessary to  change a key.
	 * 0x1..0xD: Authentication with the specified key is necessary to change any 
	 * key. A change Key or a PICC master key can only be changed after authentication with the master key. 
	 * For keys other than the master or the change key, an authentication with the same key is needed. 
	 * 0xE : Authentication with the key to be changed (same keyNo) is necessary to change a key.
	 * 0xF : All keys (except application master key, see Bit0) within this application  are frozen. 
	 */
	
	private int changeKeyAccessRights;

	/**
	 * 	CFG CHANGEABLE:
		b0: configuration not changeable anymore (frozen)
		b1: this configuration is changeable if authenticated with the PICC master key
		   (default setting)
	 * 
	 */
	private boolean configurationChangable;
	
	/**
	 * 		FREE CREATE_DELETE:
		b0: Create Application / Delete Application is permitted only with PICC master
		   key authentication.
		b1: Create Application is permitted without PICC master key authentication.
		   Delete Application requires an authentication with PICC master key or ap-
		  plication master key. (default setting)

	 */
	
	private boolean freeCreateAndDelete;
	/**
	 * FREE DIRECTORY ACCESS:
		b0: Successful PICC master key authentication is required for executing the
		   GetApplicationIDs and KetKeySettings commands.
		b1: GetApplicationIDs, GetDFNames and GetKeySettings commands suc-
		   ceed independently of a preceding PICC master key authentication. (de-
		  fault setting)
	 */
	
	private boolean freeDirectoryAccess;
	
	/**
	PMK CHANGEABLE:
	b0: PICC Master Key is not changeable anymore (frozen).
	b1: PICC Master Key is changeable (authentication with the current PICC
	   master key necessary) default setting)
	    */
	private boolean canChangeMasterKey;
	
	/** Number of keys that can be stored within the application for cryptographic purposes. 
	 * A maximum of 14 keys can be stored within an application of DESFire.*/

	private int maxKeys; // unit8 
	
	/**
	bit 5 of byte 1
	b00: NO 2 Byte File Identifiers for files within the application supported
	b01: 2 Byte File Identifiers for files within the application supported
	*/
	
	private boolean twoByteIdentifiers;
	private DesfireKeyType type;
	
	private byte[] settings;
	
	public DesfireApplicationKeySettings(byte[] settings) {
		this.settings = new byte[]{settings[0], settings[1]};
		
		configurationChangable = isConfigurationChangable(settings[0] & 0xFF);
		freeCreateAndDelete = freeCreateAndDelete(settings[0] & 0xFF);
		freeDirectoryAccess = freeDirectoryAccess(settings[0] & 0xFF);
		canChangeMasterKey = canChangeMasterKey(settings[0] & 0xFF);
		
		changeKeyAccessRights = (settings[0] >> 4) & 0xF; // not for PICC application (0x000000)
		
		maxKeys = settings[1] & 0x0F;
		
		twoByteIdentifiers = (settings[1] & 0x20) != 0;
		
		int crypt = (settings[1] >> 6) & 0x3;
		
		switch((settings[1] >> 6) & 0x3) {
			case 0x0 : {
				type = DesfireKeyType.TDES;
				break;
			}
			case 0x1 : {
				type = DesfireKeyType.TKTDES;
				break;
			}
			case 0x2 : {
				type = DesfireKeyType.AES;
				break;
			}
			default : {
				type = DesfireKeyType.NONE;
				break;
			}
		}
		
	}
	
	public DesfireApplicationKeySettings() {
	}
	
	public int getMaxKeys() {
		return maxKeys;
	}
	
	public void setMaxKeys(int maxKeys) {
		this.maxKeys = maxKeys;
	}
	
	public boolean isConfigurationChangable(int settings) {
		return (settings & 0x08) != 0;
	}
	
	public boolean freeCreateAndDelete(int settings) {
		return (settings & 0x04) != 0;
	}

	public boolean freeDirectoryAccess(int settings) {
		return (settings & 0x02) != 0;
	}
	
	public boolean canChangeMasterKey(int settings) {
		return (settings & 0x01) != 0;
	}

	@Override
	public int describeContents() {
		return 0;
	}

	@Override
	public void writeToParcel(Parcel dest, int flags) {
		dest.writeByteArray(settings);
	}
	
    public static final Creator<DesfireApplicationKeySettings> CREATOR = new Creator<DesfireApplicationKeySettings>() {
        public DesfireApplicationKeySettings createFromParcel(Parcel in) {
       	 
        	byte[] settings = new byte[2];
        	in.readByteArray(settings);

        	DesfireApplicationKeySettings item = new DesfireApplicationKeySettings(settings);

            return item;
        }

        public DesfireApplicationKeySettings[] newArray(int size) {
            return new DesfireApplicationKeySettings[size];
        }
    };

	public int getChangeKeyAccessRights() {
		return changeKeyAccessRights;
	}

	public boolean isConfigurationChangable() {
		return configurationChangable;
	}

	public boolean isRequiresMasterKeyForCreateAndDelete() {
		return !freeCreateAndDelete;
	}

	public boolean isRequiresMasterKeyForDirectoryList() {
		return !freeDirectoryAccess;
	}
	
	public boolean isFreeCreateAndDelete() {
		return freeCreateAndDelete;
	}
	
	public boolean isFreeDirectoryAccess() {
		return freeDirectoryAccess;
	}

	public boolean isCanChangeMasterKey() {
		return canChangeMasterKey;
	}

	public boolean isTwoByteIdentifiers() {
		return twoByteIdentifiers;
	}

	public DesfireKeyType getType() {
		return type;
	}

	public byte[] getSettings() {
		return settings;
	}

	@Override
	public String toString() {
		return "DesfireApplicationKeySettings [changeKeyAccessRights=" + changeKeyAccessRights + ", configurationChangable=" + configurationChangable + ", freeCreateAndDelete=" + freeCreateAndDelete
				+ ", freeDirectoryAccess=" + freeDirectoryAccess + ", canChangeMasterKey=" + canChangeMasterKey + ", maxKeys=" + maxKeys + ", twoByteIdentifiers=" + twoByteIdentifiers + ", type="
				+ type + ", settings=" + Arrays.toString(settings) + "]";
	}
    
	
    
}
