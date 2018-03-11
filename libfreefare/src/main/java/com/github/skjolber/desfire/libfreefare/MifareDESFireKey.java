package com.github.skjolber.desfire.libfreefare;

import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

import javax.crypto.spec.SecretKeySpec;

public class MifareDESFireKey {

	private byte[] data = new byte[24];
    private DesfireKeyType type;
	private byte[] cmac_sk1 = new byte[24];
	private byte[] cmac_sk2 = new byte[24];
    private byte aes_version;
    
    private byte[] ks1 = new byte[8];
    private byte[] ks2 = new byte[8];
    private byte[] ks3 = new byte[8];
    
    private SecretKeySpec secretKeySpec;
	
	public byte[] getCmac_sk1() {
		return cmac_sk1;
	}

	public void setCmac_sk1(byte[] cmac_sk1) {
		this.cmac_sk1 = cmac_sk1;
	}

	public byte[] getCmac_sk2() {
		return cmac_sk2;
	}

	public void setCmac_sk2(byte[] cmac_sk2) {
		this.cmac_sk2 = cmac_sk2;
	}

	public DesfireKeyType getType() {
		return type;
	}
	
	public void setType(DesfireKeyType type) {
		this.type = type;
		
		this.secretKeySpec = null;
	}
	
	public byte[] getData() {
		return data;
	}

	public void setData(byte[] key) {
		this.data = key;
		
		this.secretKeySpec = null;
	}

	public void setVersion(byte version) {
		this.aes_version = version;
		
		this.secretKeySpec = null;
	}

	public SecretKeySpec toKey() {
		if(secretKeySpec == null) {
			if(type == DesfireKeyType.AES) {
				secretKeySpec = new SecretKeySpec(data, 0, 16, "AES");
			} else {
				throw new IllegalArgumentException();
			}
		}
		return secretKeySpec;
	}

	public byte[] getKs1() {
		return ks1;
	}

	public void setKs1(byte[] ks1) {
		this.ks1 = ks1;
	}

	public byte[] getKs2() {
		return ks2;
	}

	public void setKs2(byte[] ks2) {
		this.ks2 = ks2;
	}

	public byte[] getKs3() {
		return ks3;
	}

	public void setKs3(byte[] ks3) {
		this.ks3 = ks3;
	}

	public void setAESVersion(byte version) {
		this.aes_version = version;
	}

	public byte getAESVersion() {
		return aes_version;
	}
	
}
