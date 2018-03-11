package com.github.skjolber.desfire.ev1.model.key.session;

import com.github.skjolber.desfire.ev1.model.key.DesfireKey;


public abstract class DesfireSessionKey<T extends DesfireKey> {
	
	protected T key;
	
	protected byte[] data;
	
	protected byte[] cmacSK1 = new byte[24];
	protected byte[] cmacSK2 = new byte[24];
    
	public byte[] getCmacSK1() {
		return cmacSK1;
	}
	
	public byte[] getCmacSK2() {
		return cmacSK2;
	}
	
	public void setCmacSK1(byte[] cmacSK1) {
		this.cmacSK1 = cmacSK1;
	}
	
	public void setCmacSK2(byte[] cmacSK2) {
		this.cmacSK2 = cmacSK2;
	}
	
	public byte[] getData() {
		return data;
	}
	
	public void setData(byte[] data) {
		this.data = data;
	}
	
	public T getKey() {
		return key;
	}
	
	public abstract byte[] encrypt(byte[] encrypt) throws Exception;
	
	public abstract byte[] decrypt(byte[] decrypt) throws Exception;

	public abstract DesfireSessionKey<T> newKey(byte[] rnda, byte[] rndb) throws Exception;
	
}
