package com.github.skjolber.desfire.libfreefare;

import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;

public class MifareTag {
	
	private DefaultIsoDepAdapter io;
	
	private byte last_picc_error;
	private byte last_internal_error;
	private byte last_pcd_error;
	private MifareDESFireKey session_key;
	private AuthenticationScheme authentication_scheme;
	private int authenticated_key_no;
	private byte[] ivect = new byte[AESCrypto.MAX_CRYPTO_BLOCK_SIZE];
	private byte[] cmac = new byte[16];
	private byte[] crypto_buffer;
	private int selected_application;
	private int active;
	
	public MifareTag() {
	}
	
	public byte[] getInitializationVector() {
		return ivect;
	}
	
	public MifareDESFireKey getSessionKey() {
		return session_key;
	}
	
	public void setSelectedApplication(int aid) {
		this.selected_application = aid;
	}
	
	public int getSelectedApplication() {
		return selected_application;
	}

	public void setSessionKey(MifareDESFireKey session_key) {
		this.session_key = session_key;
	}

	public AuthenticationScheme getAuthenticationScheme() {
		return authentication_scheme;
	}

	public byte[] getCMAC() {
		return cmac;
	}
	
	public void setAuthenticatedKeyNumber(int no) {
		this.authenticated_key_no = no;
	}

	public void setAuthenticationScheme(AuthenticationScheme scheme) {
		this.authentication_scheme = scheme;
	}
	
	public void setLastPCDError(byte error) {
		this.last_pcd_error = error;
	}

	public void setLastPICCError(byte error) {
		this.last_picc_error = error;
	}

	public void initializeCryptoBuffer(int size) {
		crypto_buffer = new byte[size];
	}

	public byte[] getCryptoBuffer() {
		return crypto_buffer;
	}

	public void setCryptoBuffer(byte[] crypto_buffer) {
		this.crypto_buffer = crypto_buffer;
	}

	public int getAuthenticatedKeyNo() {
		return authenticated_key_no;
	}
	
	public void setActive(int active) {
		this.active = active;
	}
	
	public int getActive() {
		return active;
	}
	
	public DefaultIsoDepAdapter getIo() {
		return io;
	}
	
	public void setIo(DefaultIsoDepAdapter io) {
		this.io = io;
	}

	public void setCMAC(byte[] cmac) {
		this.cmac = cmac;
	}

	public void setInitializationVector(byte[] ivect) {
		this.ivect = ivect;
	}

	public boolean hasSessionKey() {
		return session_key != null;
	}
}