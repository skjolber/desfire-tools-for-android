package com.skjolberg.mifare.desfiretool.filelist;


import com.github.skjolber.desfire.ev1.model.DesfireApplicationKey;

public class ApplicationDetailApplicationKey implements ApplicationDetail {

	private String title;
	private String description;
	private DesfireApplicationKey key;
	
	public String getDescription() {
		return description;
	}
	
	public String getTitle() {
		return title;
	}

	public ApplicationDetailApplicationKey(String title, String description, DesfireApplicationKey key) {
		this.title = title;
		this.description = description;
		this.key = key;
	}
	
	public DesfireApplicationKey getKey() {
		return key;
	}
}
