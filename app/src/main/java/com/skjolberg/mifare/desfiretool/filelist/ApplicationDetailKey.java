package com.skjolberg.mifare.desfiretool.filelist;

import com.github.skjolber.desfire.ev1.model.key.DesfireKey;

public class ApplicationDetailKey implements ApplicationDetail {

	private String title;
	private String description;
	private DesfireKey key;
	
	public String getDescription() {
		return description;
	}
	
	public String getTitle() {
		return title;
	}

	public ApplicationDetailKey(String title, String description, DesfireKey key) {
		this.title = title;
		this.description = description;
		this.key = key;
	}
	
	public DesfireKey getKey() {
		return key;
	}
}
