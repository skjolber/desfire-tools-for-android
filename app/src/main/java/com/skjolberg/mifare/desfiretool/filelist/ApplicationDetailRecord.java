package com.skjolberg.mifare.desfiretool.filelist;


public class ApplicationDetailRecord implements ApplicationDetail {

	private String title;
	private String description;
	private byte[] content;
	
	public String getDescription() {
		return description;
	}
	
	public String getTitle() {
		return title;
	}

	public ApplicationDetailRecord(String title, String description, byte[] content) {
		this.title = title;
		this.description = description;
		this.content = content;
	}

	public byte[] getContent() {
		return content;
	}
}
