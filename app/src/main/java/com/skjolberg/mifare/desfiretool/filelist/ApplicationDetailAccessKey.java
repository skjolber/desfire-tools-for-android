package com.skjolberg.mifare.desfiretool.filelist;


public class ApplicationDetailAccessKey implements ApplicationDetail {

	private String title;
	private String description;
	private int index;
	
	public String getDescription() {
		return description;
	}
	
	public String getTitle() {
		return title;
	}

	public ApplicationDetailAccessKey(String title, String description, int index) {
		this.title = title;
		this.description = description;
		this.index = index;
	}
	
	public int getIndex() {
		return index;
	}
}
