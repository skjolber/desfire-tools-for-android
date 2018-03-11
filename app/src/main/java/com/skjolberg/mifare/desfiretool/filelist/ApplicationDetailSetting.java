package com.skjolberg.mifare.desfiretool.filelist;

public class ApplicationDetailSetting implements ApplicationDetail {

	private String title;
	private String description;
	
	public String getDescription() {
		return description;
	}
	
	public String getTitle() {
		return title;
	}

	public ApplicationDetailSetting(String title, String description) {
		this.title = title;
		this.description = description;
	}
}
