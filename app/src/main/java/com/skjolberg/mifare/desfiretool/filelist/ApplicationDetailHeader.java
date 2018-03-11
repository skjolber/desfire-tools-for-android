package com.skjolberg.mifare.desfiretool.filelist;

public class ApplicationDetailHeader implements ApplicationDetail {

	private String title;
	
	public ApplicationDetailHeader(String title) {
		this.title = title;
	}
	
	public String getTitle() {
		return title;
	}

}
