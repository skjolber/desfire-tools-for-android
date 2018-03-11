package com.skjolberg.mifare.desfiretool.filelist;

import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile;

public class ApplicationDetailFile implements ApplicationDetail {

	private String title;
	private String description;
	private String access;
	private DesfireFile file;

	public ApplicationDetailFile(String title, String description, DesfireFile file, String access) {
		this.title = title;
		this.description = description;
		this.file = file;
		this.access = access;
	}
	
	public String getDescription() {
		return description;
	}
	
	public String getTitle() {
		return title;
	}

	public DesfireFile getFile() {
		return file;
	}
	
	public String getAccess() {
		return access;
	}
	
	public boolean isSize() {
		return file instanceof StandardDesfireFile;
	}
	
	public int size() {
		StandardDesfireFile standardDesfireFile = (StandardDesfireFile)file;
		
		return standardDesfireFile.getFileSize();
	}
}
