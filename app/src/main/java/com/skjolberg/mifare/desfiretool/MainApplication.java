package com.skjolberg.mifare.desfiretool;

import com.skjolberg.mifare.desfiretool.keys.DataSource;

import android.app.Application;

public class MainApplication extends Application {

	private static MainApplication application;
	
	private DataSource dataSource;
	
	@Override
	public void onCreate() {
		super.onCreate();
		
		MainApplication.application = this;
		
		this.dataSource = new DataSource(this);
		this.dataSource.loadAll();
	}

	public DataSource getDataSource() {
		return dataSource;
	}

	public static MainApplication getInstance() {
		return application;
	}
}

