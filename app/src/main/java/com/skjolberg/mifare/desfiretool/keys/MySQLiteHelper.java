package com.skjolberg.mifare.desfiretool.keys;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

// http://www.codeproject.com/Articles/119293/Using-SQLite-Database-with-Android
public class MySQLiteHelper extends SQLiteOpenHelper {

	public static final String KEYS_TABLE = "Keys";
	public static final String TAGS_COLUMN_ID = "id";
	public static final String TAGS_COLUMN_BYTES = "bytes";
	
	private static final String DATABASE_NAME = "keys.db";
	private static final int DATABASE_VERSION = 3;

	private static final String TAG = MySQLiteHelper.class.getName();
	
	// Database creation sql statement
	private static final String DATABASE_CREATE_TAGS_TABLE = "create table "
			+ KEYS_TABLE + "( " + TAGS_COLUMN_ID
			+ " integer primary key autoincrement, " 
			+ TAGS_COLUMN_BYTES + " BLOB "
			+ ");";

	public static String[] allColumns = {
			MySQLiteHelper.TAGS_COLUMN_ID,
			MySQLiteHelper.TAGS_COLUMN_BYTES,
			};
	
	private boolean created = false;
	
	public MySQLiteHelper(DataSource dataSource, Context context) {
		super(context, DATABASE_NAME, null, DATABASE_VERSION);
	}

	@Override
	public void onCreate(SQLiteDatabase database) {
		Log.d(TAG, "onCreate");
		
		database.execSQL(DATABASE_CREATE_TAGS_TABLE);
		
		created = true;
	}
	
	@Override
	public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
		if (oldVersion >= newVersion) {
			return;
		}
	}
	
	@Override
	public void onOpen(SQLiteDatabase db) {
		super.onOpen(db);
		if (!db.isReadOnly()) {
			// Enable foreign key constraints
			db.execSQL("PRAGMA foreign_keys=ON;");
		}
	} 
	
	public boolean isCreated() {
		return created;
	}

}