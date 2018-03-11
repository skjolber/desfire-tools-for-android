package com.skjolberg.mifare.desfiretool.keys;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import com.github.skjolber.desfire.ev1.model.key.Desfire3DESKey;
import com.github.skjolber.desfire.ev1.model.key.Desfire3K3DESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireAESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireDESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;

public class DataSource {

	private static final String TAG = DataSource.class.getName();

	// Database fields
	private SQLiteDatabase database;
	private MySQLiteHelper dbHelper;
	
	private List<DesfireKey> list = new ArrayList<DesfireKey>();

	public DataSource(Context context) {
		dbHelper = new MySQLiteHelper(this, context);
		
		open();
		
		if(dbHelper.isCreated()) {
			try {
				createKey(DesfireDESKey.defaultVersionNull);
				createKey(DesfireDESKey.defaultVersionAA);
				
				createKey(DesfireAESKey.defaultVersion42);

				createKey(Desfire3K3DESKey.defaultVersion55);

				createKey(Desfire3DESKey.defaultVersionNull);
				createKey(Desfire3DESKey.defaultVersionC7);
			} catch (Exception e) {
				throw new IllegalArgumentException(e);
			}
		}
	}

	public void loadAll() {
		list = getAllTags();
		Collections.sort(list);
	}
	
	protected void open() throws SQLException {
		database = dbHelper.getWritableDatabase();
	}

	public void close() {
		dbHelper.close();
	}

	public List<DesfireKey> getKeys() {
		return list;
	}
	
	protected List<DesfireKey> getAllTags(long user) {
		List<DesfireKey> comments = new ArrayList<DesfireKey>();

		Cursor cursor = database.query(MySQLiteHelper.KEYS_TABLE,
				MySQLiteHelper.allColumns, null, null, null, null, null);

		cursor.moveToFirst();
		while (!cursor.isAfterLast()) {
			DesfireKey tag = cursorToTag(cursor);
			comments.add(tag);
			cursor.moveToNext();
		}
		// Make sure to close the cursor
		cursor.close();
		return comments;
	}

	public void createKey(DesfireKey tag) throws IOException {
		ContentValues values = new ContentValues();
		values.put(MySQLiteHelper.TAGS_COLUMN_BYTES, tag.toBytes());
		
		long result = database.insert(MySQLiteHelper.KEYS_TABLE, null, values);
		if(result == -1) {
			Log.d(TAG, "Unable to insert tag " + tag.getName() + " to database");
		} else {
			Log.d(TAG, "Added tag to database");
			
			tag.setId(result);
			
			list.add(0, tag);
			
			Collections.sort(list);
		}
	}

	public void deleteKey(DesfireKey tag) {
		System.out.println("Delete tag " + tag.getId());
		long result = database.delete(MySQLiteHelper.KEYS_TABLE, MySQLiteHelper.TAGS_COLUMN_ID + " = " + tag.getId(), null);
		if(result <= 0) {
			Log.d(TAG, "Unable to delete tag " + tag.getId() + " from database");
		} else {
			list.remove(tag);
		}
	}

	private List<DesfireKey> getAllTags() {
		List<DesfireKey> tags = new ArrayList<DesfireKey>();

		Cursor cursor = database.query(MySQLiteHelper.KEYS_TABLE,
				MySQLiteHelper.allColumns, null, null, null, null, null);

		cursor.moveToFirst();
		while (!cursor.isAfterLast()) {
			DesfireKey tag = cursorToTag(cursor);
			tags.add(tag);
			cursor.moveToNext();
		}
		// Make sure to close the cursor
		cursor.close();
		
		Collections.sort(tags);
		
		return tags;
	}
	
	private DesfireKey cursorToTag(Cursor cursor) {
		
		DesfireKey tag;
		try {
			tag = DesfireKey.fromBytes(cursor.getBlob(1));
		} catch (IOException e) {
			return null;
		}

		tag.setId(cursor.getLong(0));
		
		return tag;
	}

	public void listColumns() {

		try {
			Cursor c = database.query(MySQLiteHelper.KEYS_TABLE, null, null, null, null, null, null);
			if (c != null) {
				int num = c.getColumnCount();
				for (int i = 0; i < num; ++i) {
					String colname = c.getColumnName(i);

					Log.d(TAG, i + ": " + colname);
				}
			}

		} catch (Exception e) {
			Log.d(MySQLiteHelper.KEYS_TABLE, e.getMessage(), e);
		}
	}

	public boolean hasTags() {
		Cursor mCount= database.rawQuery("select count(*) from " + MySQLiteHelper.KEYS_TABLE, null);
		mCount.moveToFirst();
		int count= mCount.getInt(0);
		mCount.close();
		
		return count > 0;
	}

	public void deleteAll() {
		int result  = database.delete(MySQLiteHelper.KEYS_TABLE, null, null);
		if(result <= 0) {
			Log.d(TAG, "Unable to delete all tags from database");
		}

	}

	public List<DesfireKey> getKeys(DesfireKeyType type) {
		List<DesfireKey> keys = new ArrayList<>();
		
		for(DesfireKey key : list) {
			if(key.getType() == type) {
				keys.add(key);
			}
		}
		
		return keys;
	}

	
}