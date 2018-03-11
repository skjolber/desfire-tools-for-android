// ***********************************************************
// Android AlertDialog allowing selection of target directory and entry of filename.
//
// Copyright �   2013 Craig Greenock.
// Version 2.0 - Jan 2014
// Machine     - KEFALLONIA Microsoft Windows NT 6.1.7600.0
// Contact     - cgreenock@bcs.org.uk
// 
// ***********************************************************

// submit@codeproject.com

package com.skjolberg.mifare.desfiretool;


import java.io.File;
import java.util.ArrayList;
import java.util.List;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Environment;
import android.text.InputType;
import android.util.DisplayMetrics;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;


/** Allow user to select destination directory and to enter filename.
 *
 * */
public class FileSaveFragment extends DialogFragment 
		implements OnItemClickListener {

	/*
	 * Use the unicode "back" triangle to indicate there is a parent 
	 * directory rather than an icon to minimise file dependencies.
	 * 
	 * You may have to find an alternative symbol if the font in use 
	 * doesn't support this character. 
	 * */ 
	final String PARENT =  "\u25C0"; 
	
	private Callbacks mCallbacks;
	private ArrayList<File> directoryList;
	private String defaultExtension;
	
	// The widgets required to provide the UI.
	private TextView currentPath;
	private EditText fileName;
	private LinearLayout root;
	private ListView directoryView;

	// The directory the user has selected.
	private File currentDirectory;
	
	// Resource IDs
	private int resourceID_OK;
	private int resourceID_Cancel;
	private int resourceID_Title;
	private int resourceID_EditHint;
	private int resourceID_Icon; 
	
	/**  Does file already exist?
	 * */
	public static boolean FileExists(String absolutePath, String fileName) {
		File checkFile = new File(absolutePath, fileName);
		return checkFile.exists();
	}
	
	/** Restrict valid filenames to alpha-numeric (word chars) only. Simplifies reserved 
	 *  path character validation at cost of forbidding spaces, hyphens and underscores.
	 *  
	 *  @param fileName - filename without extension or path information.
	 *  
	 * */
	public static boolean IsAlphaNumeric(String fileName) {
		fileName = NameNoExtension(fileName);
		return (!fileName.matches(".*\\W{1,}.*"));
	}
	
	/** Return the characters following the final full stop
	 *  in the filename.
	 * */
	public static String Extension(String fileName) {
		
		String extension = "";
		
		if (fileName.contains(".")) {
			String[] tokens = fileName.split("\\.(?=[^\\.]+$)");
			extension = tokens[1];
		}		

		return extension;
	}
	
	/** Return the filename without any extension. Extension is taken to be the
	 *  characters following the final full stop (if any) in the filename.
	 * @param fileName - File name with or without extension.
	 * */
	public static String NameNoExtension(String fileName) {
		
		if (fileName.contains(".")) {
			String[] tokens = fileName.split("\\.(?=[^\\.]+$)");
			fileName = tokens[0];
		}		

		return fileName;
	}
	
	
	/** 
	 * Signal to / request action of host activity.
	 * 
	 * */
	public interface Callbacks {

		/** Hand potential file details to context for validation.
		 *  @param absolutePath - Absolute path to target directory.
		 *  @param fileName     - Filename. Not guaranteed to have a type extension.
		 *  
		 * */
		public boolean onCanSave(String absolutePath, String fileName);

		/**  
		 * Hand validated path and name to context for use.
		 * If user cancels absolutePath and filename are handed out as null.
		 * 
		 *  @param absolutePath - Absolute path to target directory.
		 *  @param fileName     - Filename. Not guaranteed to have a type extension.
		 * */
		public void onConfirmSave(String absolutePath, String fileName);
	}

	/** Create new instance of a file save popup. 
	 * 
	 * @param defaultExtension - Display a default extension for file to be created. Can be null.
	 * @param resourceID_OK - String resource ID for the positive (OK) button.
	 * @param resourceID_Cancel - String resource ID for the negative (Cancel) button.
	 * @param resourceID_Title - String resource ID for the dialogue's title.
	 * @param resourceID_EditHint - String resource ID for the filename edit widget.
	 * @param resourceID_Icon - Drawable resource ID for the dialogue's title bar icon.
	 * */
    public static FileSaveFragment newInstance(String defaultExtension,
    		                                   int resourceID_OK, 
    		                                   int resourceID_Cancel, 
    		                                   int resourceID_Title, 
    		                                   int resourceID_EditHint,
    		                                   int resourceID_Icon) {
    	FileSaveFragment frag = new FileSaveFragment();
    	
    	Bundle args = new Bundle();
    	args.putString("extensionList", defaultExtension);
    	args.putInt("captionOK", resourceID_OK);
    	args.putInt("captionCancel", resourceID_Cancel);
    	args.putInt("popupTitle", resourceID_Title);
    	args.putInt("editHint", resourceID_EditHint);
    	args.putInt("popupIcon", resourceID_Icon);
    	frag.setArguments(args);
        return frag;
    }

    /** Note the parent activity for callback purposes.
     *  @param activity - parent activity
     * */
	@Override
	public void onAttach(Activity activity) {
		super.onAttach(activity);
        // The containing activity is expected to implement the fragment's 
        // callbacks otherwise it can't react to item changes.
        if (!(activity instanceof Callbacks)) {
            throw new IllegalStateException("Activity must implement fragment's callbacks.");
        }

        mCallbacks = (Callbacks) activity;
        directoryList = new ArrayList<File>();
        defaultExtension = getArguments().getString("extensionList");
        resourceID_OK = getArguments().getInt("captionOK");
        resourceID_Cancel = getArguments().getInt("captionCancel");
        resourceID_Title = getArguments().getInt("popupTitle");
        resourceID_EditHint = getArguments().getInt("editHint");
        resourceID_Icon = getArguments().getInt("popupIcon");
        
	}

	/** Build the popup.  
	 * */
	@Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {

        /* 
         * Use the same callback for [OK] & [Cancel]. 
         * Hand out nulls to indicate abandonment. 
         * */
       
		/* 
		 * We want to make this a transportable piece of code so don't want an XML
		 * layout dependency so layout is set up in code.
		 * 
		 *   [ListView of directory names                         ]
		 *   [                                                    ]
		 *   [                                                    ]
		 *   [                                                    ]
		 *   ------------------------------------------------------
		 *   {current path}/ [ Enter Filename  ] {default extension}  
		 * 
		 * */
	
		// Set up the container view.
		LinearLayout.LayoutParams rootLayout = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
				                                                             ViewGroup.LayoutParams.WRAP_CONTENT, 
				                                                             0.0F);
		root = new LinearLayout(getActivity());
		root.setOrientation(LinearLayout.VERTICAL);
		root.setLayoutParams(rootLayout);

		/* 
		 * Set up initial sub-directory list.
		 * 
		 * */
		currentDirectory = Environment.getExternalStorageDirectory();
		directoryList = getSubDirectories(currentDirectory);
		DirectoryDisplay displayFormat = new DirectoryDisplay(getActivity(), directoryList);

		DisplayMetrics displaymetrics = new DisplayMetrics();
		getActivity().getWindowManager().getDefaultDisplay().getMetrics(displaymetrics);
		int height = displaymetrics.heightPixels;
		int width = displaymetrics.widthPixels;
		
		
		/*
		 * Fix the height of the listview at 150px, enough to show 3 or 4 entries at a time.
		 * Don't want the popup shrinking and growing all the time. Tried it. 
		 * Most disconcerting.
		 * */
		LinearLayout.LayoutParams listViewLayout = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                                                                                 height / 3,
                                                                                 0.0F);
		directoryView = new ListView(getActivity());
		directoryView.setLayoutParams(listViewLayout);
		directoryView.setAdapter(displayFormat);
		directoryView.setOnItemClickListener(this);
		root.addView(directoryView);
		
		View horizDivider = new View(getActivity()); 
		horizDivider.setBackgroundColor(Color.CYAN);
		root.addView(horizDivider,
				     new ViewGroup.LayoutParams( ViewGroup.LayoutParams.MATCH_PARENT, 2));		

		/*
		 * Now set up the filename entry area.
		 * 
		 * {current path}/ [Enter Filename         ] {default extension}
		 * 
		 * */
		LinearLayout nameArea = new LinearLayout(getActivity());
		nameArea.setOrientation(LinearLayout.HORIZONTAL);
		nameArea.setLayoutParams(rootLayout);
		root.addView(nameArea);
		
	    currentPath = new TextView(getActivity());
		currentPath.setText(currentDirectory.getAbsolutePath() + "/");
		nameArea.addView(currentPath);
		
		/*
		 * We want the filename input area to be as large as possible, but still leave
		 * enough room to show the path and any default extension that may be supplied
		 * so we give it a weight of 1.
		 * */
		LinearLayout.LayoutParams fileNameLayout = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
				                                                                 ViewGroup.LayoutParams.WRAP_CONTENT,
				                                                                 1.0F );
		fileName = new EditText(getActivity());
		fileName.setHint(resourceID_EditHint);
		fileName.setGravity(Gravity.LEFT);
		fileName.setLayoutParams(fileNameLayout);
		fileName.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
		nameArea.addView(fileName);
		
		/*
		 *  We only display the default extension if one has been supplied. 
		 *    
		 * */
		if (defaultExtension != null ) {
			TextView defaultExt = new TextView(getActivity());
			defaultExt.setText(defaultExtension);
			defaultExt.setGravity(Gravity.LEFT);
			defaultExt.setPadding(2, 0, 6, 0);
			nameArea.addView(defaultExt);
		}
		
		// Use the standard AlertDialog builder to create the popup. 
		//     Android custom and practice is normally to chain calls from the builder, but
		//     it can become an unreadable and unmaintainable mess very quickly so I don't.
		Builder popupBuilder = new AlertDialog.Builder(getActivity());
		popupBuilder.setView(root);
		popupBuilder.setIcon(resourceID_Icon);
		popupBuilder.setTitle(resourceID_Title);

		// Set up anonymous methods to handle [OK] & [Cancel] click.
		popupBuilder.setPositiveButton(resourceID_OK,
                                       new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
            	// Empty method. Method defined in onStart();
            }
        });

		popupBuilder.setNegativeButton(resourceID_Cancel,
				                       new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
            	mCallbacks.onConfirmSave(null, null);
            }
        });
		
        AlertDialog create = popupBuilder.create();
        
        return create;
    }

	
	/** 
	 * Provide the [PositiveButton] with a click listener that doesn't 
	 * dismiss the popup if the user has entered an invalid filename. 
	 * 
	 * */
	@Override
	public void onStart()
	{
	    super.onStart();    
	    AlertDialog d = (AlertDialog)getDialog();
	    if(d != null)
	    {
	        Button positiveButton = (Button) d.getButton(Dialog.BUTTON_POSITIVE);
	        positiveButton.setOnClickListener(new View.OnClickListener()
	                {
	                    @Override
	                    public void onClick(View v)
	                    {
	                    	String absolutePath = currentDirectory.getAbsolutePath();
	                    	String filename = fileName.getText().toString();
	                    	if (mCallbacks.onCanSave(absolutePath, filename)) {
	                    		dismiss();
	                    		mCallbacks.onConfirmSave(absolutePath, filename);
	                    	}
	                    }
	                });
	    }
	}	
	
	
	/** Identify all sub-directories within a directory. 
	 *  @param directory The directory to walk.
	 * */
	private ArrayList<File> getSubDirectories(File directory) {
		
		ArrayList<File> directories = new ArrayList<File>();
		File[] files = directory.listFiles();

		// Allow navigation back up the tree when the directory is a sub-directory.
		if (directory.getParent() != null) {
			directories.add(new File(PARENT));
		}
		
		// Enumerate any sub-directories in this directory.
		if (files != null) {
			for (File f : files) {
				if (f.isDirectory() && !f.isHidden()) {
					directories.add(f);
				}
			}
		}
		
		return directories;
		
	}
	
	/** 
	 * Refresh the listview's display adapter using the content
	 * of the identified directory. 
	 * 
	 * */
	@Override
	public void onItemClick(AdapterView<?> arg0, View list, int pos, long id )
	{
		
		File selected = null;
		
		if (pos >= 0 || pos < directoryList.size()) {
			selected = directoryList.get(pos);
			String name = selected.getName();

			// Are we going up or down?
			if (name.equals(PARENT)) {
				currentDirectory = currentDirectory.getParentFile();
			}
			else {
				currentDirectory = 	selected;
			}

			// Refresh the listview display for the newly selected directory.
			directoryList = getSubDirectories(currentDirectory);
			DirectoryDisplay displayFormatter = new DirectoryDisplay(getActivity(), directoryList);
			directoryView.setAdapter(displayFormatter);
			
			// Update the path TextView widget.  Tell the user where he or she is.
			String path = currentDirectory.getAbsolutePath();
			if (currentDirectory.getParent() != null) {
				path += "/";
			}
			currentPath.setText(path);	
		}
	}	
	
	/** Display the sub-directories in a selected directory. 
	 * 
	 * */
	private class DirectoryDisplay 
		extends ArrayAdapter<File> {
		
		public DirectoryDisplay(Context context, List<File> displayContent) {
			super(context, android.R.layout.simple_list_item_1, displayContent);
		}
		
		/** Display the name of each sub-directory. 
		 * */
		@Override
		public View getView(int position, View convertView, ViewGroup parent) {

			// We assume that we've got a parent directory...
			TextView textview = (TextView) super.getView( position, convertView, parent );
			
			// If we've got a directory then get its name.
			if ( directoryList.get(position) != null ) {
				textview.setText( directoryList.get(position).getName() );
			}

			return textview;
		}		
		
		
	}

}
