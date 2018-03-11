package com.skjolberg.mifare.desfiretool;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;

import com.github.skjolber.desfire.ev1.model.DesfireApplication;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKey;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.key.DesfireKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetail;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailApplicationKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailFile;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailHeader;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailSetting;

public class FileListFragment extends Fragment {

	private DesfireApplication application;
	
	private ListView listView;
	
	private OnItemClickListener listener;
	
	private FileListItemAdapter adapter;

	@Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.fragment_file_list, container, false);
        
        listView = (ListView)view.findViewById(R.id.listView);
        listView.setOnItemClickListener(listener);
        init(view, getActivity());
        
        return view;
    }
	
	private void init(View view, Activity activity) {
		if(view != null && activity != null) {
			List<ApplicationDetail> details = new ArrayList<ApplicationDetail>();
			
			details.add(new ApplicationDetailHeader(activity.getString(R.string.applicationId, "0x" + application.getIdString())));

        	DesfireApplicationKeySettings settings = application.getKeySettings();
			
            if(settings.isConfigurationChangable()) {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationConfigurationChangable), activity.getString(R.string.applicationKeySettingYes)));
            } else {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationConfigurationChangable), activity.getString(R.string.applicationKeySettingNo)));
            }
                       	
			details.add(new ApplicationDetailHeader(activity.getString(R.string.fileList)));
			
            if(settings.isFreeCreateAndDelete()) {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationFreeCreateAndDelete), activity.getString(R.string.applicationKeySettingYes)));
            } else {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationFreeCreateAndDelete), activity.getString(R.string.applicationKeySettingNo)));
            }

            if(settings.isFreeDirectoryAccess()) {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationFreeDirectoryList), activity.getString(R.string.applicationKeySettingYes)));
            } else {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationFreeDirectoryList), activity.getString(R.string.applicationKeySettingNo)));
            }

			List<DesfireFile> files = application.getFiles();
			for(DesfireFile file : files) {
				
		       	String title = activity.getString(R.string.fileId, "0x" + Integer.toHexString(file.getId()).toUpperCase(Locale.ROOT));
		        
		        int communicationSettingString;
		        switch(file.getCommunicationSettings()) {
		        	case ENCIPHERED : {
		        		communicationSettingString = R.string.fileCommuncationTypeEnciphered;
		        		break;
		        	}
		        	case PLAIN: {
		        		communicationSettingString = R.string.fileCommuncationTypePlain;
		        		break;
		        	}
		        	case PLAIN_MAC: {
		        		communicationSettingString = R.string.fileCommuncationTypePlainMac;
		        		break;
		        	}
		        	default : {
		        		throw new IllegalArgumentException();
		        	}
		        }
		        
		        int fileTypeString;
		        switch(file.getFileType()) {
		        	case BACKUP_DATA_FILE : {
		        		fileTypeString = R.string.fileTypeBackup;
		        		
		        		break;
		        	}
		        	case CYCLIC_RECORD_FILE: {
		        		fileTypeString = R.string.fileTypeCyclicRecord;
		        		
		        		break;
		        	}
		        	case LINEAR_RECORD_FILE : {
		        		fileTypeString = R.string.fileTypeLinearRecord;
		        		
		        		break;
		        	}
		        	case STANDARD_DATA_FILE: {
		        		fileTypeString = R.string.fileTypeStandard;
		        		
		        		break;
		        	}
		        	case VALUE_FILE: {
		        		fileTypeString = R.string.fileTypeValue;
		        		
		        		break;
		        	}
		        	default : {
		        		throw new IllegalArgumentException();
		        	}
		        }
		        
		        String description = activity.getString(R.string.fileDescription, activity.getString(fileTypeString), activity.getString(communicationSettingString));

		        String access;
		        if(file.isFreeReadWriteAccess()) {
		        	access = activity.getString(R.string.fileAccessSummaryFree);
		        } else {
		        	access = activity.getString(R.string.fileAccessSummary, translateAccessKey(file.getReadAccessKey(), activity),  translateAccessKey(file.getWriteAccessKey(), activity),  translateAccessKey(file.getReadWriteAccessKey(), activity),  translateAccessKey(file.getChangeAccessKey(), activity));
		        }
		        details.add(new ApplicationDetailFile(title, description, file, access));
			}

			details.add(new ApplicationDetailHeader(activity.getString(R.string.keyList)));

            if(settings.isCanChangeMasterKey()) {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationCanChangeMasterKey), activity.getString(R.string.applicationKeySettingYes)));
            } else {
    			details.add(new ApplicationDetailSetting(getString(R.string.applicationCanChangeMasterKey), activity.getString(R.string.applicationKeySettingNo)));
            }

			details.add(new ApplicationDetailSetting(getString(R.string.applicationChangeKeyAccessRights), Integer.toString(settings.getChangeKeyAccessRights())));

            details.add(new ApplicationDetailSetting(getString(R.string.applicationKeys), Integer.toString(settings.getMaxKeys())));

			List<DesfireApplicationKey> keys = application.getKeys();
			for(DesfireApplicationKey desfireApplicationKey : keys) {
				DesfireKey key = desfireApplicationKey.getDesfireKey();
				
				details.add(new ApplicationDetailApplicationKey(activity.getString(R.string.key, desfireApplicationKey.getIndex()), activity.getString(R.string.keyVersion, Integer.toHexString(key.getVersion())), desfireApplicationKey));
			}

			adapter = new FileListItemAdapter(getActivity(), details);
        	listView.setAdapter(adapter);
        	
     
		}
	}

	private String translateAccessKey(int key, Context context) {
		if(key == 14) {
			return context.getString(R.string.fileAccessFree);
		}
		return Integer.toString(key);
	}

	public ApplicationDetail getApplicationDetail(int position) {
		return (ApplicationDetail) adapter.getItem(position);
	}
	
	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
	}
	
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        
        init(getView(), activity);
    }
    
	public void setApplication(DesfireApplication application) {
		this.application = application;
	}
	
	public void setOnItemClickListener(OnItemClickListener listener) {
		this.listener = listener;
	}

}
