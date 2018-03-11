package com.skjolberg.mifare.desfiretool;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;

import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.RecordDesfireFile;
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile;
import com.github.skjolber.desfire.ev1.model.file.ValueDesfireFile;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetail;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailAccessKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailApplicationKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailFile;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailHeader;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailRecord;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailSetting;

public class FileFragment extends Fragment {

	private DesfireFile file;
	
	private ListView listView;
	
	private OnItemClickListener listener;
	
	private FileListItemAdapter adapter;

	@Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.fragment_file, container, false);
        
        listView = (ListView)view.findViewById(R.id.listView);
        listView.setOnItemClickListener(listener);
        init(view, getActivity());
        
        return view;
    }
	
	private void init(View view, Activity activity) {
		if(view != null && activity != null) {
			List<ApplicationDetail> details = new ArrayList<ApplicationDetail>();
			
			details.add(new ApplicationDetailHeader(activity.getString(R.string.fileId, file.getIdString())));

	        int communicationSettingString;
	        switch(file.getCommunicationSettings()) {
	        	case ENCIPHERED : {
	        		communicationSettingString = R.string.fileCommuncationsTypeEnciphered;
	        		break;
	        	}
	        	case PLAIN: {
	        		communicationSettingString = R.string.fileCommuncationsTypePlain;
	        		break;
	        	}
	        	case PLAIN_MAC: {
	        		communicationSettingString = R.string.fileCommuncationsTypePlainMac;
	        		break;
	        	}
	        	default : {
	        		throw new IllegalArgumentException();
	        	}
	        }
	        
			details.add(new ApplicationDetailSetting(getString(R.string.fileCommuncations), activity.getString(communicationSettingString)));
	        
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

			details.add(new ApplicationDetailSetting(getString(R.string.fileType), activity.getString(fileTypeString)));

			if(file instanceof StandardDesfireFile) {
				StandardDesfireFile standardDesfireFile = (StandardDesfireFile)file;
				
				details.add(new ApplicationDetailSetting(getString(R.string.fileSize), getString(R.string.fileSizeBytes, standardDesfireFile.getFileSize())));
			} else if(file instanceof ValueDesfireFile) {
				ValueDesfireFile valueDesfireFile = (ValueDesfireFile)file;

				if(valueDesfireFile.isValue()) {
					details.add(new ApplicationDetailSetting(getString(R.string.fileValue), Integer.toString(valueDesfireFile.getValue())));
				} else {
					details.add(new ApplicationDetailSetting(getString(R.string.fileValue), "-"));
				}

				details.add(new ApplicationDetailSetting(getString(R.string.fileValueLowerLimit), Integer.toString(valueDesfireFile.getLowerLimit())));
				details.add(new ApplicationDetailSetting(getString(R.string.fileValueUpperLimit), Integer.toString(valueDesfireFile.getUpperLimit())));
				details.add(new ApplicationDetailSetting(getString(R.string.fileValueLimitedCredit), getString(valueDesfireFile.isLimitedCredit()? R.string.fileValueLimitedCreditYes : R.string.fileValueLimitedCreditNo)));
				details.add(new ApplicationDetailSetting(getString(R.string.fileValueLimitedCreditValue), Integer.toString(valueDesfireFile.getLowerLimit())));
			} else if(file instanceof RecordDesfireFile) {
				RecordDesfireFile recordDesfireFile = (RecordDesfireFile)file;

				details.add(new ApplicationDetailSetting(getString(R.string.fileRecordRecordSize), Integer.toString(recordDesfireFile.getRecordSize())));
				details.add(new ApplicationDetailSetting(getString(R.string.fileRecordMaxRecords), Integer.toString(recordDesfireFile.getMaxRecords())));
				details.add(new ApplicationDetailSetting(getString(R.string.fileRecordCurrentRecords), Integer.toString(recordDesfireFile.getCurrentRecords())));
				

				if(recordDesfireFile.isRecords()) {
					details.add(new ApplicationDetailHeader(activity.getString(R.string.fileRecords)));
					
					byte[] value = recordDesfireFile.getRecords();
					
					int recordSize = recordDesfireFile.getRecordSize();
					for(int i = 0; i < recordDesfireFile.getCurrentRecords(); i ++) {
						byte[] record = new byte[recordSize];
						System.arraycopy(value, i * recordSize, record, 0, recordSize);
						details.add(new ApplicationDetailRecord(getString(R.string.fileRecordRecord, i), Utils.getHexString(record), record));
					}
				}
				
			}

			details.add(new ApplicationDetailHeader(activity.getString(R.string.keyList)));
			
			details.add(new ApplicationDetailAccessKey(getString(R.string.fileReadAccessKey), translateAccessKey(file.getReadAccessKey(), activity), file.getReadAccessKey()));
			details.add(new ApplicationDetailAccessKey(getString(R.string.fileWriteAccessKey), translateAccessKey(file.getWriteAccessKey(), activity), file.getWriteAccessKey()));
			details.add(new ApplicationDetailAccessKey(getString(R.string.fileReadWriteAccessKey), translateAccessKey(file.getReadWriteAccessKey(), activity), file.getReadWriteAccessKey()));
			details.add(new ApplicationDetailAccessKey(getString(R.string.fileChangeAccessKey), translateAccessKey(file.getChangeAccessKey(), activity), file.getChangeAccessKey()));
			
			adapter = new FileListItemAdapter(getActivity(), details);
        	listView.setAdapter(adapter);
		}
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
    
	
	public void setFile(DesfireFile file) {
		this.file = file;
	}
	
	public void setOnItemClickListener(OnItemClickListener listener) {
		this.listener = listener;
	}

	private String translateAccessKey(int key, Context context) {
		if(key == 14) {
			return context.getString(R.string.fileAccessSummaryFree);
		}
		return Integer.toString(key);
	}
	
	public DesfireFile getFile() {
		return file;
	}
}
