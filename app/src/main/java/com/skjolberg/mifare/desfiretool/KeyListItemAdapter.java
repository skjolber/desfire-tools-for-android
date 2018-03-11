package com.skjolberg.mifare.desfiretool;

import java.util.List;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetail;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailFile;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailHeader;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailKey;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailSetting;

public class KeyListItemAdapter extends BaseAdapter {

    private Context context;
    private List<ApplicationDetail> data;
    private static LayoutInflater inflater = null;

    public KeyListItemAdapter(Context context, List<ApplicationDetail> data) {
        this.context = context;
        this.data = data;
        inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
    }

    @Override
    public int getCount() {
        return data.size();
    }

    @Override
    public Object getItem(int position) {
        return data.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
    	
		final ApplicationDetail i = (ApplicationDetail)data.get(position);
		int resource;
		if(i instanceof ApplicationDetailHeader) {
			resource = R.layout.file_list_title_item;
		} else if(i instanceof ApplicationDetailSetting) {
			resource = R.layout.file_list_key_value_item;
		} else {
			resource = R.layout.file_list_title_description_item;
		}
		
		View v = null;

		// reuse view?
		if (convertView != null) {
			Integer resouceType = (Integer) convertView.getTag();
			if(resource == resouceType) {
				v = convertView;
			}
		}

		if(v == null) {
			v = inflater.inflate(resource, null);
			v.setTag(resource);
		}
    	
        ApplicationDetail detail = (ApplicationDetail)data.get(position);
        if(detail instanceof ApplicationDetailFile) {
        	ApplicationDetailFile file = (ApplicationDetailFile)detail;
        	
            TextView text = (TextView) v.findViewById(R.id.title);
            text.setText(file.getTitle());
            
            TextView description = (TextView) v.findViewById(R.id.description);
            description.setText(file.getDescription());
        } else if(detail instanceof ApplicationDetailHeader) {
        	ApplicationDetailHeader header = (ApplicationDetailHeader)detail;
        	
            TextView text = (TextView) v.findViewById(R.id.title);
            text.setText(header.getTitle());
            
			// not clickable
			v.setOnClickListener(null);
			v.setOnLongClickListener(null);
			v.setLongClickable(false);

        } else if(detail instanceof ApplicationDetailSetting) {
        	ApplicationDetailSetting setting = (ApplicationDetailSetting)detail;
        	
            TextView text = (TextView) v.findViewById(R.id.title);
            text.setText(setting.getTitle());
            
            TextView description = (TextView) v.findViewById(R.id.description);
            description.setText(setting.getDescription());
            
			// not clickable
			v.setOnClickListener(null);
			v.setOnLongClickListener(null);
			v.setLongClickable(false);

        } else if(detail instanceof ApplicationDetailKey) {
        	ApplicationDetailKey key = (ApplicationDetailKey)detail;
        	
            TextView text = (TextView) v.findViewById(R.id.title);
            text.setText(key.getTitle());
            
            TextView description = (TextView) v.findViewById(R.id.description);
            description.setText(key.getDescription());
        } else {
        	throw new IllegalArgumentException();
        }
        
        return v;
    }
  
}