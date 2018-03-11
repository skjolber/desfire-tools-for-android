package com.skjolberg.mifare.desfiretool;

import java.util.List;

import android.app.Activity;
import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;

import com.github.skjolber.desfire.ev1.model.DesfireApplication;

public class ApplicationListFragment extends Fragment {

	private List<DesfireApplication> applications;
	
	private ListView listView;
	
	private OnItemClickListener listener;
	
	public void setApplications(List<DesfireApplication> applications) {
		this.applications = applications;
	}
	
	@Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.fragment_application_list, container, false);
        
        listView = (ListView)view.findViewById(R.id.listView);
        listView.setOnItemClickListener(listener);

        if(getActivity() != null) {
        	listView.setAdapter(new ApplicationListItemAdapter(getActivity(), applications));
        }
        
        return view;
    }
	
	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
	}
	
    public void onAttach(Activity activity) {
        super.onAttach(activity);

        if(getView() != null) {
        	listView.setAdapter(new ApplicationListItemAdapter(activity, applications));
        }
    }

	public void setOnItemClickListener(OnItemClickListener listener) {
		this.listener = listener;
	}
}
