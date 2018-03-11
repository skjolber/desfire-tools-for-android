package com.skjolberg.mifare.desfiretool;

import java.util.List;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import com.github.skjolber.desfire.ev1.model.DesfireApplication;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;

public class ApplicationListItemAdapter extends BaseAdapter {

    private Context context;
    private List<? extends DesfireApplicationId> data;
    private static LayoutInflater inflater = null;

    public ApplicationListItemAdapter(Context context, List<? extends DesfireApplicationId> data) {
        this.context = context;
        this.data = data;
        inflater = (LayoutInflater) context
                .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
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
        View vi = convertView;
        if (vi == null)
            vi = inflater.inflate(R.layout.application_list_item, null);
        
        
        DesfireApplication desfireApplication = (DesfireApplication) data.get(position);
        
        TextView text = (TextView) vi.findViewById(R.id.title);
        if(desfireApplication.getIdInt() == 0) {
        	text.setText(context.getString(R.string.applicationIdPICC, "0x" + desfireApplication.getIdString()));
        } else {
        	text.setText(context.getString(R.string.applicationId, "0x" + desfireApplication.getIdString()));
        }
        
        TextView description = (TextView) vi.findViewById(R.id.description);
        
        DesfireApplicationKeySettings keySettings = desfireApplication.getKeySettings();
        switch(keySettings.getType()) {
        case NONE : {
        	description.setText(R.string.applicationCryptoNone);
        	break;
        }
        case TKTDES : {
        	if(keySettings.getMaxKeys() == 1) {
        		description.setText(context.getString(R.string.applicationCryptoSingle3K3DES));
        	} else {
        		description.setText(context.getString(R.string.applicationCryptoMultiple3K3DES, Integer.toString(keySettings.getMaxKeys())));
        	}
        	break;
        }
        case AES : {
        	if(keySettings.getMaxKeys() == 1) {
        		description.setText(context.getString(R.string.applicationCryptoSingleAES));
        	} else {
        		description.setText(context.getString(R.string.applicationCryptoMultipleAES, Integer.toString(keySettings.getMaxKeys())));
        	}
        	break;
        }
        case TDES : {
        	if(keySettings.getMaxKeys() == 1) {
        		description.setText(context.getString(R.string.applicationCryptoSingle3DES));
        	} else {
        		description.setText(context.getString(R.string.applicationCryptoMultiple3DES, Integer.toString(keySettings.getMaxKeys())));
        	}
        	break;
        }
        case DES: {
        	if(keySettings.getMaxKeys() == 1) {
        		description.setText(context.getString(R.string.applicationCryptoSingleDES));
        	} else {
        		description.setText(context.getString(R.string.applicationCryptoMultipleDES, Integer.toString(keySettings.getMaxKeys())));
        	}
        	break;
        }
        }

        return vi;
    }
  
}