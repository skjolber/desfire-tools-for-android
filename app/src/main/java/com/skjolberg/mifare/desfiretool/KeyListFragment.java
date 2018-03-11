package com.skjolberg.mifare.desfiretool;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Fragment;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.RadioGroup;
import android.widget.RadioGroup.OnCheckedChangeListener;

import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.key.Desfire3DESKey;
import com.github.skjolber.desfire.ev1.model.key.Desfire3K3DESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireAESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireDESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetail;
import com.skjolberg.mifare.desfiretool.filelist.ApplicationDetailKey;
import com.skjolberg.mifare.desfiretool.keys.DataSource;

public class KeyListFragment extends Fragment {

	private static final String TAG = KeyListFragment.class.getName();

	private List<DesfireKey> keys;
	
	private ListView listView;
	
	private MainActivity context;

	private DataSource dataSource;
	
	private OnItemClickListener listener;
	
	private KeyListItemAdapter adapter;
	
	private int checked = R.id.buttonAES;

	public KeyListFragment() {
		this.dataSource = MainApplication.getInstance().getDataSource();
	}

    public void setContext(MainActivity context) {
        this.context = context;
    }

    @Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
	}
	
	@Override
	public void onCreateContextMenu(ContextMenu menu, View v, ContextMenuInfo menuInfo) {
		super.onCreateContextMenu(menu, v, menuInfo);
		
		menu.add(Menu.NONE, R.id.action_add, Menu.NONE, R.string.keyAdd);
	}
	
	@Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.key_list, container, false);
        
        listView = (ListView)view.findViewById(R.id.listView);
        listView.setOnItemClickListener(listener);

		populateList();
                
        return view;
    }

	private void populateList() {
		List<ApplicationDetail> details = new ArrayList<ApplicationDetail>();
        List<DesfireKey> keys = dataSource.getKeys();
        
		for(DesfireKey key : keys) {
			details.add(new ApplicationDetailKey(key.getName(), context.getString(R.string.keyVersion, key.getVersionAsHexString()), key));
		}

		this.adapter = new KeyListItemAdapter(context, details);
		
        listView.setAdapter(adapter);
	}
	
	@Override
	public void onActivityCreated(Bundle savedInstanceState) {
		super.onActivityCreated(savedInstanceState);
	}
	
    public void onAttach(Activity activity) {
        super.onAttach(activity);
    }

	public int getPx(int dp) {
		float scale = getResources().getDisplayMetrics().density;
		return ((int) (dp * scale + 0.5f));
	}

	public void showAddKey(final DesfireKey existingKey) {
		Log.d(TAG, "Show add key");

		LayoutInflater factory = LayoutInflater.from(context);
		
		View message = factory.inflate(R.layout.keys_add_dialog, null);
		
		message.setPadding(getPx(10), getPx(10), getPx(10), getPx(10));
		
		final EditText name = (EditText) message.findViewById(R.id.name);
		final EditText value = (EditText) message.findViewById(R.id.value);
		final EditText version = (EditText) message.findViewById(R.id.version);
		
		if(existingKey != null) {
			version.setText(Integer.toHexString(existingKey.getVersion()));
			value.setText(Utils.getHexString(existingKey.getValue(), true));
			name.setText(existingKey.getName());
		}
		
		
        RadioGroup radioGroup = (RadioGroup) message.findViewById(R.id.segmentedControlKeyType);        
        radioGroup.setOnCheckedChangeListener(new OnCheckedChangeListener() 
        {
            public void onCheckedChanged(RadioGroup group, int checkedId) {
            	KeyListFragment.this.checked = checkedId;
            }
        });
        
        if(existingKey != null) {
            DesfireKeyType type = existingKey.getType();
			switch(type) {
			case DES : {
				radioGroup.check(R.id.buttonDES);
				break;
			}
			case TDES : {
				radioGroup.check(R.id.button3DES);
				break;
			}
			case TKTDES: {
				radioGroup.check(R.id.button3K3DES);
				break;
			}
			case AES : {
				radioGroup.check(R.id.buttonAES);
				break;
			}
			default : {
				throw new IllegalArgumentException();
			}
		}

        }

        
		/*
		if(key.getId() != -1L) {
			name.setText(key.getName());
			value.setText(Utils.getHexString(key.getValue(), false));
		}
		*/
		
		value.addTextChangedListener(new TextWatcher() {
    	    public void afterTextChanged(Editable s) {
    	    	value.setError(null);
    	    }
			
    	    public void beforeTextChanged(CharSequence s, int start, int count, int after){}
    	    public void onTextChanged(CharSequence s, int start, int before, int count){
    	    }
    	});
		
		DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
			@Override
			public void onClick(DialogInterface dialog, int which) {
				switch (which) {
				case DialogInterface.BUTTON_NEGATIVE:
					// Yes button clicked
					dialog.dismiss();

					break;
					
				case DialogInterface.BUTTON_NEUTRAL:
					// Yes button clicked
					dialog.dismiss();

					Log.d(TAG, "Delete key " + name.getText() + " key " + name.getText());

                	dataSource.deleteKey(existingKey);
					
					populateList();
					// delete
                	adapter.notifyDataSetChanged();

					break;
				case DialogInterface.BUTTON_POSITIVE:
					throw new RuntimeException();
				}
			}

		};
		
		AlertDialog.Builder builder = new AlertDialog.Builder(context);
		builder.setView(message)
				.setPositiveButton(R.string.keyDialogOk, dialogClickListener)
				.setNegativeButton(R.string.keyDialogCancel, dialogClickListener);
		
		if(existingKey != null) {
			builder.setNeutralButton(R.string.keyDialogDelete, dialogClickListener);
		}
		
		final AlertDialog alert = builder.create();
		
	    alert.setOnShowListener(new DialogInterface.OnShowListener() {
	        @Override
	        public void onShow(DialogInterface dialog) {
                Button button = alert.getButton(DialogInterface.BUTTON_POSITIVE);
                button.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
    					String keyValueString = value.getText().toString().replaceAll("\\s","");
    					
    					int size;
    					if(checked == R.id.buttonAES) {
    						size = 16 * 2;
    					} else if(checked == R.id.buttonDES) {
    						size = 8 * 2;
    					} else if(checked == R.id.button3DES) {
    						size = 16 * 2;
    					} else if(checked == R.id.button3K3DES) {
    						size = 24 * 2;
    					} else {
    						throw new IllegalArgumentException();
    					}

    					CharSequence keyErrorMessage = getKeyErrorMessage(keyValueString, size);
    					if(keyErrorMessage != null) {
    						setErrorMessage(value, keyErrorMessage);
    						return;
    					}
    					
    					String versionValueString = version.getText().toString().replaceAll("\\s","");

    					keyErrorMessage = getKeyErrorMessage(versionValueString, 2);
    					if(keyErrorMessage != null) {
    						setErrorMessage(version, keyErrorMessage);
    						return;
    					}

    					alert.dismiss();

    					Log.d(TAG, "Add key " + name.getText() + " key " + name.getText());

                    	byte[] bytes = hexStringToByteArray(keyValueString.toString());

                        DesfireKeyType type;
    					if(checked == R.id.buttonAES) {
    						type = DesfireKeyType.AES;
    					} else if(checked == R.id.buttonDES) {
    						type = DesfireKeyType.DES;
    					} else if(checked == R.id.button3DES) {
    						type = DesfireKeyType.TDES;
    					} else if(checked == R.id.button3K3DES) {
    						type = DesfireKeyType.TKTDES;
    					} else {
    						throw new IllegalArgumentException();
    					}
    					
    					DesfireKey key = DesfireKey.newInstance(type, Integer.parseInt(versionValueString, 16));
    					key.setName(name.getText().toString());
    					key.setValue(bytes);
    					
    					try {
        					if(existingKey != null) {
    							dataSource.deleteKey(existingKey);
        					}
        					
							dataSource.createKey(key);
						} catch (IOException e) {
							Log.d(TAG, "Problem adding key", e);
						}
    					
    					populateList();
    					/*
                    	if(key.getId() == -1L) {
	                    	if(dataSource.createKey(key)) {
	                        	Log.d(TAG, "Add key");
	                        	
	                           	mAdapter.notifyDataSetInvalidated();
    	                	} else {
    	                    	Log.e(TAG, "Problem creating key");
	                    	}
                    	} else {
                    		if(dataSource.updateKey(key)) {
    	                    	Log.d(TAG, "Updated key " + key.getId());
    	                	} else {
    	                    	Log.e(TAG, "Problem updating key " + key.getId());
    	                	}
                    	}
                    	*/
    					
                       	adapter.notifyDataSetInvalidated();
                    }
                });
                
                InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
                imm.showSoftInput(value, InputMethodManager.SHOW_IMPLICIT);
	        }
	    });
	    
		context.show(alert);
	}

	public void setOnItemClickListener(OnItemClickListener onItemClickListener) {
		this.listener = onItemClickListener;
	}

	public ApplicationDetail getApplicationDetail(int position) {
		return (ApplicationDetail) adapter.getItem(position);
	}
	
	private CharSequence getKeyErrorMessage(String string, int size) {
		if(!isHex(string)) {
			return getText(R.string.keyDialogIllegalCharacters);
		} 
		
		if(string.length() < size) {
			return getString(R.string.keyDialogIllegalLength, size);
		} else if(string.length() > size) {
			return getString(R.string.keyDialogIllegalLength, size);
		}
		return null;
	}

	public static boolean isHex(String key) {
    	for (int i = key.length() - 1; i >= 0; i--) {
    		final char c = key.charAt(i);
    		if (!(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f')) {
    			return false;
    		}
    	}

    	return true;
    }
	
	private boolean setErrorMessage(final EditText editText, CharSequence message) {
		if(editText.getText().length() > 0) {
			editText.setError(message);
			
			return false;
		} else {
			editText.setError(null);
			
			return true;
		}
	}
	
	public static byte[] hexStringToByteArray(String s) {
		if(s.length() % 2 != 0) {
			throw new IllegalArgumentException();
		}
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

}
