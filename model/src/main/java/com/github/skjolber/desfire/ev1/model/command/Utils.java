package com.github.skjolber.desfire.ev1.model.command;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import android.view.WindowManager;

import org.w3c.dom.Node;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.StringWriter;
import java.util.List;

public class Utils {

    public static String getHexString (byte[] a) {
	    return getHexString(a, false);
    }
    
    public static String getHexString(byte[] a, boolean space) {
        return getHexString(a, 0, a.length, space);
    }

    public static String getHexString(byte[] data, int offset, int length, boolean space) {
        StringBuilder sb = new StringBuilder(length * 2);

        for(int i = offset; i < offset + length; i++) {
            sb.append(String.format("%02x ", data[i]));
            if(space) {
                sb.append(' ');
            }
        }

        return sb.toString().toUpperCase();
    }


    public static int byteArrayToInt(byte[] b) {
        return byteArrayToInt(b, 0);
    }
    
    public static int byteArrayToInt(byte[] b, int offset) {
        return byteArrayToInt(b, offset, b.length);
    }
    
    public static int byteArrayToInt(byte[] b, int offset, int length) {
        return (int) byteArrayToLong(b, offset, length);
    }

    public static long byteArrayToLong(byte[] b, int offset, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) {
            int shift = (length - 1 - i) * 8;
            value += (b[i + offset] & 0xFF) << shift;
        }
        return value;
    }
}