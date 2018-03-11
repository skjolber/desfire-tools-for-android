package com.github.skjolber.desfire.libfreefare;

/**
 * Created by skjolber on 10.03.18.
 */

public class TestUtils {

    public static byte[] hexStringToByteArray (String s) {
        s = s.replaceAll(" ", "");
        if ((s.length() % 2) != 0) {
            throw new IllegalArgumentException("Bad input string: " + s);
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
