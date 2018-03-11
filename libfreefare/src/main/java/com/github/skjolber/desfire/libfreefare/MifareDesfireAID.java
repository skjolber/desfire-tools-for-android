package com.github.skjolber.desfire.libfreefare;

import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;

public class MifareDesfireAID {

    public static DesfireApplicationId mifare_desfire_aid_new(int aid) {
        if (aid > 0x00ffffff)
            throw new IllegalArgumentException();

        return new DesfireApplicationId(C.getBytes3(aid));
    }

    public static int mifare_desfire_aid_get_aid(DesfireApplicationId aid) {
        return aid.getIdInt();
    }

}