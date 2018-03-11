package com.github.skjolber.desfire.ev1.model.key;

public enum DesfireKeyType {
    NONE(0),
    DES(1),
    TDES(2),
    TKTDES(3),
    AES(4);

    private final int id;

    private DesfireKeyType(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public static DesfireKeyType getType(int id) {
        for(DesfireKeyType type : values()) {
            if(type.getId() == id) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown id " + id);
    }
}
