package org.dpr.mykeys.app.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.dpr.mykeys.app.CertificateType;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.Map;

public class Pair implements Comparable<Pair>{
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Pair(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    String key;
    String value;

    @Override
    public int compareTo(@NotNull Pair other) {
        if (Type.lookup(this.key) == null && Type.lookup(other.key) ==null){
            return 0;
        }
        if (Type.lookup(this.key) == null){
            return 1;
        }
        if (Type.lookup(other.key) == null){
            return -1;
        }
        return Integer.compare(Type.lookup(this.key).order, Type.lookup(other.key).order);
    }

    public enum Type {
        CN(1),O(2),OU(3),C(4);
        private int order;
        Type(int order) {
            this.order = order;
        }
        private static final Map<String, Type> nameIndex = new HashMap<>();
        static {
            for (Type suit : Type.values()) {
                nameIndex.put(suit.name(), suit);
            }
        }
        public static Type lookup(String name) {
            return nameIndex.get(name);
        }
        public static Type fromValue(String v) {
            return valueOf(v);
        }

        public static String getValue(Type type) {
            return type.toString();
        }
    }
}
