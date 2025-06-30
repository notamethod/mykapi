package com.notamethod.mkcore.test;

import com.notamethod.mkcore.utils.KeyUsages;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestKeyUsages {

    static int checkValue=0;
    @Test
    public void testConversion() {
        boolean[] usages = new boolean[]{true, true, false,true};
        assertEquals(208, KeyUsages.toInt(usages));
    }

    @Test
    public void testConversion2() {
        List<String> usages = new ArrayList<>();
        usages.add("digitalSignature");
        usages.add("nonRepudiation");
        usages.add("dataEncipherment");
        assertEquals(208, KeyUsages.toInt(usages));
    }
}
