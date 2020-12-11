package org.dpr.mykeys.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

public class TestUtils {

    static Path getCopy(String filename, String suffix) throws IOException {
        String root = "src/test/resources/data/";
        String rootCopy = "target/test-classes/data/";
        Path source = Paths.get(root + filename);
        Path target = Paths.get(rootCopy + filename+"."+suffix);
        Files.copy(source, target, REPLACE_EXISTING);
        return target;
    }

    static Path getCopy(String filename) throws IOException {
        return getCopy(filename,"work");
    }
}
