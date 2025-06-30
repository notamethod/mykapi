package com.notamethod.mkcore.keystore.repository;

public class RepositoryException extends Exception {
    public RepositoryException(String s) {
        super(s);
    }

    public RepositoryException(String s, Exception e) {
        super(s, e);
    }

    public RepositoryException(Exception e) {
        super(e);
    }
}
