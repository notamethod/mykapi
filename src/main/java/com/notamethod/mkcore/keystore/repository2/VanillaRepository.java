package com.notamethod.mkcore.keystore.repository2;

import com.notamethod.mkcore.keystore.repository.RepositoryException;

import java.nio.file.Path;

public class VanillaRepository extends AbstractCryptoRepository implements CryptoRepository {
    public VanillaRepository(Path file) {
    }

    @Override
    public void persist() throws RepositoryException {

    }
}
