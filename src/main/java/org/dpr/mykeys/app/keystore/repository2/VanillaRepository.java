package org.dpr.mykeys.app.keystore.repository2;

import org.dpr.mykeys.app.keystore.repository.RepositoryException;

import java.nio.file.Path;

public class VanillaRepository extends AbstractCryptoRepository implements CryptoRepository {
    public VanillaRepository(Path file) {
    }

    @Override
    public void persist() throws RepositoryException {

    }
}
