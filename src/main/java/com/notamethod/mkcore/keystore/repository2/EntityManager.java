package com.notamethod.mkcore.keystore.repository2;

import com.notamethod.mkcore.common.CryptoObject;
import com.notamethod.mkcore.keystore.KeystoreUtils;
import com.notamethod.mkcore.keystore.StoreFormat;
import com.notamethod.mkcore.keystore.UnknownKeystoreTypeException;
import com.notamethod.mkcore.keystore.repository.RepositoryException;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class EntityManager {
    final CryptoRepository repository;
    File file;
    private boolean autoCommit = true;

    public EntityManager(@NotNull String fileName) throws RepositoryException {
        this(fileName, null, null);
    }

    public EntityManager(@NotNull String fileName, char[] pass) throws RepositoryException {
        this(fileName, pass, null);
    }

    public EntityManager(@NotNull String fileName, char[] pass, StoreFormat givenFormat) throws RepositoryException {
        Path file = Paths.get(fileName);
        StoreFormat format;
        if (givenFormat == null) {
            try {
                format = KeystoreUtils.findKeystoreType(fileName);
            } catch (UnknownKeystoreTypeException e) {
                throw new RepositoryException("Error getting child list", e);
            }
        } else {
            format = givenFormat;
        }
        repository =
                switch (format) {
                    case JKS -> new JavaRepository(file, StoreFormat.JKS, pass, true);
                    case PKCS12 -> new JavaRepository(file, StoreFormat.PKCS12, pass, false);
                    case PEM -> new PemRepository(file);
                    case DER -> new DerRepository(file);
                    default -> new VanillaRepository(file);
                };
    }

    public long count() {
        return repository.count();
    }


    public void deleteAll() throws RepositoryException {
        repository.deleteAll();
        commit();
    }

    private void commit() throws RepositoryException {
        if (autoCommit) {
            repository.persist();
        }
    }


    public List<CryptoObject> findAll() throws RepositoryException {
        return repository.findAll();
    }


    public CryptoObject save(CryptoObject entity) throws RepositoryException {
        repository.save(entity);
        repository.persist();
        return entity;
    }

    public List findAllByType(CryptoObject.Type type) {
        return repository.findAllByType(type);
    }

}
