package org.dpr.mykeys.app.keystore.repository2;

import org.dpr.mykeys.app.CryptoObject;
import org.dpr.mykeys.app.keystore.KeystoreUtils;
import org.dpr.mykeys.app.keystore.StoreFormat;
import org.dpr.mykeys.app.keystore.UnknownKeystoreTypeException;
import org.dpr.mykeys.app.keystore.repository.*;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class EntityManager
{
    private boolean autoCommit=true;
    File file;
    CryptoRepository repository;
    public EntityManager(@NotNull String fileName) throws RepositoryException {
        Path file= Paths.get(fileName);
        StoreFormat format = null;
        try {
            format = KeystoreUtils.findKeystoreType(fileName);
        } catch (UnknownKeystoreTypeException e) {
            throw new RepositoryException("Error getting child list",e);
        }
        switch (format) {
            case PEM:
                repository= new PemRepository(file);
                break;
            case DER:
                repository= new DerRepository(file);
                break;
            case PKCS12:
                repository= new VanillaRepository(file);
                break;
            case JKS:
                repository= new JKSRepository(file);
                break;
            default:
                repository= new VanillaRepository(file);
        }
    }

    public long count() {
        return repository.count();
    }


    public void deleteAll() throws RepositoryException {
        repository.deleteAll();
        commit();
    }

    private void commit() throws RepositoryException {
        if (autoCommit){
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
