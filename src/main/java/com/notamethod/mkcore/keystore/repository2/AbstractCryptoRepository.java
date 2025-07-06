package com.notamethod.mkcore.keystore.repository2;

import com.notamethod.mkcore.common.CryptoObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public abstract class AbstractCryptoRepository implements CryptoRepository{
    List<CryptoObject> cryptoObjects = new ArrayList<>();

    @Override
    public long count() {
        return cryptoObjects.size();
    }

    @Override
    public void deleteAll() {
        cryptoObjects.clear();
    }


    @Override
    public List findAll() {
        return cryptoObjects;
    }

    @Override
    public boolean existsById(Object o) {
        return false;
    }


    @Override
    public Iterable<CryptoObject> findAllById(Iterable iterable) {
        return null;
    }

    @Override
    public Optional findById(Object o) {
        return Optional.empty();
    }

    @Override
    public List findAllByType(CryptoObject.Type type) {
        return cryptoObjects.stream()
                .filter(e -> e.getType().equals(type))
                .toList();
    }


    @Override
    public void delete(CryptoObject entity) {

    }



    @Override
    public void deleteAll(Iterable entities) {

    }

    @Override
    public void deleteById(Object o) {

    }



    @Override
    public Iterable saveAll(Iterable entities) {
        return null;
    }

    @Override
    public CryptoObject save(CryptoObject entity) {
        cryptoObjects.add(entity);
        return entity;
    }


}
