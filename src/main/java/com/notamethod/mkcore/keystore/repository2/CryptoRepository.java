package com.notamethod.mkcore.keystore.repository2;

import com.notamethod.mkcore.common.CryptoObject;
import com.notamethod.mkcore.keystore.repository.RepositoryException;

import java.util.List;
import java.util.Optional;

public interface CryptoRepository<T extends CryptoObject, ID> {

    /**
     * Returns the number of entities available.
     *
     * @return
     */
    long count();

    /**
     * Deletes a given entity.
     *
     * @param entity
     */
    void delete(T entity);

    /**
     * Deletes all entities managed by the repository.
     */
    void deleteAll();

    /**
     * Deletes the given entities.
     *
     * @param entities
     */
    void deleteAll(Iterable<? extends T> entities);

    /**
     * Deletes the entity with the given id.
     *
     * @param id
     */
    void deleteById(ID id);

    /**
     * Returns whether an entity with the given id exists.
     *
     * @param id
     * @return
     */
    boolean existsById(ID id);

    /**
     * Returns all instances of the type.
     *
     * @return
     */
    List<T> findAll() ;

    /**
     * Returns all instances of the type T with the given IDs.
     *
     * @param ids
     * @return
     */
    Iterable<T> findAllById(Iterable<ID> ids);

    /**
     * Retrieves an entity by its id.
     *
     * @param id
     * @return
     */
    Optional<T> findById(ID id);

    /**
     * Saves a given entity.
     *
     * @param entity
     * @param <S>
     * @return
     */
    <S extends T>
    S save(S entity);

    /**
     * Saves all given entities.
     *
     * @param entities
     * @param <S>
     * @return
     */
    <S extends T>
    Iterable<S> saveAll(Iterable<S> entities);

    <S extends T>
    List<S> findAllByType(CryptoObject.Type certificate);

    void persist() throws RepositoryException;
}
