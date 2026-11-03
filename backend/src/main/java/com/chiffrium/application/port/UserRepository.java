package com.chiffrium.application.port;

import com.chiffrium.domain.security.User;

import java.util.List;
import java.util.Optional;

/**
 * Persistance des comptes utilisateurs.
 */
public interface UserRepository {

    Optional<User> findByUsername(String username);

    Optional<User> findById(String id);

    List<User> findAll();

    long count();

    /** Crée ou met à jour. */
    void save(User user);
}
