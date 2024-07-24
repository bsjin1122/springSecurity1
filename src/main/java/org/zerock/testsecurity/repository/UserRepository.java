package org.zerock.testsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.zerock.testsecurity.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
	boolean existsByUsername(String username);
	UserEntity findByUsername(String username);
}