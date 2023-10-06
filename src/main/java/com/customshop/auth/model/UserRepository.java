package com.customshop.auth.model;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<UserModel, Long>{
	Optional<UserModel> findByEmail(@Param("usuario_email") String email);
	
	List<UserModel> findAll();
}
