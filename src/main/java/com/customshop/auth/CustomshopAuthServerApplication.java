package com.customshop.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.customshop.auth.model.UserRepository;
import com.customshop.auth.model.UserModel;

@SpringBootApplication
public class CustomshopAuthServerApplication {

	@Autowired
	private UserRepository user;
	
	public static void main(String[] args) {
		SpringApplication.run(CustomshopAuthServerApplication.class, args);
		
	
		
	}

}
