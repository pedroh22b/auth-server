package com.customshop.auth.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
@Validated
@ConfigurationProperties("aw.auth")
public class AuthProperties {
	
	@NotBlank
	private String providerUri;
	
	
	private String keypass;
	private String storepass;
	private String alias;
	private String path;
	
}
