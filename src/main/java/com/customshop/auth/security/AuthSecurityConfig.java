package com.customshop.auth.security;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;


import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.customshop.auth.model.UserRepository;
import com.customshop.auth.model.UserModel;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class AuthSecurityConfig {
	
	
	@Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }
	
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain loginFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
		return http.formLogin(Customizer.withDefaults()).build();
	}
	
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwAuth2TokenCustomizer(UserRepository userRepository){
		return (context -> {
			Authentication auth = context.getPrincipal();
			if(auth.getPrincipal() instanceof User) {
				final User user = (User) auth.getPrincipal();
				final UserModel userEntity = userRepository.findByEmail(user.getUsername()).orElseThrow();
				
				Set<String> authorities = new HashSet<>();
				for(GrantedAuthority authority : user.getAuthorities()) {
					authorities.add(authority.toString());
				}
				
				context.getClaims().claim("user_cpf", userEntity.getCpf());
				context.getClaims().claim("authorities", authorities);
			}
			
		});
	}
	
	@Bean
	public RegisteredClientRepository repository(PasswordEncoder pass, AuthenticationManagerBuilder auth) throws Exception {
		RegisteredClient rootjwtClient = RegisteredClient
				.withId("1")
				.clientId("root")
                .clientSecret(pass.encode("123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/authorized")
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope("myuser:read")
                .scope("myuser:write")
                .scope("posts:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();
		RegisteredClient awuserClient = RegisteredClient
				.withId("2")
				.clientId("awuser")
                .clientSecret(pass.encode("123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("users:read")
                .scope("users:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();
		return new InMemoryRegisteredClientRepository(
				Arrays.asList(awuserClient,rootjwtClient)
		);
	}
	
	@Bean
	public AuthorizationServerSettings providerSettings(AuthProperties authProperties) {
		String uriAuth = authProperties.getProviderUri();
		return AuthorizationServerSettings.builder()
			   .issuer(uriAuth)
			   .build();
	}
	
	@Bean
	public JWKSet jwkSet(AuthProperties authProperties) throws Exception {
		final InputStream inputStream = new ClassPathResource(authProperties.getPath()).getInputStream();
		final KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(inputStream, authProperties.getStorepass().toCharArray());
		RSAKey rsaKey = RSAKey.load(keyStore, authProperties.getAlias(), authProperties.getKeypass().toCharArray());
		
		return new JWKSet(rsaKey);
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet){
		return ((jwkSelector,securityContext) -> jwkSelector.select(jwkSet));
	}
	
	@Bean
	public JwtEncoder jwtEnconder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
	
	
}
